package com.dpi.io;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * A highly optimized PCAP reader utilizing memory-mapped files via `java.nio`.
 * Iterates over RawPackets with zero-copy of the underlying payload.
 */
public class PcapReader implements AutoCloseable, Iterable<RawPacket> {

    private final FileChannel fileChannel;
    private final ByteBuffer mappedBuffer;
    private final PcapGlobalHeader globalHeader;
    private final boolean isSwapped;

    public PcapReader(Path pcapPath) throws IOException {
        this.fileChannel = FileChannel.open(pcapPath, StandardOpenOption.READ);
        long size = fileChannel.size();

        // Use Integer.MAX_VALUE limit since ByteBuffer operates on int indices.
        // For files > 2GB, a multi-segment approach would be needed.
        // Assuming typical PCAPs (< 2GB) for this architecture or splitting externally.
        if (size > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("PCAP file too large for single mapping (> 2GB). " +
                    "Use a segmenting reader for > 2GB captures.");
        }

        this.mappedBuffer = fileChannel.map(FileChannel.MapMode.READ_ONLY, 0, size);
        this.globalHeader = readGlobalHeader();

        this.isSwapped = globalHeader.isSwapped();

        if (isSwapped) {
            // Reconfigure buffer byte order if magic number was swapped
            mappedBuffer.order(ByteOrder.LITTLE_ENDIAN == ByteOrder.nativeOrder() ? ByteOrder.BIG_ENDIAN
                    : ByteOrder.LITTLE_ENDIAN);
        } else {
            // Explicitly set little-endian as standard pcap format (native is usually LE on
            // x86)
            mappedBuffer.order(ByteOrder.LITTLE_ENDIAN);
        }
    }

    private PcapGlobalHeader readGlobalHeader() {
        if (mappedBuffer.remaining() < 24) {
            throw new IllegalStateException("File too small to contain PCAP global header");
        }

        // Temporarily set to LITTLE_ENDIAN to sniff magic number
        mappedBuffer.order(ByteOrder.LITTLE_ENDIAN);
        int magicNumber = mappedBuffer.getInt();

        ByteOrder actualOrder = ByteOrder.LITTLE_ENDIAN;
        if (magicNumber == PcapGlobalHeader.MAGIC_SWAPPED) {
            actualOrder = ByteOrder.BIG_ENDIAN;
        } else if (magicNumber == PcapGlobalHeader.MAGIC_NATIVE || magicNumber == PcapGlobalHeader.MAGIC_NANO) {
            actualOrder = ByteOrder.LITTLE_ENDIAN;
        } else {
            // Need to reverse magic number to see if it's swapped from Big Endian
            // perspective
            mappedBuffer.order(ByteOrder.BIG_ENDIAN);
            mappedBuffer.position(0);
            int magicBig = mappedBuffer.getInt();
            if (magicBig == PcapGlobalHeader.MAGIC_NATIVE || magicBig == PcapGlobalHeader.MAGIC_NANO) {
                actualOrder = ByteOrder.BIG_ENDIAN;
            } else {
                throw new IllegalStateException(String.format("Unknown PCAP magic number: 0x%08X", magicNumber));
            }
        }

        mappedBuffer.order(actualOrder);
        mappedBuffer.position(0); // rewind

        int magic = mappedBuffer.getInt();
        int vMajor = mappedBuffer.getShort() & 0xFFFF;
        int vMinor = mappedBuffer.getShort() & 0xFFFF;
        int thiszone = mappedBuffer.getInt();
        int sigfigs = mappedBuffer.getInt();
        int snaplen = mappedBuffer.getInt();
        int network = mappedBuffer.getInt();

        return new PcapGlobalHeader(magic, vMajor, vMinor, thiszone, sigfigs, snaplen, network);
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    @Override
    public Iterator<RawPacket> iterator() {
        return new PcapIterator();
    }

    @Override
    public void close() throws IOException {
        fileChannel.close();
        // mappedBuffer relies on GC for cleanup (or internal unmap hacks if necessary,
        // omitted for standard Java)
    }

    private class PcapIterator implements Iterator<RawPacket> {
        @Override
        public boolean hasNext() {
            return mappedBuffer.remaining() >= PcapPacketHeader.SIZE;
        }

        @Override
        public RawPacket next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }

            int tsSec = mappedBuffer.getInt();
            int tsUsec = mappedBuffer.getInt();
            int inclLen = mappedBuffer.getInt();
            int origLen = mappedBuffer.getInt();

            PcapPacketHeader header = new PcapPacketHeader(
                    Integer.toUnsignedLong(tsSec),
                    Integer.toUnsignedLong(tsUsec),
                    inclLen,
                    origLen);

            if (mappedBuffer.remaining() < inclLen) {
                // Truncated packet at EOF
                inclLen = mappedBuffer.remaining();
            }

            // Create a slice for the packet data
            int oldLimit = mappedBuffer.limit();
            mappedBuffer.limit(mappedBuffer.position() + inclLen);
            ByteBuffer packetData = mappedBuffer.slice();
            mappedBuffer.limit(oldLimit); // Restore limit
            mappedBuffer.position(mappedBuffer.position() + inclLen); // Advance position

            return new RawPacket(header, packetData);
        }
    }
}
