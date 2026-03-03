package com.dpi.io;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * A fast PCAP writer that appends packets to an output file.
 * Uses a buffered approach to reduce system calls overhead.
 */
public class PcapWriter implements AutoCloseable {

    private final FileChannel fileChannel;
    private final ByteBuffer writeBuffer;

    private final ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;

    public PcapWriter(Path outputPath, PcapGlobalHeader globalHeader) throws IOException {
        this.fileChannel = FileChannel.open(outputPath,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING);

        // 1MB buffer to smooth out writes
        this.writeBuffer = ByteBuffer.allocateDirect(1024 * 1024).order(byteOrder);

        writeGlobalHeader(globalHeader);
    }

    private void writeGlobalHeader(PcapGlobalHeader header) throws IOException {
        ensureCapacity(24);
        writeBuffer.putInt(PcapGlobalHeader.MAGIC_NATIVE); // Output in standard native format
        writeBuffer.putShort((short) header.versionMajor());
        writeBuffer.putShort((short) header.versionMinor());
        writeBuffer.putInt(header.thiszone());
        writeBuffer.putInt(header.sigfigs());
        writeBuffer.putInt(header.snaplen());
        writeBuffer.putInt(header.network());
    }

    public synchronized void writePacket(RawPacket packet) throws IOException {
        PcapPacketHeader header = packet.header();
        ByteBuffer data = packet.data();
        int inclLen = header.inclLen();

        ensureCapacity(PcapPacketHeader.SIZE + inclLen);

        // Write header
        writeBuffer.putInt((int) header.tsSec());
        writeBuffer.putInt((int) header.tsUsec());
        writeBuffer.putInt(inclLen);
        writeBuffer.putInt(header.origLen());

        // Write data
        // Reset the data buffer position to 0 since we might have read from it
        data.clear();
        writeBuffer.put(data);
    }

    private void ensureCapacity(int required) throws IOException {
        if (writeBuffer.remaining() < required) {
            flush();
        }
    }

    public synchronized void flush() throws IOException {
        writeBuffer.flip();
        while (writeBuffer.hasRemaining()) {
            fileChannel.write(writeBuffer);
        }
        writeBuffer.clear();
    }

    @Override
    public void close() throws IOException {
        flush();
        fileChannel.close();
    }
}
