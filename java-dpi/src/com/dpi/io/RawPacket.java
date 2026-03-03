package com.dpi.io;

import java.nio.ByteBuffer;

/**
 * An immutable raw captured packet: header metadata + a read-only ByteBuffer
 * slice pointing directly into the memory-mapped file region.
 *
 * <p>Zero-copy: the {@code data} buffer is a slice of the MappedByteBuffer;
 * no byte arrays are allocated during normal read operations.</p>
 *
 * <p>Callers that need to retain the data beyond the lifetime of the
 * reader must call {@link #copy()} to obtain a heap-backed duplicate.</p>
 */
public final class RawPacket {

    private final PcapPacketHeader header;
    private final ByteBuffer       data;   // read-only slice

    public RawPacket(PcapPacketHeader header, ByteBuffer data) {
        this.header = header;
        this.data   = data.asReadOnlyBuffer();
    }

    /** @return the 16-byte per-packet metadata. */
    public PcapPacketHeader header() { return header; }

    /**
     * Returns a read-only view of the raw frame bytes (position=0, limit=inclLen).
     * The buffer is rewound on each call so callers get a fresh view.
     */
    public ByteBuffer data() {
        ByteBuffer view = data.duplicate();
        view.position(0);
        return view;
    }

    /** @return number of bytes captured (same as {@code header().inclLen()}). */
    public int length() { return header.inclLen(); }

    /**
     * Creates a heap-backed copy of this packet.  Use when the packet must
     * outlive the memory-mapped region or be queued for async processing.
     */
    public RawPacket copy() {
        byte[] bytes = new byte[header.inclLen()];
        data().get(bytes);
        return new RawPacket(header, ByteBuffer.wrap(bytes));
    }

    @Override
    public String toString() {
        return String.format("RawPacket{%s, len=%d}", header, header.inclLen());
    }
}
