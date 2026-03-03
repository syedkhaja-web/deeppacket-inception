package com.dpi.io;

/**
 * Represents the 16-byte per-packet header that precedes each captured frame
 * in a PCAP file.
 */
public record PcapPacketHeader(
        long tsSec,     // timestamp – whole seconds   (unsigned 32-bit stored as long)
        long tsUsec,    // timestamp – microseconds    (unsigned 32-bit stored as long)
        int  inclLen,   // bytes actually present in the file
        int  origLen    // original length on the wire (may be larger than inclLen)
) {
    /** Size of this header on disk (bytes). */
    public static final int SIZE = 16;

    /**
     * Returns the capture timestamp as nanoseconds since the Unix epoch.
     * Handles both micro- and nanosecond-resolution files by accepting a flag.
     */
    public long timestampNanos(boolean nano) {
        return tsSec * 1_000_000_000L + (nano ? tsUsec : tsUsec * 1_000L);
    }

    @Override
    public String toString() {
        return String.format("PcapPacketHeader{ts=%d.%06d, incl=%d, orig=%d}",
                tsSec, tsUsec, inclLen, origLen);
    }
}
