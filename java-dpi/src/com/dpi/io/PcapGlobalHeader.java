package com.dpi.io;

/**
 * Represents the 24-byte global header at the start of every PCAP file.
 *
 * Magic number variants:
 *   0xa1b2c3d4 → microsecond timestamps, native byte order
 *   0xd4c3b2a1 → swapped byte order
 *   0xa1b23c4d → nanosecond timestamps
 */
public record PcapGlobalHeader(
        int  magicNumber,    // raw (may be byte-swapped)
        int  versionMajor,
        int  versionMinor,
        int  thiszone,       // GMT offset in seconds (usually 0)
        int  sigfigs,        // accuracy of timestamps (usually 0)
        int  snaplen,        // max capture length per packet (bytes)
        int  network         // link-layer type (1 = Ethernet)
) {
    /** Standard PCAP magic: little-endian file, timestamps in microseconds. */
    public static final int MAGIC_NATIVE  = 0xa1b2c3d4;
    /** Byte-swapped PCAP magic: big-endian file. */
    public static final int MAGIC_SWAPPED = 0xd4c3b2a1;
    /** Nanosecond-resolution variant. */
    public static final int MAGIC_NANO    = 0xa1b23c4d;

    /** Link-layer type for Ethernet II. */
    public static final int LINKTYPE_ETHERNET = 1;

    public boolean isSwapped()     { return magicNumber == MAGIC_SWAPPED; }
    public boolean isNanoSecond()  { return magicNumber == MAGIC_NANO; }
    public boolean isEthernet()    { return network == LINKTYPE_ETHERNET; }

    @Override
    public String toString() {
        return String.format(
            "PcapGlobalHeader{v%d.%d, snaplen=%d, linktype=%d, swapped=%b, nano=%b}",
            versionMajor, versionMinor, snaplen, network, isSwapped(), isNanoSecond());
    }
}
