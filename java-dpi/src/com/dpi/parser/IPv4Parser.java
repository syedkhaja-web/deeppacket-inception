package com.dpi.parser;

import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * Parses IPv4 headers.
 */
public class IPv4Parser {

    public static final int PROTOCOL_TCP = 6;
    public static final int PROTOCOL_UDP = 17;

    /**
     * Parses the IPv4 header and returns its payload (Transport layer) and
     * metadata.
     */
    public static Optional<ParseResult> parse(ByteBuffer ipData) {
        if (ipData.remaining() < 20) {
            return Optional.empty(); // Minimum IPv4 header size
        }

        int startPos = ipData.position();

        // Byte 0: Version (4 bits) + IHL (4 bits)
        byte versionAndIhl = ipData.get(startPos);
        int version = (versionAndIhl >> 4) & 0x0F;

        if (version != 4) {
            return Optional.empty(); // Not IPv4
        }

        int ihl = versionAndIhl & 0x0F;
        int headerLength = ihl * 4;

        if (headerLength < 20 || ipData.remaining() < headerLength) {
            return Optional.empty(); // Malformed
        }

        // Byte 2,3: Total Length
        int totalLength = ipData.getShort(startPos + 2) & 0xFFFF;
        if (ipData.remaining() < totalLength) {
            totalLength = ipData.remaining(); // Handle capture truncation
        }

        // Bytes 6,7: Flags and Fragment Offset
        int flagsAndFrag = ipData.getShort(startPos + 6) & 0xFFFF;
        boolean isFragmented = (flagsAndFrag & 0x1FFF) > 0 || (flagsAndFrag & 0x2000) != 0;

        if (isFragmented) {
            // For a pure DPI engine without fragment reassembly, we often drop or ignore
            // subsequent fragments.
            // We'll return empty here to simplify, realistic enterprise engines would do IP
            // defragmentation.
            // But usually only the first fragment has L4 headers anyway.
        }

        // Byte 9: Protocol
        int protocol = ipData.get(startPos + 9) & 0xFF;

        // Bytes 12-15: Source IP
        int srcIp = ipData.getInt(startPos + 12);

        // Bytes 16-19: Dest IP
        int dstIp = ipData.getInt(startPos + 16);

        // Calculate actual payload length
        int payloadLength = totalLength - headerLength;
        if (payloadLength < 0) {
            return Optional.empty();
        }

        // Slice payload
        int oldLimit = ipData.limit();
        ipData.position(startPos + headerLength);
        ipData.limit(Math.min(oldLimit, startPos + headerLength + payloadLength));
        ByteBuffer payload = ipData.slice();

        // Restore buffer state
        ipData.position(startPos);
        ipData.limit(oldLimit);

        return Optional.of(new ParseResult(srcIp, dstIp, protocol, isFragmented, payload));
    }

    public record ParseResult(int srcIp, int dstIp, int protocol, boolean isFragmented, ByteBuffer payload) {
    }
}
