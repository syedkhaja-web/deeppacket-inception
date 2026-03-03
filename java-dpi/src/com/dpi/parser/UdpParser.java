package com.dpi.parser;

import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * Parses UDP headers.
 */
public class UdpParser {

    /**
     * Parses the UDP header and returns its payload (Application layer) and
     * metadata.
     */
    public static Optional<ParseResult> parse(ByteBuffer udpData) {
        if (udpData.remaining() < 8) {
            return Optional.empty(); // UDP header is exactly 8 bytes
        }

        int startPos = udpData.position();

        int srcPort = udpData.getShort(startPos) & 0xFFFF;
        int dstPort = udpData.getShort(startPos + 2) & 0xFFFF;
        int length = udpData.getShort(startPos + 4) & 0xFFFF;

        if (length < 8) {
            return Optional.empty(); // Malformed
        }

        // Sometimes the capture length is less than the UDP length
        int actualPayloadLen = Math.min(udpData.remaining() - 8, length - 8);

        if (actualPayloadLen < 0) {
            actualPayloadLen = 0;
        }

        // Slice payload
        int oldLimit = udpData.limit();
        udpData.position(startPos + 8);
        udpData.limit(startPos + 8 + actualPayloadLen);
        ByteBuffer payload = udpData.slice();

        // Restore buffer state
        udpData.position(startPos);
        udpData.limit(oldLimit);

        return Optional.of(new ParseResult(srcPort, dstPort, payload));
    }

    public record ParseResult(int srcPort, int dstPort, ByteBuffer payload) {
    }
}
