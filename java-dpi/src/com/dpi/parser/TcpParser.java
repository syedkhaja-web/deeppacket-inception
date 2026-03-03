package com.dpi.parser;

import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * Parses TCP headers.
 */
public class TcpParser {

    /**
     * Parses the TCP header and returns its payload (Application layer) and
     * metadata.
     */
    public static Optional<ParseResult> parse(ByteBuffer tcpData) {
        if (tcpData.remaining() < 20) {
            return Optional.empty(); // Minimum TCP header size
        }

        int startPos = tcpData.position();

        int srcPort = tcpData.getShort(startPos) & 0xFFFF;
        int dstPort = tcpData.getShort(startPos + 2) & 0xFFFF;

        long seqNum = Integer.toUnsignedLong(tcpData.getInt(startPos + 4));
        long ackNum = Integer.toUnsignedLong(tcpData.getInt(startPos + 8));

        int dataOffsetAndFlags = tcpData.getShort(startPos + 12) & 0xFFFF;
        int dataOffset = (dataOffsetAndFlags >> 12) & 0x0F;
        int headerLength = dataOffset * 4;

        if (headerLength < 20 || tcpData.remaining() < headerLength) {
            return Optional.empty(); // Malformed
        }

        boolean syn = (dataOffsetAndFlags & 0x0002) != 0;
        boolean ack = (dataOffsetAndFlags & 0x0010) != 0;
        boolean fin = (dataOffsetAndFlags & 0x0001) != 0;
        boolean rst = (dataOffsetAndFlags & 0x0004) != 0;

        // Slice payload
        int oldLimit = tcpData.limit();
        tcpData.position(startPos + headerLength);
        ByteBuffer payload = tcpData.slice();

        // Restore buffer state
        tcpData.position(startPos);
        tcpData.limit(oldLimit);

        return Optional.of(new ParseResult(srcPort, dstPort, seqNum, ackNum, syn, ack, fin, rst, payload));
    }

    public record ParseResult(int srcPort, int dstPort, long seqNum, long ackNum,
            boolean syn, boolean ack, boolean fin, boolean rst,
            ByteBuffer payload) {
    }
}
