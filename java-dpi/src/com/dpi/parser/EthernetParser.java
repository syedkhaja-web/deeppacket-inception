package com.dpi.parser;

import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * Parses Ethernet II frames.
 */
public class EthernetParser {

    // Common EtherTypes
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_VLAN = 0x8100;

    /**
     * Parses the Ethernet header and returns a slice of the ByteBuffer pointing to
     * the payload (Network layer).
     * The input buffer's position is left unchanged; a new sliced view is returned.
     * 
     * @param packetData The raw network packet data
     * @return An Optional containing the slice of the Network layer and its
     *         EtherType, or empty if invalid
     */
    public static Optional<ParseResult> parse(ByteBuffer packetData) {
        if (packetData.remaining() < 14) {
            return Optional.empty(); // Too short for Ethernet
        }

        int startPos = packetData.position();

        // Skip MACs (6 bytes destination, 6 bytes source)
        int etherTypeOffset = startPos + 12;
        int etherType = packetData.getShort(etherTypeOffset) & 0xFFFF;

        int headerLength = 14;

        // Handle VLAN tag (802.1Q)
        if (etherType == ETHERTYPE_VLAN) {
            if (packetData.remaining() < 18) {
                return Optional.empty();
            }
            etherType = packetData.getShort(startPos + 16) & 0xFFFF;
            headerLength = 18;
        }

        // Slice payload
        int oldLimit = packetData.limit();
        packetData.position(startPos + headerLength);
        ByteBuffer payload = packetData.slice();
        packetData.position(startPos); // restore original position
        packetData.limit(oldLimit); // restore original limit

        return Optional.of(new ParseResult(etherType, payload));
    }

    public record ParseResult(int etherType, ByteBuffer payload) {
    }
}
