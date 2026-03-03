package com.dpi.inspect;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Server Name Indication (SNI) from TLS Client Hello packets.
 * Designed to prevent buffer overflows and ensure zero-copy logic where
 * possible.
 */
public class TlsSniExtractor {

    // TLS Record Type for Handshake
    private static final byte CONTENT_TYPE_HANDSHAKE = 22;
    // Handshake Type for Client Hello
    private static final byte HANDSHAKE_TYPE_CLIENT_HELLO = 1;
    // Extension Type for SNI
    private static final int EXTENSION_SERVER_NAME = 0;
    // Name Type for Hostname
    private static final byte NAME_TYPE_HOSTNAME = 0;

    /**
     * Parses a TLS payload (typically TCP payload) and tries to extract the SNI.
     * 
     * @param payload Application layer payload
     * @return Optional containing the SNI string if present, or empty.
     */
    public static Optional<String> extractSni(ByteBuffer payload) {
        if (payload.remaining() < 5) {
            return Optional.empty();
        }

        int startPos = payload.position();

        // 1. Check TLS Record Header
        byte contentType = payload.get(startPos);
        if (contentType != CONTENT_TYPE_HANDSHAKE) {
            return Optional.empty();
        }

        // byte 1-2: Version
        // byte 3-4: Length
        int recordLength = payload.getShort(startPos + 3) & 0xFFFF;
        if (payload.remaining() < 5 + recordLength) {
            return Optional.empty(); // Fragmented or cut off
        }

        // 2. Check Handshake Header
        int handshakeOffset = startPos + 5;
        if (handshakeOffset >= payload.limit())
            return Optional.empty();

        byte handshakeType = payload.get(handshakeOffset);
        if (handshakeType != HANDSHAKE_TYPE_CLIENT_HELLO) {
            return Optional.empty();
        }

        // Handshake length (24-bit integer, bytes offset 1,2,3)
        int hsLength = ((payload.get(handshakeOffset + 1) & 0xFF) << 16) |
                ((payload.get(handshakeOffset + 2) & 0xFF) << 8) |
                (payload.get(handshakeOffset + 3) & 0xFF);

        // Advanced offset past handshake header
        int offset = handshakeOffset + 4;

        // Ensure we have enough bounds
        if (offset + hsLength > payload.limit()) {
            return Optional.empty();
        }

        try {
            // Client Version (2 bytes)
            offset += 2;

            // Client Random (32 bytes)
            offset += 32;

            // Session ID Length (1 byte)
            if (offset >= payload.limit())
                return Optional.empty();
            int sessionIdLen = payload.get(offset) & 0xFF;
            offset += 1 + sessionIdLen;

            // Cipher Suites Length (2 bytes)
            if (offset + 2 > payload.limit())
                return Optional.empty();
            int cipherSuitesLen = payload.getShort(offset) & 0xFFFF;
            offset += 2 + cipherSuitesLen;

            // Compression Methods Length (1 byte)
            if (offset >= payload.limit())
                return Optional.empty();
            int compressionMethodsLen = payload.get(offset) & 0xFF;
            offset += 1 + compressionMethodsLen;

            // Extensions Length (2 bytes)
            if (offset + 2 > payload.limit())
                return Optional.empty();
            int extensionsLen = payload.getShort(offset) & 0xFFFF;
            offset += 2;

            int extensionsEnd = offset + extensionsLen;
            if (extensionsEnd > payload.limit()) {
                extensionsEnd = payload.limit();
            }

            // Iterate over extensions
            while (offset + 4 <= extensionsEnd) {
                int extType = payload.getShort(offset) & 0xFFFF;
                int extLen = payload.getShort(offset + 2) & 0xFFFF;
                offset += 4;

                if (offset + extLen > extensionsEnd) {
                    break; // Malformed extension length
                }

                if (extType == EXTENSION_SERVER_NAME) {
                    return parseSniExtension(payload, offset, extLen);
                }

                offset += extLen;
            }

        } catch (IndexOutOfBoundsException e) {
            // In case of malformed packets where bounds checking missed an edge case
            return Optional.empty();
        }

        return Optional.empty();
    }

    private static Optional<String> parseSniExtension(ByteBuffer payload, int offset, int extLen) {
        if (extLen < 2)
            return Optional.empty();

        int serverNameListLen = payload.getShort(offset) & 0xFFFF;
        int listOffset = offset + 2;
        int listEnd = listOffset + serverNameListLen;

        while (listOffset + 3 <= listEnd) {
            byte nameType = payload.get(listOffset);
            int nameLen = payload.getShort(listOffset + 1) & 0xFFFF;
            listOffset += 3;

            if (listOffset + nameLen > listEnd) {
                break;
            }

            if (nameType == NAME_TYPE_HOSTNAME) {
                byte[] nameBytes = new byte[nameLen];
                // Using absolute bulk get to not disturb buffer position
                for (int i = 0; i < nameLen; i++) {
                    nameBytes[i] = payload.get(listOffset + i);
                }
                return Optional.of(new String(nameBytes, StandardCharsets.UTF_8));
            }

            listOffset += nameLen;
        }

        return Optional.empty();
    }
}
