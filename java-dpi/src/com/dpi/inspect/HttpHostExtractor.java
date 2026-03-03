package com.dpi.inspect;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Host header from an HTTP request.
 * Uses a fast byte-scanning approach to avoid unnecessary allocations.
 */
public class HttpHostExtractor {

    private static final byte[] HOST_HEADER = "Host: ".getBytes(StandardCharsets.US_ASCII);
    private static final byte CR = '\r';
    private static final byte LF = '\n';

    /**
     * Parses the HTTP payload and extracts the Host header if present.
     * Note: This assumes the payload starts at the beginning of the HTTP request.
     */
    public static Optional<String> extractHost(ByteBuffer payload) {
        if (payload.remaining() < 16) {
            return Optional.empty();
        }

        // Fast check: Is it an HTTP request? (GET, POST, PUT, HEAD, etc.)
        // We only care if it's "HTTP-like", we don't strictly validate the method.
        // We look for 'Host: ' in the first chunk of the payload, up to the end of
        // headers \r\n\r\n

        int startPos = payload.position();
        int endPos = payload.limit();

        // Don't search beyond typical HTTP header sizes to prevent performance
        // degradation
        // on very large payloads that aren't HTTP headers.
        int searchLimit = Math.min(endPos, startPos + 2048);

        for (int i = startPos; i < searchLimit - HOST_HEADER.length; i++) {
            if (matches(payload, i, HOST_HEADER)) {
                // Found 'Host: '
                int valueStart = i + HOST_HEADER.length;

                // Skip optional leading spaces
                while (valueStart < searchLimit && payload.get(valueStart) == ' ') {
                    valueStart++;
                }

                // Find end of line (\r or \n)
                int valueEnd = valueStart;
                while (valueEnd < searchLimit) {
                    byte b = payload.get(valueEnd);
                    if (b == CR || b == LF) {
                        break;
                    }
                    valueEnd++;
                }

                int len = valueEnd - valueStart;
                if (len > 0 && len < 256) { // Hostnames shouldn't be massive
                    byte[] hostBytes = new byte[len];
                    for (int j = 0; j < len; j++) {
                        hostBytes[j] = payload.get(valueStart + j);
                    }
                    // Strip optional port off the host header (e.g. host.com:80 -> host.com)
                    String hostWithPort = new String(hostBytes, StandardCharsets.US_ASCII);
                    int colonIdx = hostWithPort.indexOf(':');
                    if (colonIdx > 0) {
                        return Optional.of(hostWithPort.substring(0, colonIdx));
                    }
                    return Optional.of(hostWithPort);
                }
                break;
            }

            // Fast exit if we hit end of headers
            if (i > startPos + 3 &&
                    payload.get(i) == CR && payload.get(i + 1) == LF &&
                    payload.get(i - 2) == CR && payload.get(i - 1) == LF) {
                break; // End of HTTP headers
            }
        }

        return Optional.empty();
    }

    private static boolean matches(ByteBuffer buffer, int offset, byte[] target) {
        for (int i = 0; i < target.length; i++) {
            if (buffer.get(offset + i) != target[i] &&
            // Case insensitive 'Host' check (hH oO sS tT)
                    Character.toLowerCase((char) buffer.get(offset + i)) != Character.toLowerCase((char) target[i])) {
                return false;
            }
        }
        return true;
    }
}
