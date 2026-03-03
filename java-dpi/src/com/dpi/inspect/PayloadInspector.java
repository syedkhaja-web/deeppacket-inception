package com.dpi.inspect;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * High-performance intrusion detection scanner for raw ByteBuffers.
 * Searches for malicious byte patterns without converting payloads to Strings.
 */
public class PayloadInspector {

    private final List<byte[]> signatures = new ArrayList<>();

    public void addSignature(String signatureAscii) {
        signatures.add(signatureAscii.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    /**
     * Checks if the given buffer contains any of the malicious signatures.
     * Operates without mutating the buffer position.
     * 
     * @param payload The raw protocol payload
     * @return true if a signature is matched, false otherwise
     */
    public boolean containsSignatures(ByteBuffer payload) {
        if (signatures.isEmpty() || payload == null || payload.remaining() == 0) {
            return false;
        }

        // Fast path naive search. High-end implementations often use Aho-Corasick or
        // Boyer-Moore, but for simplicity and small signature counts, naive iterating
        // directly from the direct ByteBuffer is fast enough due to spatial locality.

        int limit = payload.limit();
        int startPos = payload.position();

        for (byte[] sig : signatures) {
            if (sig.length == 0 || sig.length > payload.remaining()) {
                continue;
            }

            int endSearch = limit - sig.length;
            for (int i = startPos; i <= endSearch; i++) {
                boolean match = true;
                for (int j = 0; j < sig.length; j++) {
                    if (payload.get(i + j) != sig[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return true;
                }
            }
        }

        return false;
    }
}
