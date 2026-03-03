package test;

import com.dpi.parser.IPv4Parser;

import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * Tests for IPv4 header parsing.
 */
public class IPv4ParserTest {

    // Build a 20-byte IPv4 header + some payload bytes
    private static ByteBuffer buildIpHeader(byte versionIhl, int fragFlags, int protocol,
            int s1, int s2, int s3, int s4,
            int d1, int d2, int d3, int d4, int extraPayload) {
        ByteBuffer buf = ByteBuffer.allocate(20 + extraPayload);
        buf.put(versionIhl); // Version + IHL
        buf.put((byte) 0); // DSCP
        buf.putShort((short) (20 + extraPayload)); // Total length
        buf.putShort((short) 1234); // ID
        buf.putShort((short) fragFlags); // Flags + fragment offset
        buf.put((byte) 64); // TTL
        buf.put((byte) protocol); // Protocol
        buf.putShort((short) 0); // Checksum
        buf.put((byte) s1);
        buf.put((byte) s2);
        buf.put((byte) s3);
        buf.put((byte) s4);
        buf.put((byte) d1);
        buf.put((byte) d2);
        buf.put((byte) d3);
        buf.put((byte) d4);
        buf.position(0);
        return buf;
    }

    public static void main(String[] args) {
        int passed = 0;
        int failed = 0;

        // Test 1: Valid IPv4 TCP header
        try {
            ByteBuffer buf = buildIpHeader((byte) 0x45, 0x4000, 6, 1, 2, 3, 4, 5, 6, 7, 8, 20);
            Optional<IPv4Parser.ParseResult> r = IPv4Parser.parse(buf);
            assert r.isPresent() : "Should parse valid IPv4";
            assert r.get().protocol() == 6 : "Protocol should be TCP(6)";
            assert r.get().srcIp() == ((1 << 24) | (2 << 16) | (3 << 8) | 4) : "srcIp mismatch";
            assert r.get().dstIp() == ((5 << 24) | (6 << 16) | (7 << 8) | 8) : "dstIp mismatch";
            assert !r.get().isFragmented() : "Should not be fragmented";
            System.out.println("PASS: valid IPv4 header parsed correctly");
            passed++;
        } catch (AssertionError e) {
            System.out.println("FAIL: valid IPv4 - " + e.getMessage());
            failed++;
        }

        // Test 2: Fragmented packet → return empty (no reassembly support)
        try {
            ByteBuffer buf = buildIpHeader((byte) 0x45, 0x0008, 6, 1, 2, 3, 4, 5, 6, 7, 8, 20);
            Optional<IPv4Parser.ParseResult> r = IPv4Parser.parse(buf);
            assert r.isEmpty() : "Fragmented packet should return empty";
            System.out.println("PASS: fragmented packet returns empty");
            passed++;
        } catch (AssertionError e) {
            System.out.println("FAIL: fragmented - " + e.getMessage());
            failed++;
        }

        // Test 3: IPv6 packet version field → rejected by IPv4 parser
        try {
            ByteBuffer buf = ByteBuffer.allocate(40);
            buf.put((byte) 0x60); // Version 6
            buf.position(0);
            Optional<IPv4Parser.ParseResult> r = IPv4Parser.parse(buf);
            assert r.isEmpty() : "IPv6 header should be rejected";
            System.out.println("PASS: IPv6 packet rejected by IPv4 parser");
            passed++;
        } catch (AssertionError e) {
            System.out.println("FAIL: IPv6 rejection - " + e.getMessage());
            failed++;
        }

        // Test 4: Buffer too short → no crash
        try {
            ByteBuffer buf = ByteBuffer.wrap(new byte[] { 0x45, 0x00, 0x00 });
            Optional<IPv4Parser.ParseResult> r = IPv4Parser.parse(buf);
            assert r.isEmpty() : "Truncated buffer should return empty";
            System.out.println("PASS: truncated buffer doesn't crash");
            passed++;
        } catch (Exception e) {
            System.out.println("FAIL: truncated buffer threw exception - " + e.getMessage());
            failed++;
        }

        System.out.println("\nIPv4ParserTest: " + passed + " passed, " + failed + " failed");
    }
}
