package test;

import com.dpi.inspect.HttpHostExtractor;

import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * Tests for the HTTP Host header extractor.
 */
public class HttpHostExtractorTest {

    public static void main(String[] args) {
        int passed = 0;
        int failed = 0;

        // Test 1: Normal HTTP GET request
        try {
            String http = "GET / HTTP/1.1\r\nHost: facebook.com\r\nUser-Agent: test\r\n\r\n";
            Optional<String> host = HttpHostExtractor.extractHost(toBuffer(http));
            assert host.isPresent() : "Should extract host";
            assert host.get().equals("facebook.com") : "Host should be facebook.com, got: " + host.get();
            System.out.println("PASS: normal GET request host extraction");
            passed++;
        } catch (AssertionError e) {
            System.out.println("FAIL: normal GET request - " + e.getMessage());
            failed++;
        }

        // Test 2: Host with port number (should strip the port)
        try {
            String http = "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
            Optional<String> host = HttpHostExtractor.extractHost(toBuffer(http));
            assert host.isPresent() : "Should find host";
            assert host.get().equals("example.com") : "Should strip port, got: " + host.get();
            System.out.println("PASS: host with port strips port number");
            passed++;
        } catch (AssertionError e) {
            System.out.println("FAIL: host with port - " + e.getMessage());
            failed++;
        }

        // Test 3: Case-insensitive header name
        try {
            String http = "GET / HTTP/1.1\r\nhost: google.com\r\n\r\n";
            Optional<String> host = HttpHostExtractor.extractHost(toBuffer(http));
            assert host.isPresent() : "Should handle lowercase 'host:'";
            assert host.get().equals("google.com") : "Should return google.com, got: " + host.get();
            System.out.println("PASS: case-insensitive host header");
            passed++;
        } catch (AssertionError e) {
            System.out.println("FAIL: case-insensitive - " + e.getMessage());
            failed++;
        }

        // Test 4: No host header present (should return empty)
        try {
            String http = "GET / HTTP/1.1\r\nContent-Type: text/html\r\n\r\n";
            Optional<String> host = HttpHostExtractor.extractHost(toBuffer(http));
            assert host.isEmpty() : "Should be empty when no Host header present";
            System.out.println("PASS: no host header returns empty");
            passed++;
        } catch (AssertionError e) {
            System.out.println("FAIL: no host header - " + e.getMessage());
            failed++;
        }

        // Test 5: Empty buffer (should not crash)
        try {
            Optional<String> host = HttpHostExtractor.extractHost(ByteBuffer.allocate(0));
            assert host.isEmpty() : "Empty buffer should return empty";
            System.out.println("PASS: empty buffer doesn't crash");
            passed++;
        } catch (Exception e) {
            System.out.println("FAIL: empty buffer threw exception - " + e.getMessage());
            failed++;
        }

        System.out.println("\nHttpHostExtractorTest: " + passed + " passed, " + failed + " failed");
    }

    private static ByteBuffer toBuffer(String s) {
        return ByteBuffer.wrap(s.getBytes());
    }
}
