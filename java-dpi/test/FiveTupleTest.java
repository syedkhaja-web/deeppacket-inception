package test;

import com.dpi.flow.FiveTuple;

/**
 * Tests for FiveTuple -- making sure bidirectional equality works correctly.
 *
 * Two flows going in opposite directions (A->B and B->A) represent the same
 * TCP connection. createBidirectional() normalizes the direction so both
 * sides hit the same map key.
 */
public class FiveTupleTest {

    // Converts "a.b.c.d" to a 32-bit int the same way IPv4Parser does
    private static int ip(int a, int b, int c, int d) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }

    public static void main(String[] args) {
        int passed = 0;
        int failed = 0;

        // Test 1: Same flow from same direction should be equal
        try {
            FiveTuple t1 = FiveTuple.createBidirectional(ip(192, 168, 1, 1), ip(10, 0, 0, 1), 12345, 80, 6);
            FiveTuple t2 = FiveTuple.createBidirectional(ip(192, 168, 1, 1), ip(10, 0, 0, 1), 12345, 80, 6);
            assert t1.equals(t2) : "Same tuple should be equal";
            assert t1.hashCode() == t2.hashCode() : "Same hash expected";
            System.out.println("PASS: same-direction equality");
            passed++;
        } catch (AssertionError e) {
            System.out.println("FAIL: same-direction equality - " + e.getMessage());
            failed++;
        }

        // Test 2: Reversed flow (B->A) should match (A->B) -- critical for
        // bidirectional tracking
        try {
            FiveTuple forward = FiveTuple.createBidirectional(ip(192, 168, 1, 1), ip(10, 0, 0, 1), 12345, 80, 6);
            FiveTuple backward = FiveTuple.createBidirectional(ip(10, 0, 0, 1), ip(192, 168, 1, 1), 80, 12345, 6);
            assert forward.equals(backward) : "Reversed tuple should equal forward (bidirectional)";
            assert forward.hashCode() == backward.hashCode() : "Reversed tuple same hashCode";
            System.out.println("PASS: bidirectional equality");
            passed++;
        } catch (AssertionError e) {
            System.out.println("FAIL: bidirectional equality - " + e.getMessage());
            failed++;
        }

        // Test 3: Different protocol should NOT match
        try {
            FiveTuple tcp = FiveTuple.createBidirectional(ip(192, 168, 1, 1), ip(10, 0, 0, 1), 12345, 80, 6); // TCP
            FiveTuple udp = FiveTuple.createBidirectional(ip(192, 168, 1, 1), ip(10, 0, 0, 1), 12345, 80, 17); // UDP
            assert !tcp.equals(udp) : "TCP and UDP should NOT be equal";
            System.out.println("PASS: different protocol not equal");
            passed++;
        } catch (AssertionError e) {
            System.out.println("FAIL: different protocol not equal - " + e.getMessage());
            failed++;
        }

        // Test 4: Different destination port should NOT match
        try {
            FiveTuple http = FiveTuple.createBidirectional(ip(192, 168, 1, 1), ip(10, 0, 0, 1), 12345, 80, 6);
            FiveTuple https = FiveTuple.createBidirectional(ip(192, 168, 1, 1), ip(10, 0, 0, 1), 12345, 443, 6);
            assert !http.equals(https) : "Port 80 and 443 should NOT match";
            System.out.println("PASS: different ports not equal");
            passed++;
        } catch (AssertionError e) {
            System.out.println("FAIL: different ports not equal - " + e.getMessage());
            failed++;
        }

        System.out.println("\nFiveTupleTest: " + passed + " passed, " + failed + " failed");
    }
}
