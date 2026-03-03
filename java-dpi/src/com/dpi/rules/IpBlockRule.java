package com.dpi.rules;

import com.dpi.flow.Flow;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Checks if a flow is communicating with a banned IP address.
 */
public class IpBlockRule implements Rule {

    // Store IPs as integers for faster comparison
    private final Set<Integer> blockedIps = new HashSet<>();

    public void addIp(int ip) {
        blockedIps.add(ip);
    }

    /**
     * Helper method to take a normal string like "192.168.1.1"
     * and convert it into a 32-bit integer for our set.
     */
    public void addIpStr(String ipStr) {
        String[] parts = ipStr.split("\\.");
        if (parts.length != 4) {
            System.err.println("Bad IP format: " + ipStr);
            return;
        }

        // Shift the bytes into a single integer
        int ip = (Integer.parseInt(parts[0]) << 24) |
                (Integer.parseInt(parts[1]) << 16) |
                (Integer.parseInt(parts[2]) << 8) |
                (Integer.parseInt(parts[3]));

        addIp(ip);
    }

    @Override
    public Optional<String> evaluate(Flow flow) {
        // Block if either the source or destination IP is in our bad list
        if (blockedIps.contains(flow.getFiveTuple().srcIp()) ||
                blockedIps.contains(flow.getFiveTuple().dstIp())) {
            return Optional.of("IP blocked!");
        }

        return Optional.empty();
    }
}
