package com.dpi.flow;

/**
 * Represents the 5-tuple that uniquely identifies a network connection.
 * We use this as a key in our FlowTable to track packets belonging to the same
 * flow.
 * A record automatically gives us equals() and hashCode()!
 */
public record FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {

    /**
     * Creates a bidirectional tuple. We sort the IP and ports so that packets
     * going in either direction (A to B, or B to A) generate the same tuple object.
     * This helps us track the whole conversation as one Flow.
     */
    public static FiveTuple createBidirectional(int ip1, int ip2, int port1, int port2, int protocol) {
        int srcIp, dstIp, srcPort, dstPort;

        if (ip1 < ip2) {
            srcIp = ip1;
            dstIp = ip2;
            srcPort = port1;
            dstPort = port2;
        } else if (ip1 > ip2) {
            srcIp = ip2;
            dstIp = ip1;
            srcPort = port2;
            dstPort = port1;
        } else {
            // If IPs are the same, order by port to keep it consistent
            srcIp = ip1;
            dstIp = ip1;
            if (port1 < port2) {
                srcPort = port1;
                dstPort = port2;
            } else {
                srcPort = port2;
                dstPort = port1;
            }
        }

        return new FiveTuple(srcIp, dstIp, srcPort, dstPort, protocol);
    }
}
