package com.dpi.server.model;

// one flow = one connection we saw in the pcap
// riskScore is 0-100, threatLevel tells you how bad it is
public record FlowReport(
                String srcIp,
                String dstIp,
                int srcPort,
                int dstPort,
                String protocol,
                String appProtocol,
                String sniOrHost, // the domain name if we could figure it out
                long packets,
                long bytes,
                long riskScore, // 0 = chill, 100 = very sus
                String threatLevel, // NORMAL / SUSPICIOUS / MALICIOUS / CRITICAL
                boolean blocked,
                String blockReason) {
}
