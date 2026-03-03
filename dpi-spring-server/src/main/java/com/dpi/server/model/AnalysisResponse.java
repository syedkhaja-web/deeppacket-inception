package com.dpi.server.model;

import java.util.List;

// everything we found after scanning the pcap
public record AnalysisResponse(
                int totalFlows,
                int anomalies,
                int packetsDropped,
                long processingMs,
                String summary,
                List<FlowReport> flows) {
}
