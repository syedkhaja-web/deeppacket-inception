package com.dpi.server.model;

import java.util.Set;

// basic stats snapshot
public record MetricsResponse(
                long totalPacketsProcessed,
                long totalPacketsDropped,
                long totalAnomaliesDetected,
                int blockedIpCount,
                int blockedDomainCount,
                Set<String> blockedIps,
                Set<String> blockedDomains,
                String modelStatus // tells you if the ML model loaded ok
) {
}
