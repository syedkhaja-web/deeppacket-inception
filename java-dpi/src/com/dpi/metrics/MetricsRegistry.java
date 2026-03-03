package com.dpi.metrics;

import java.util.concurrent.atomic.LongAdder;

/**
 * Thread-safe registry for performance counters and metrics.
 * Uses LongAdder instead of AtomicLong for high-concurrency throughput under
 * heavy contention.
 */
public class MetricsRegistry {

    private final LongAdder packetsProcessed = new LongAdder();
    private final LongAdder packetsDropped = new LongAdder();
    private final LongAdder bytesProcessed = new LongAdder();
    private final LongAdder flowsBlocked = new LongAdder();
    private final LongAdder evictedFlows = new LongAdder();
    private final LongAdder errors = new LongAdder();

    // Advanced Metrics
    private final LongAdder idsAlerts = new LongAdder();
    private final java.util.concurrent.ConcurrentHashMap<String, LongAdder> appBytesProcessed = new java.util.concurrent.ConcurrentHashMap<>();

    private final long startTimeMillis = System.currentTimeMillis();

    public void incrementPacketsProcessed() {
        packetsProcessed.increment();
    }

    public void incrementPacketsDropped() {
        packetsDropped.increment();
    }

    public void addBytesProcessed(long bytes, String appProtocol) {
        bytesProcessed.add(bytes);
        if (appProtocol != null) {
            appBytesProcessed.computeIfAbsent(appProtocol, k -> new LongAdder()).add(bytes);
        }
    }

    public void incrementFlowsBlocked() {
        flowsBlocked.increment();
    }

    public void addEvictedFlows(int count) {
        evictedFlows.add(count);
    }

    public void incrementErrors() {
        errors.increment();
    }

    public void incrementIdsAlerts() {
        idsAlerts.increment();
    }

    public long getPacketsProcessed() {
        return packetsProcessed.sum();
    }

    public long getPacketsDropped() {
        return packetsDropped.sum();
    }

    public long getBytesProcessed() {
        return bytesProcessed.sum();
    }

    public long getFlowsBlocked() {
        return flowsBlocked.sum();
    }

    public long getEvictedFlows() {
        return evictedFlows.sum();
    }

    public long getErrors() {
        return errors.sum();
    }

    public long getIdsAlerts() {
        return idsAlerts.sum();
    }

    public java.util.Map<String, Long> getAppUsageBytes() {
        java.util.Map<String, Long> usage = new java.util.HashMap<>();
        for (java.util.Map.Entry<String, LongAdder> entry : appBytesProcessed.entrySet()) {
            usage.put(entry.getKey(), entry.getValue().sum());
        }
        return usage;
    }

    public long getUptimeMillis() {
        return System.currentTimeMillis() - startTimeMillis;
    }

    @Override
    public String toString() {
        return String.format(
                "Metrics: [pkts=%d, drops=%d, bytes=%d, block_flows=%d, evict=%d, ids_alerts=%d, errs=%d]",
                getPacketsProcessed(), getPacketsDropped(), getBytesProcessed(),
                getFlowsBlocked(), getEvictedFlows(), getIdsAlerts(), getErrors());
    }
}
