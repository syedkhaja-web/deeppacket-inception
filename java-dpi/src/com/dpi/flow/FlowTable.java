package com.dpi.flow;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Stores network flows in a thread-safe map.
 * This acts as our connection tracking table.
 */
public class FlowTable {

    // Using ConcurrentHashMap to handle multiple threads easily
    private final Map<FiveTuple, Flow> flows = new ConcurrentHashMap<>();
    private final long timeoutMillis;

    public FlowTable(int timeoutSeconds) {
        this.timeoutMillis = timeoutSeconds * 1000L;
    }

    /**
     * Gets an existing connection flow or creates a new one if it doesn't exist.
     */
    public Flow getOrCreate(FiveTuple tuple, long timestamp) {
        return flows.computeIfAbsent(tuple, key -> new Flow(tuple, timestamp));
    }

    /**
     * Removes flows that haven't been active for a while or are closed.
     * This keeps our RAM usage low.
     */
    public void cleanupStaleFlows(long currentTime) {
        for (Map.Entry<FiveTuple, Flow> entry : flows.entrySet()) {
            Flow flow = entry.getValue();
            boolean isOld = (currentTime - flow.getLastSeenTime()) > timeoutMillis;

            if (flow.isClosed() || isOld) {
                flows.remove(entry.getKey());
            }
        }
    }

    public int size() {
        return flows.size();
    }
}
