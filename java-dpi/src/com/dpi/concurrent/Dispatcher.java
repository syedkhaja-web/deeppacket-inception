package com.dpi.concurrent;

import com.dpi.flow.FiveTuple;
import com.dpi.io.RawPacket;

/**
 * Route packets to the correct worker based on hash of the FiveTuple.
 * Ensures flow affinity (same flow always goes to same worker).
 */
public class Dispatcher {

    private final Worker[] workers;
    private final int workerCount;

    public Dispatcher(Worker[] workers) {
        this.workers = workers;
        this.workerCount = workers.length;
    }

    /**
     * Dispatches a packet to a worker based on the flow's hash.
     * Uses modulo operation for fast distribution.
     */
    public void dispatch(RawPacket packet, FiveTuple tuple) {
        // We use Math.abs to handle negative hash codes
        // Fallback for Integer.MIN_VALUE since Math.abs(Integer.MIN_VALUE) ==
        // Integer.MIN_VALUE
        int hash = tuple.hashCode();
        if (hash == Integer.MIN_VALUE) {
            hash = 0;
        } else {
            hash = Math.abs(hash);
        }

        int workerIndex = hash % workerCount;
        workers[workerIndex].submit(packet, tuple);
    }

    /**
     * Instructs all workers to shut down gracefully.
     */
    public void shutdown() {
        for (Worker worker : workers) {
            worker.shutdown();
        }
    }
}
