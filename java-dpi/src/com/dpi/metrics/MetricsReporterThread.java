package com.dpi.metrics;

/**
 * Periodically prints the current state of metrics to the standard output.
 * Helps monitor throughput in real-time.
 */
public class MetricsReporterThread extends Thread {

    private final MetricsRegistry registry;
    private final long intervalMillis;
    private volatile boolean running = true;

    // To calculate deltas and rates
    private long lastPackets = 0;
    private long lastBytes = 0;
    private long lastTime = System.currentTimeMillis();

    public MetricsReporterThread(MetricsRegistry registry, long intervalMillis) {
        super("Metrics-Reporter");
        this.registry = registry;
        this.intervalMillis = intervalMillis;
        this.setDaemon(true); // Don't prevent JVM shutdown
    }

    public void shutdown() {
        this.running = false;
        this.interrupt();
    }

    @Override
    public void run() {
        System.out.println("Starting Metrics Reporter...");
        while (running) {
            try {
                Thread.sleep(intervalMillis);
                report();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        // Final report on shutdown
        System.out.println("Final " + registry.toString());
    }

    private void report() {
        long currentPackets = registry.getPacketsProcessed();
        long currentBytes = registry.getBytesProcessed();
        long currentTime = System.currentTimeMillis();

        long timeDelta = currentTime - lastTime;
        if (timeDelta == 0)
            return;

        long packetsDelta = currentPackets - lastPackets;
        long bytesDelta = currentBytes - lastBytes;

        // pps = packets per second
        long pps = (packetsDelta * 1000) / timeDelta;

        // Mbps = Megabits per second
        double mbps = ((bytesDelta * 8.0) / 1_000_000.0) / (timeDelta / 1000.0);

        System.out.printf("[Metrics] %s | Rate: %d pps, %.2f Mbps%n",
                registry.toString(), pps, mbps);

        lastPackets = currentPackets;
        lastBytes = currentBytes;
        lastTime = currentTime;
    }
}
