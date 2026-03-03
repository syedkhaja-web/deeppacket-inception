package com.dpi.concurrent;

import com.dpi.flow.FiveTuple;
import com.dpi.flow.Flow;
import com.dpi.flow.FlowTable;
import com.dpi.inspect.HttpHostExtractor;
import com.dpi.inspect.TlsSniExtractor;
import com.dpi.io.RawPacket;
import com.dpi.metrics.MetricsRegistry;
import com.dpi.parser.EthernetParser;
import com.dpi.parser.IPv4Parser;
import com.dpi.parser.TcpParser;
import com.dpi.parser.UdpParser;
import com.dpi.rules.CompositeRuleEngine;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * An independent worker thread that processes a subset of flows.
 * Uses a single-threaded execution model per worker to eliminate lock
 * contention
 * on the FlowTable.
 */
public class Worker implements Runnable {

    // Capacity bounds to prevent OutOfMemory errors on sudden burst
    private static final int QUEUE_CAPACITY = 65536;

    // Shutdown sentinel
    private static final PacketTask POISON_PILL = new PacketTask(null, null);

    private final BlockingQueue<PacketTask> queue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
    private final FlowTable flowTable;
    private final CompositeRuleEngine ruleEngine;
    private final MetricsRegistry metrics;
    private final Consumer<RawPacket> packetWriter;
    private final com.dpi.inspect.PayloadInspector payloadInspector;

    private volatile boolean running = true;

    // Records the packet and its extracted tuple so we don't have to re-parse
    // L2/L3/L4 initially
    // We do have to re-parse the buffers for the payload inspection, but that's
    // fine.
    private record PacketTask(RawPacket packet, FiveTuple tuple) {
    }

    public Worker(long flowTimeoutSeconds, long defaultRateLimitBytesPerSec, CompositeRuleEngine ruleEngine,
            MetricsRegistry metrics, Consumer<RawPacket> packetWriter,
            com.dpi.inspect.PayloadInspector payloadInspector) {
        this.flowTable = new FlowTable((int) flowTimeoutSeconds);
        this.ruleEngine = ruleEngine;
        this.metrics = metrics;
        this.packetWriter = packetWriter;
        this.payloadInspector = payloadInspector;
    }

    /**
     * Submits a packet to this worker's queue.
     * Blocks if the queue is full (provides backpressure up to the reader).
     */
    public void submit(RawPacket packet, FiveTuple tuple) {
        try {
            // We MUST copy the raw packet because the PcapReader reuses the underlying
            // mapped buffer slice view
            // (or rather, its memory might be unmapped or overwritten if it was a live
            // capture).
            // Actually, for memory-mapped files without overwrite, it's safe to pass the
            // view,
            // BUT each thread needs its OWN ByteBuffer instance because position/limit are
            // stateful.
            // RawPacket.data() returns a duplicate view, which is thread-safe as long as
            // the underlying memory is valid.
            // But we should retain a safe reference. We use a copied packet to be safe in a
            // queue model.
            queue.put(new PacketTask(packet.copy(), tuple));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void shutdown() {
        this.running = false;
        try {
            queue.put(POISON_PILL);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void run() {
        long lastEvictionTime = System.nanoTime();
        final long EVICTION_INTERVAL = 10_000_000_000L; // 10 seconds

        while (running || !queue.isEmpty()) {
            try {
                PacketTask task = queue.poll(100, TimeUnit.MILLISECONDS);

                if (task == POISON_PILL) {
                    break;
                }

                if (task != null) {
                    metrics.incrementPacketsProcessed();
                    processPacket(task.packet(), task.tuple());

                    // Periodic eviction check could be driven by packet timestamps
                    // rather than wall clock for offline PCAP processing.
                    long pktTime = task.packet().header().timestampNanos(true);
                    if (pktTime - lastEvictionTime > EVICTION_INTERVAL) {
                        flowTable.cleanupStaleFlows(System.currentTimeMillis());
                        lastEvictionTime = pktTime;
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                // Log and continue, don't crash the worker
                System.err.println("Error processing packet: " + e.getMessage());
                metrics.incrementErrors();
            }
        }
    }

    private void processPacket(RawPacket packet, FiveTuple tuple) {
        long timestampNanos = packet.header().timestampNanos(true);
        Flow flow = flowTable.getOrCreate(tuple, timestampNanos);

        flow.addBytes(packet.length());
        metrics.addBytesProcessed(packet.length(), flow.getApplicationProtocol().orElse(null));

        // Fast path for blocked flows: just drop
        if (flow.isBlocked()) {
            metrics.incrementPacketsDropped();
            return;
        }

        // Only do DPI if we haven't already fully classified the flow
        if (!flow.isFullyParsed() && packet.length() > 0) {
            inspectDpi(packet, flow);
        }

        // Apply Rules
        Optional<String> blockReason = ruleEngine.evaluate(flow);
        if (blockReason.isPresent()) {
            flow.setBlocked(true, blockReason.get());
            metrics.incrementFlowsBlocked();
            metrics.incrementPacketsDropped();
            return; // Dropped
        }

        // Apply Rate Limiting
        if (!flow.tryConsumeBandwidth(packet.length(), timestampNanos)) {
            // Packet dropped due to rate limiting
            metrics.incrementPacketsDropped();
            return;
        }

        // Allowed packet: Write it
        if (packetWriter != null) {
            packetWriter.accept(packet);
        }
    }

    private void inspectDpi(RawPacket packet, Flow flow) {
        ByteBuffer data = packet.data();

        // Fast skip over headers since we already parsed the tuple
        Optional<EthernetParser.ParseResult> ethRes = EthernetParser.parse(data);
        if (ethRes.isEmpty())
            return;

        if (ethRes.get().etherType() != EthernetParser.ETHERTYPE_IPV4)
            return;

        Optional<IPv4Parser.ParseResult> ipRes = IPv4Parser.parse(ethRes.get().payload());
        if (ipRes.isEmpty() || ipRes.get().isFragmented())
            return;

        ByteBuffer transportPayload = null;

        if (ipRes.get().protocol() == IPv4Parser.PROTOCOL_TCP) {
            Optional<TcpParser.ParseResult> tcpRes = TcpParser.parse(ipRes.get().payload());
            if (tcpRes.isPresent()) {
                transportPayload = tcpRes.get().payload();
                if (tcpRes.get().fin() || tcpRes.get().rst()) {
                    flow.setClosed(true);
                }
            }
        } else if (ipRes.get().protocol() == IPv4Parser.PROTOCOL_UDP) {
            Optional<UdpParser.ParseResult> udpRes = UdpParser.parse(ipRes.get().payload());
            if (udpRes.isPresent())
                transportPayload = udpRes.get().payload();
        }

        if (transportPayload == null || transportPayload.remaining() == 0)
            return;

        // IDS Scanning
        if (payloadInspector != null && payloadInspector.containsSignatures(transportPayload)) {
            metrics.incrementIdsAlerts();
            // In a strict setup, we might also: flow.block("IDS_ALERT");
            // But requirement: "do not block unless configured". So we just alert.
        }

        transportPayload.position(0); // rewind for SNI

        // Try extracting TLS SNI first (Common on 443, but we check agnostic of port)
        Optional<String> sni = TlsSniExtractor.extractSni(transportPayload);
        if (sni.isPresent()) {
            flow.setApplicationProtocol("TLS");
            flow.setSniOrHost(sni.get());
            flow.setFullyParsed(true);
            return;
        }

        // Try extracting HTTP Host
        transportPayload.position(0); // rewind
        Optional<String> host = HttpHostExtractor.extractHost(transportPayload);
        if (host.isPresent()) {
            flow.setApplicationProtocol("HTTP");
            flow.setSniOrHost(host.get());
            flow.setFullyParsed(true);
            return;
        }

        // If neither, maybe wait for more packets. We don't mark setFullyParsed(true)
        // just yet if the payload was too small (< handshake size).
    }
}
