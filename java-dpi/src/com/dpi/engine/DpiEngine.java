package com.dpi.engine;

import com.dpi.flow.FiveTuple;
import com.dpi.flow.Flow;
import com.dpi.flow.FlowTable;
import com.dpi.parser.*;
import com.dpi.io.*;
import com.dpi.inspect.*;
import com.dpi.rules.CompositeRuleEngine;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * The core engine of our DPI system.
 * It reads packets, inspects them one-by-one, runs them through the block
 * rules, and writes allowed packets out to the output PCAP.
 */
public class DpiEngine {

    // Using the standard Java logging API instead of System.out for proper log
    // levels
    private static final Logger log = Logger.getLogger(DpiEngine.class.getName());
    private final Path inputPcap;
    private final Path outputPcap;
    private final int numWorkers;
    private final CompositeRuleEngine ruleEngine;
    private final FlowTable flowTable;

    // AtomicLong is needed because the background thread updates these while
    // the main thread might print them at shutdown
    private final AtomicLong packetsProcessed = new AtomicLong(0);
    private final AtomicLong packetsDropped = new AtomicLong(0);

    public DpiEngine(Path inputPcap, Path outputPcap, int numWorkers,
            CompositeRuleEngine ruleEngine) {
        this.inputPcap = inputPcap;
        this.outputPcap = outputPcap;
        this.numWorkers = numWorkers;
        this.ruleEngine = ruleEngine;
        this.flowTable = new FlowTable(60); // 60 second timeout for stale flows
    }

    public void run() throws IOException, InterruptedException {
        log.info("Starting DPI Engine...");
        log.info("Processing: " + inputPcap + " -> " + outputPcap);

        // We use a single worker thread so packets are always written to the PCAP
        // in the exact order they were read. A multi-thread writer would jumble
        // timestamps.
        ExecutorService threadPool = Executors.newSingleThreadExecutor();

        long packetCount = 0;

        try (PcapReader reader = new PcapReader(inputPcap);
                PcapWriter writer = new PcapWriter(outputPcap, reader.getGlobalHeader())) {

            for (RawPacket packet : reader) {
                // Periodically clean up old connections so we don't run out of memory
                if (++packetCount % 5000 == 0) {
                    flowTable.cleanupStaleFlows(System.currentTimeMillis());
                }

                // Hand each packet off to the single-threaded inspector
                threadPool.submit(() -> processPacket(packet, writer));
            }

            log.info("Finished reading PCAP. Waiting for processing to finish...");
            threadPool.shutdown();
            threadPool.awaitTermination(10, TimeUnit.SECONDS);

            log.info("DPI Engine completed.");
            log.info("Packets Passed:   " + packetsProcessed.get());
            log.info("Packets Dropped:  " + packetsDropped.get());

        } finally {
            if (!threadPool.isTerminated()) {
                threadPool.shutdownNow();
            }
        }
    }

    /**
     * Inspects one packet: tracks its flow, extracts HTTP/TLS details,
     * checks blocking rules, and either writes it or drops it.
     */
    private void processPacket(RawPacket packet, PcapWriter writer) {
        try {
            Optional<FiveTuple> tupleOpt = extractFiveTuple(packet);

            if (tupleOpt.isEmpty()) {
                // Not IPv4/TCP/UDP (e.g. ARP, ICMP) -- just pass it through
                writePacketSafe(writer, packet);
                packetsProcessed.incrementAndGet();
                return;
            }

            FiveTuple tuple = tupleOpt.get();
            Flow flow = flowTable.getOrCreate(tuple, System.currentTimeMillis());

            // Count the bytes for this flow
            flow.addBytes(packet.length());

            // Try to figure out the application layer (HTTP or TLS) on first few packets
            if (!flow.isFullyParsed()) {
                inspectPayload(packet, tuple, flow);
            }

            // If this flow is already marked as blocked from a previous packet, drop it
            if (flow.isBlocked()) {
                packetsDropped.incrementAndGet();
                return;
            }

            // Run the blocking rules against the current flow state
            Optional<String> blockReason = ruleEngine.evaluate(flow);
            if (blockReason.isPresent()) {
                flow.setBlocked(true, blockReason.get());
                packetsDropped.incrementAndGet();
                return;
            }

            // All clear -- write the packet to the output file
            writePacketSafe(writer, packet);
            packetsProcessed.incrementAndGet();

        } catch (Exception e) {
            log.warning("Error processing packet: " + e.getMessage());
        }
    }

    // Synchronized so the single writer thread never overlaps writes
    private synchronized void writePacketSafe(PcapWriter writer, RawPacket packet) throws IOException {
        writer.writePacket(packet);
    }

    /**
     * Digs into the packet payload to identify TLS (via SNI) or HTTP (via Host
     * header).
     */
    private void inspectPayload(RawPacket packet, FiveTuple tuple, Flow flow) {
        ByteBuffer data = packet.data();
        data.position(0);

        Optional<EthernetParser.ParseResult> ethRes = EthernetParser.parse(data);
        if (ethRes.isEmpty())
            return;

        Optional<IPv4Parser.ParseResult> ipRes = IPv4Parser.parse(ethRes.get().payload());
        if (ipRes.isEmpty())
            return;

        ByteBuffer l4Payload = ipRes.get().payload();
        ByteBuffer appPayload = null;

        if (tuple.protocol() == IPv4Parser.PROTOCOL_TCP) {
            Optional<TcpParser.ParseResult> tcpRes = TcpParser.parse(l4Payload);
            if (tcpRes.isPresent()) {
                appPayload = tcpRes.get().payload();
                // Mark connection as done if FIN or RST flag is set
                // Note: Java records use field name directly as accessor (fin(), not isFin())
                if (tcpRes.get().fin() || tcpRes.get().rst()) {
                    flow.setClosed(true);
                }
            }
        } else if (tuple.protocol() == IPv4Parser.PROTOCOL_UDP) {
            Optional<UdpParser.ParseResult> udpRes = UdpParser.parse(l4Payload);
            if (udpRes.isPresent()) {
                appPayload = udpRes.get().payload();
            }
        }

        if (appPayload == null || appPayload.remaining() == 0) {
            return;
        }

        // Try TLS first (HTTPS connections have SNI in the ClientHello)
        Optional<String> sni = TlsSniExtractor.extractSni(appPayload);
        if (sni.isPresent()) {
            flow.setApplicationProtocol("TLS");
            flow.setSniOrHost(sni.get());
            flow.setFullyParsed(true);
            return;
        }

        // Fall back to HTTP Host header
        appPayload.position(0);
        Optional<String> host = HttpHostExtractor.extractHost(appPayload);
        if (host.isPresent()) {
            flow.setApplicationProtocol("HTTP");
            flow.setSniOrHost(host.get());
            flow.setFullyParsed(true);
        }
    }

    /**
     * Parses just enough of the packet to identify the 5-tuple (src/dst IP + port +
     * protocol).
     * Returns empty if we don't support this packet type.
     */
    private Optional<FiveTuple> extractFiveTuple(RawPacket packet) {
        ByteBuffer data = packet.data();
        data.position(0);

        Optional<EthernetParser.ParseResult> ethRes = EthernetParser.parse(data);
        if (ethRes.isEmpty() || ethRes.get().etherType() != EthernetParser.ETHERTYPE_IPV4) {
            return Optional.empty();
        }

        Optional<IPv4Parser.ParseResult> ipRes = IPv4Parser.parse(ethRes.get().payload());
        if (ipRes.isEmpty() || ipRes.get().isFragmented()) {
            return Optional.empty();
        }

        int protocol = ipRes.get().protocol();
        ByteBuffer l4Payload = ipRes.get().payload();

        int srcPort = 0;
        int dstPort = 0;

        if (protocol == IPv4Parser.PROTOCOL_TCP) {
            Optional<TcpParser.ParseResult> tcpRes = TcpParser.parse(l4Payload);
            if (tcpRes.isPresent()) {
                srcPort = tcpRes.get().srcPort();
                dstPort = tcpRes.get().dstPort();
            } else {
                return Optional.empty();
            }
        } else if (protocol == IPv4Parser.PROTOCOL_UDP) {
            Optional<UdpParser.ParseResult> udpRes = UdpParser.parse(l4Payload);
            if (udpRes.isPresent()) {
                srcPort = udpRes.get().srcPort();
                dstPort = udpRes.get().dstPort();
            } else {
                return Optional.empty();
            }
        } else {
            return Optional.empty(); // ICMP, IGMP, etc
        }

        return Optional.of(FiveTuple.createBidirectional(
                ipRes.get().srcIp(), ipRes.get().dstIp(), srcPort, dstPort, protocol));
    }
}
