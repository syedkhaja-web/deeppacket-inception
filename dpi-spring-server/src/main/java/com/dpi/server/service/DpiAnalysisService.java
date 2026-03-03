package com.dpi.server.service;

import com.dpi.flow.Flow;
import com.dpi.flow.FiveTuple;
import com.dpi.inspect.HttpHostExtractor;
import com.dpi.inspect.TlsSniExtractor;
import com.dpi.io.PcapReader;
import com.dpi.io.RawPacket;
import com.dpi.parser.*;
import com.dpi.rules.*;
import com.dpi.server.ml.FlowFeatureExtractor;
import com.dpi.server.model.AnalysisResponse;
import com.dpi.server.model.FlowReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

// main service - reads the pcap, tracks flows, scores them with AI
// basically glues the dpi engine to the spring boot api
@Service
public class DpiAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(DpiAnalysisService.class);

    private final AnomalyDetectionService anomalyService;
    private final FlowFeatureExtractor featureExtractor;
    private final RulesService rulesService;

    // running totals across all requests
    private final AtomicLong totalPackets = new AtomicLong(0);
    private final AtomicLong totalDropped = new AtomicLong(0);

    // last run's anomalies, for the GET /api/anomalies endpoint
    private volatile List<FlowReport> lastAnomalies = Collections.emptyList();

    public DpiAnalysisService(AnomalyDetectionService anomalyService,
            FlowFeatureExtractor featureExtractor,
            RulesService rulesService) {
        this.anomalyService = anomalyService;
        this.featureExtractor = featureExtractor;
        this.rulesService = rulesService;
    }

    // takes the raw pcap bytes, saves to a temp file, processes it
    public AnalysisResponse analyze(byte[] pcapBytes) throws IOException {
        long startMs = System.currentTimeMillis();
        Path tempFile = Files.createTempFile("dpi-upload-", ".pcap");
        try {
            Files.write(tempFile, pcapBytes);
            return processPcap(tempFile, startMs);
        } finally {
            Files.deleteIfExists(tempFile); // cleanup
        }
    }

    public List<FlowReport> getLastAnomalies() {
        return lastAnomalies;
    }

    public long getTotalPackets() {
        return totalPackets.get();
    }

    public long getTotalDropped() {
        return totalDropped.get();
    }

    // the actual work: read every packet, build the flow table, apply rules, then
    // AI score
    private AnalysisResponse processPcap(Path pcapPath, long startMs) throws IOException {
        Map<FiveTuple, Flow> flows = new HashMap<>();
        Map<FiveTuple, Long> flowStartTimes = new HashMap<>();
        AtomicLong dropped = new AtomicLong(0);
        AtomicLong packetCount = new AtomicLong(0);

        CompositeRuleEngine ruleEngine = rulesService.buildRuleEngine();

        try (PcapReader reader = new PcapReader(pcapPath)) {
            for (RawPacket packet : reader) {
                packetCount.incrementAndGet();
                totalPackets.incrementAndGet();

                Optional<FiveTuple> tupleOpt = extractFiveTuple(packet);
                if (tupleOpt.isEmpty())
                    continue; // not tcp/udp, skip it

                FiveTuple tuple = tupleOpt.get();
                long now = System.currentTimeMillis();

                // get the existing flow or make a new one
                Flow flow = flows.computeIfAbsent(tuple, t -> {
                    flowStartTimes.put(t, now);
                    return new Flow(t, now);
                });

                flow.addBytes(packet.length());

                // try to figure out if its http or tls
                if (!flow.isFullyParsed()) {
                    inspectPayload(packet, tuple, flow);
                }

                // already blocked? drop it and move on
                if (flow.isBlocked()) {
                    dropped.incrementAndGet();
                    totalDropped.incrementAndGet();
                    continue;
                }

                // check the block rules
                Optional<String> blockReason = ruleEngine.evaluate(flow);
                if (blockReason.isPresent()) {
                    flow.setBlocked(true, blockReason.get());
                    dropped.incrementAndGet();
                    totalDropped.incrementAndGet();
                }
            }
        }

        log.info("done: {} packets, {} flows, {} dropped", packetCount.get(), flows.size(), dropped.get());

        // now score every flow with the ML model
        List<FlowReport> reports = new ArrayList<>();
        List<FlowReport> anomalies = new ArrayList<>();

        for (Map.Entry<FiveTuple, Flow> entry : flows.entrySet()) {
            FiveTuple tuple = entry.getKey();
            Flow flow = entry.getValue();
            long flowStart = flowStartTimes.getOrDefault(tuple, startMs);

            double[] features = featureExtractor.extract(flow, flowStart);
            double score = anomalyService.score(features);
            String threat = AnomalyDetectionService.threatLevel(score);
            long scorePct = Math.round(score * 100.0);

            FlowReport report = new FlowReport(
                    intToIp(tuple.srcIp()),
                    intToIp(tuple.dstIp()),
                    tuple.srcPort(),
                    tuple.dstPort(),
                    protocolName(tuple.protocol()),
                    flow.getApplicationProtocol().orElse("UNKNOWN"),
                    flow.getSniOrHost().orElse(""),
                    flow.getPacketsTransferred(),
                    flow.getBytesTransferred(),
                    scorePct,
                    threat,
                    flow.isBlocked(),
                    flow.getBlockReason());

            reports.add(report);
            if (score > 0.55)
                anomalies.add(report);
        }

        // sort highest risk first so bad stuff is at the top
        reports.sort(Comparator.comparingLong(FlowReport::riskScore).reversed());
        lastAnomalies = List.copyOf(anomalies);

        long processingMs = System.currentTimeMillis() - startMs;
        String summary = String.format(
                "Analyzed %d flows in %dms. Detected %d anomalies, dropped %d packets.",
                reports.size(), processingMs, anomalies.size(), dropped.get());

        return new AnalysisResponse(
                reports.size(), anomalies.size(), (int) dropped.get(),
                processingMs, summary, reports);
    }

    // parses just enough to get the 5-tuple (src ip, dst ip, ports, protocol)
    private Optional<FiveTuple> extractFiveTuple(RawPacket packet) {
        ByteBuffer data = packet.data();
        data.position(0);

        Optional<EthernetParser.ParseResult> ethRes = EthernetParser.parse(data);
        if (ethRes.isEmpty() || ethRes.get().etherType() != EthernetParser.ETHERTYPE_IPV4)
            return Optional.empty();

        Optional<IPv4Parser.ParseResult> ipRes = IPv4Parser.parse(ethRes.get().payload());
        if (ipRes.isEmpty() || ipRes.get().isFragmented())
            return Optional.empty();

        int protocol = ipRes.get().protocol();
        ByteBuffer l4 = ipRes.get().payload();
        int srcPort = 0, dstPort = 0;

        if (protocol == IPv4Parser.PROTOCOL_TCP) {
            Optional<TcpParser.ParseResult> r = TcpParser.parse(l4);
            if (r.isEmpty())
                return Optional.empty();
            srcPort = r.get().srcPort();
            dstPort = r.get().dstPort();
        } else if (protocol == IPv4Parser.PROTOCOL_UDP) {
            Optional<UdpParser.ParseResult> r = UdpParser.parse(l4);
            if (r.isEmpty())
                return Optional.empty();
            srcPort = r.get().srcPort();
            dstPort = r.get().dstPort();
        } else {
            return Optional.empty(); // icmp etc, we dont care
        }

        return Optional.of(FiveTuple.createBidirectional(
                ipRes.get().srcIp(), ipRes.get().dstIp(), srcPort, dstPort, protocol));
    }

    // tries to figure out if the traffic is tls (https) or plain http
    private void inspectPayload(RawPacket packet, FiveTuple tuple, Flow flow) {
        ByteBuffer data = packet.data();
        data.position(0);

        Optional<EthernetParser.ParseResult> ethRes = EthernetParser.parse(data);
        if (ethRes.isEmpty())
            return;

        Optional<IPv4Parser.ParseResult> ipRes = IPv4Parser.parse(ethRes.get().payload());
        if (ipRes.isEmpty())
            return;

        ByteBuffer l4 = ipRes.get().payload();
        ByteBuffer appPayload = null;

        if (tuple.protocol() == IPv4Parser.PROTOCOL_TCP) {
            Optional<TcpParser.ParseResult> r = TcpParser.parse(l4);
            if (r.isPresent()) {
                appPayload = r.get().payload();
                if (r.get().fin() || r.get().rst())
                    flow.setClosed(true);
            }
        } else if (tuple.protocol() == IPv4Parser.PROTOCOL_UDP) {
            Optional<UdpParser.ParseResult> r = UdpParser.parse(l4);
            if (r.isPresent())
                appPayload = r.get().payload();
        }

        if (appPayload == null || appPayload.remaining() == 0)
            return;

        // check for tls sni first (the domain name in the handshake)
        Optional<String> sni = TlsSniExtractor.extractSni(appPayload);
        if (sni.isPresent()) {
            flow.setApplicationProtocol("TLS");
            flow.setSniOrHost(sni.get());
            flow.setFullyParsed(true);
            return;
        }

        // fallback to http host header
        appPayload.position(0);
        Optional<String> host = HttpHostExtractor.extractHost(appPayload);
        if (host.isPresent()) {
            flow.setApplicationProtocol("HTTP");
            flow.setSniOrHost(host.get());
            flow.setFullyParsed(true);
        }
    }

    // converts int ip to the normal dotted format like 192.168.1.1
    private static String intToIp(int ip) {
        return ((ip >> 24) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                (ip & 0xFF);
    }

    private static String protocolName(int protocol) {
        return switch (protocol) {
            case 6 -> "TCP";
            case 17 -> "UDP";
            case 1 -> "ICMP";
            default -> "PROTO_" + protocol;
        };
    }
}
