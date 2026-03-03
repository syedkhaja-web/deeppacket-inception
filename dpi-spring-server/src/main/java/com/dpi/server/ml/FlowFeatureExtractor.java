package com.dpi.server.ml;

import com.dpi.flow.Flow;
import org.springframework.stereotype.Component;

// pulls numbers out of a flow so the ML model can score it
// all values get squished to 0.0-1.0 range
@Component
public class FlowFeatureExtractor {

    public static final int FEATURE_COUNT = 7;

    // give it a flow and when it started, get back a 7-number array
    public double[] extract(Flow flow, long startTime) {
        long durationMs = Math.max(1L, flow.getLastSeenTime() - startTime);
        double durationSec = durationMs / 1000.0;

        long packets = flow.getPacketsTransferred();
        long bytes = flow.getBytesTransferred();

        double packetsPerSec = packets / durationSec;
        double bytesPerSec = bytes / durationSec;

        int dstPort = flow.getFiveTuple().dstPort();
        int protocol = flow.getFiveTuple().protocol();

        String appProto = flow.getApplicationProtocol().orElse("");

        double isTls = "TLS".equalsIgnoreCase(appProto) ? 1.0 : 0.0;
        double isHttp = "HTTP".equalsIgnoreCase(appProto) ? 1.0 : 0.0;

        return new double[] {
                Math.min(packetsPerSec / 10_000.0, 1.0), // packets per sec, capped
                Math.min(bytesPerSec / 1_000_000.0, 1.0), // bytes per sec, capped
                dstPort / 65535.0, // dest port
                protocol / 17.0, // TCP or UDP basically
                isTls, // is it https?
                isHttp, // is it plain http?
                Math.min(durationMs / 60_000.0, 1.0) // how long did it last
        };
    }
}
