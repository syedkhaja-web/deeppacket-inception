package com.dpi.server.service;

import com.dpi.server.ml.FlowFeatureExtractor;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import smile.anomaly.IsolationForest;

import java.util.Properties;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

// this is the AI part - uses SMILE isolation forest to spot weird traffic
// no internet needed, trains itself at startup on fake normal traffic
@Service
public class AnomalyDetectionService {

    private static final Logger log = LoggerFactory.getLogger(AnomalyDetectionService.class);

    @Value("${dpi.ml.anomaly-threshold:0.55}")
    private double anomalyThreshold;

    @Value("${dpi.ml.isolation-forest-trees:200}")
    private int isolationForestTrees;

    @Value("${dpi.ml.training-samples:1000}")
    private int trainingSamples;

    private IsolationForest model;
    private final AtomicLong anomalyCount = new AtomicLong(0);

    // trains on startup with made-up normal traffic so it knows what normal looks
    // like
    @PostConstruct
    public void init() {
        log.info("training isolation forest with {} trees on {} samples...", isolationForestTrees, trainingSamples);
        double[][] normalData = generateNormalTrainingData(trainingSamples);
        // SMILE 3.x IsolationForest.fit takes (data, Properties)
        Properties props = new Properties();
        props.setProperty("smile.isolation.forest.ntrees", String.valueOf(isolationForestTrees));
        props.setProperty("smile.isolation.forest.max.samples", "256");
        try {
            model = IsolationForest.fit(normalData, props);
            log.info("model ready. threshold = {}", anomalyThreshold);
        } catch (Exception e) {
            log.error("failed to init isolation forest: {}", e.getMessage());
        }
    }

    // returns 0-1, higher = more sus
    public double score(double[] features) {
        if (model == null)
            return 0.0;
        return model.score(features);
    }

    // returns true if the flow looks weird
    public boolean isAnomaly(double[] features) {
        double s = score(features);
        if (s > anomalyThreshold) {
            anomalyCount.incrementAndGet();
            return true;
        }
        return false;
    }

    public long getAnomalyCount() {
        return anomalyCount.get();
    }

    public String getModelStatus() {
        return model != null ? "READY (trees=" + isolationForestTrees + ")" : "NOT INITIALIZED";
    }

    // converts the score to a human friendly label
    public static String threatLevel(double score) {
        if (score >= 0.85)
            return "CRITICAL";
        if (score >= 0.70)
            return "MALICIOUS";
        if (score >= 0.55)
            return "SUSPICIOUS";
        return "NORMAL";
    }

    // makes up 1000 normal-looking flows to train on
    // covers http, https, dns, ssh which is basically what normal traffic is
    private double[][] generateNormalTrainingData(int n) {
        double[][] data = new double[n][FlowFeatureExtractor.FEATURE_COUNT];
        Random rng = new Random(42); // fixed seed so it's consistent

        double[] normalPorts = { 443, 80, 53, 22, 8080, 25, 443, 443 }; // 443 shows up more since most traffic is https
        boolean[] normalTls = { true, false, false, false, false, false, true, true };
        boolean[] normalHttp = { false, true, false, false, true, false, false, false };

        for (int i = 0; i < n; i++) {
            int idx = (int) (rng.nextDouble() * normalPorts.length);

            // normal pps is low, like 1-200
            data[i][0] = Math.min((1.0 + rng.nextDouble() * 199) / 10_000.0, 1.0);
            // normal bandwidth is also pretty low
            data[i][1] = Math.min((100.0 + rng.nextDouble() * 499_900) / 1_000_000.0, 1.0);
            data[i][2] = normalPorts[idx] / 65535.0;
            // mostly tcp
            data[i][3] = (rng.nextDouble() < 0.8) ? (6.0 / 17.0) : 1.0;
            data[i][4] = normalTls[idx] ? 1.0 : 0.0;
            data[i][5] = normalHttp[idx] ? 1.0 : 0.0;
            // flows dont usually last more than 30 seconds
            data[i][6] = Math.min((0.1 + rng.nextDouble() * 30.0) / 60.0, 1.0);
        }
        return data;
    }
}
