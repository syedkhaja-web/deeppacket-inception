package com.dpi.server.controller;

import com.dpi.server.model.FlowReport;
import com.dpi.server.service.DpiAnalysisService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// returns the flows that the ML model flagged as sus
// only useful after you've done a POST /api/analyze first
@RestController
@RequestMapping("/api/anomalies")
public class AnomalyController {

    private final DpiAnalysisService dpiService;

    public AnomalyController(DpiAnalysisService dpiService) {
        this.dpiService = dpiService;
    }

    // get all flagged flows (score > 55%)
    @GetMapping
    public ResponseEntity<List<FlowReport>> getAnomalies() {
        return ResponseEntity.ok(dpiService.getLastAnomalies());
    }

    // only the really bad ones (score >= 85%)
    @GetMapping("/critical")
    public ResponseEntity<List<FlowReport>> getCritical() {
        List<FlowReport> critical = dpiService.getLastAnomalies().stream()
                .filter(f -> "CRITICAL".equals(f.threatLevel()))
                .toList();
        return ResponseEntity.ok(critical);
    }

    // quick summary of how many of each threat level we found
    @GetMapping("/summary")
    public ResponseEntity<?> getSummary() {
        List<FlowReport> anomalies = dpiService.getLastAnomalies();
        long critical = anomalies.stream().filter(f -> "CRITICAL".equals(f.threatLevel())).count();
        long malicious = anomalies.stream().filter(f -> "MALICIOUS".equals(f.threatLevel())).count();
        long suspicious = anomalies.stream().filter(f -> "SUSPICIOUS".equals(f.threatLevel())).count();

        return ResponseEntity.ok(new java.util.LinkedHashMap<String, Object>() {
            {
                put("total", anomalies.size());
                put("critical", critical);
                put("malicious", malicious);
                put("suspicious", suspicious);
            }
        });
    }
}
