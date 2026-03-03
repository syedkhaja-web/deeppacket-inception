package com.dpi.server.controller;

import com.dpi.server.model.MetricsResponse;
import com.dpi.server.service.AnomalyDetectionService;
import com.dpi.server.service.DpiAnalysisService;
import com.dpi.server.service.RulesService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

// just shows whats going on - packet counts, how many anomalies, model status etc
// curl http://localhost:8080/api/metrics
@RestController
@RequestMapping("/api/metrics")
public class MetricsController {

    private final DpiAnalysisService dpiService;
    private final AnomalyDetectionService anomalyService;
    private final RulesService rulesService;

    public MetricsController(DpiAnalysisService dpiService,
            AnomalyDetectionService anomalyService,
            RulesService rulesService) {
        this.dpiService = dpiService;
        this.anomalyService = anomalyService;
        this.rulesService = rulesService;
    }

    @GetMapping
    public ResponseEntity<MetricsResponse> getMetrics() {
        MetricsResponse metrics = new MetricsResponse(
                dpiService.getTotalPackets(),
                dpiService.getTotalDropped(),
                anomalyService.getAnomalyCount(),
                rulesService.getBlockedIps().size(),
                rulesService.getBlockedDomains().size(),
                rulesService.getBlockedIps(),
                rulesService.getBlockedDomains(),
                anomalyService.getModelStatus());
        return ResponseEntity.ok(metrics);
    }
}
