package com.dpi.server.controller;

import com.dpi.server.model.AnalysisResponse;
import com.dpi.server.service.DpiAnalysisService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

// upload a pcap here and get back the analysis
// POST /api/analyze with a multipart file
@RestController
@RequestMapping("/api/analyze")
public class AnalysisController {

    private final DpiAnalysisService dpiService;

    public AnalysisController(DpiAnalysisService dpiService) {
        this.dpiService = dpiService;
    }

    // curl -X POST http://localhost:8080/api/analyze -F "file=@input.pcap"
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<AnalysisResponse> analyze(
            @RequestParam("file") MultipartFile file) {

        if (file.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        try {
            byte[] pcapBytes = file.getBytes();
            AnalysisResponse response = dpiService.analyze(pcapBytes);
            return ResponseEntity.ok(response);
        } catch (IOException e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}
