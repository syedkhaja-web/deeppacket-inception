package com.dpi.server.controller;

import com.dpi.server.model.RuleRequest;
import com.dpi.server.service.RulesService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

// manage the block rules without restarting the server
// GET  /api/rules         - see whats blocked
// POST /api/rules/ip      - block an ip
// POST /api/rules/domain  - block a domain
// DELETE versions to remove them
@RestController
@RequestMapping("/api/rules")
public class RulesController {

    private final RulesService rulesService;

    public RulesController(RulesService rulesService) {
        this.rulesService = rulesService;
    }

    // shows what IPs and domains are currently blocked
    @GetMapping
    public ResponseEntity<Map<String, Object>> getRules() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("blockedIps", rulesService.getBlockedIps());
        response.put("blockedDomains", rulesService.getBlockedDomains());
        response.put("totalIps", rulesService.getBlockedIps().size());
        response.put("totalDomains", rulesService.getBlockedDomains().size());
        return ResponseEntity.ok(response);
    }

    // curl -X POST .../api/rules/ip -H "Content-Type: application/json" -d
    // '{"value":"10.0.0.1"}'
    @PostMapping("/ip")
    public ResponseEntity<Map<String, Object>> addIp(@RequestBody RuleRequest request) {
        if (request.value() == null || request.value().isBlank())
            return ResponseEntity.badRequest().build();

        boolean added = rulesService.addIp(request.value());
        return ResponseEntity.ok(Map.of(
                "added", added,
                "ip", request.value(),
                "message", added ? "added" : "already blocked"));
    }

    @DeleteMapping("/ip")
    public ResponseEntity<Map<String, Object>> removeIp(@RequestBody RuleRequest request) {
        boolean removed = rulesService.removeIp(request.value());
        return ResponseEntity.ok(Map.of("removed", removed, "ip", request.value()));
    }

    // curl -X POST .../api/rules/domain -d '{"value":"tiktok.com"}'
    @PostMapping("/domain")
    public ResponseEntity<Map<String, Object>> addDomain(@RequestBody RuleRequest request) {
        if (request.value() == null || request.value().isBlank())
            return ResponseEntity.badRequest().build();

        boolean added = rulesService.addDomain(request.value());
        return ResponseEntity.ok(Map.of(
                "added", added,
                "domain", request.value(),
                "message", added ? "added" : "already blocked"));
    }

    @DeleteMapping("/domain")
    public ResponseEntity<Map<String, Object>> removeDomain(@RequestBody RuleRequest request) {
        boolean removed = rulesService.removeDomain(request.value());
        return ResponseEntity.ok(Map.of("removed", removed, "domain", request.value()));
    }
}
