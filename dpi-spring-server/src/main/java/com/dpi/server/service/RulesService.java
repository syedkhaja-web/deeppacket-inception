package com.dpi.server.service;

import com.dpi.rules.*;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

// holds the list of blocked ips and domains
// you can update these at runtime through the api without restarting
@Service
public class RulesService {

    private static final Logger log = LoggerFactory.getLogger(RulesService.class);

    @Value("${dpi.rules.blocked-ips:}")
    private String defaultBlockedIps;

    @Value("${dpi.rules.blocked-domains:}")
    private String defaultBlockedDomains;

    // concurrent sets so threads don't fight over them
    private final Set<String> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<String> blockedDomains = ConcurrentHashMap.newKeySet();

    // load the defaults from application.properties on startup
    @PostConstruct
    public void init() {
        if (defaultBlockedIps != null && !defaultBlockedIps.isBlank()) {
            Arrays.stream(defaultBlockedIps.split(","))
                    .map(String::trim).filter(s -> !s.isEmpty())
                    .forEach(blockedIps::add);
        }
        if (defaultBlockedDomains != null && !defaultBlockedDomains.isBlank()) {
            Arrays.stream(defaultBlockedDomains.split(","))
                    .map(String::trim).filter(s -> !s.isEmpty())
                    .forEach(blockedDomains::add);
        }
        log.info("rules loaded: {} ips, {} domains blocked", blockedIps.size(), blockedDomains.size());
    }

    // builds a fresh rule engine from whatever is in our sets right now
    public CompositeRuleEngine buildRuleEngine() {
        CompositeRuleEngine engine = new CompositeRuleEngine();

        if (!blockedIps.isEmpty()) {
            IpBlockRule ipRule = new IpBlockRule();
            blockedIps.forEach(ipRule::addIpStr);
            engine.addRule(ipRule);
        }

        if (!blockedDomains.isEmpty()) {
            DomainBlockRule domainRule = new DomainBlockRule();
            blockedDomains.forEach(domainRule::addDomain);
            engine.addRule(domainRule);
        }

        return engine;
    }

    public boolean addIp(String ip) {
        boolean added = blockedIps.add(ip.trim());
        if (added)
            log.info("blocked ip: {}", ip);
        return added;
    }

    public boolean removeIp(String ip) {
        boolean removed = blockedIps.remove(ip.trim());
        if (removed)
            log.info("unblocked ip: {}", ip);
        return removed;
    }

    public boolean addDomain(String domain) {
        boolean added = blockedDomains.add(domain.trim().toLowerCase());
        if (added)
            log.info("blocked domain: {}", domain);
        return added;
    }

    public boolean removeDomain(String domain) {
        boolean removed = blockedDomains.remove(domain.trim().toLowerCase());
        if (removed)
            log.info("unblocked domain: {}", domain);
        return removed;
    }

    public Set<String> getBlockedIps() {
        return Collections.unmodifiableSet(blockedIps);
    }

    public Set<String> getBlockedDomains() {
        return Collections.unmodifiableSet(blockedDomains);
    }
}
