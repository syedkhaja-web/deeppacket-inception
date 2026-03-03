package com.dpi.rules;

import com.dpi.flow.Flow;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Blocks flow based on identified application protocol (e.g., "TLS", "HTTP").
 */
public class AppBlockRule implements Rule {

    private final Set<String> blockedApps = new HashSet<>();

    public void addApp(String app) {
        blockedApps.add(app.toLowerCase());
    }

    @Override
    public Optional<String> evaluate(Flow flow) {
        Optional<String> app = flow.getApplicationProtocol();
        if (app.isPresent() && blockedApps.contains(app.get().toLowerCase())) {
            return Optional.of("APP_BLOCKED_" + app.get().toUpperCase());
        }
        return Optional.empty();
    }
}
