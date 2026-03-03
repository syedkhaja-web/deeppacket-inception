package com.dpi.rules;

import com.dpi.flow.Flow;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Blocks traffic going to specific domains.
 * It checks the extracted SNI (from HTTPS) or Host header (from HTTP).
 */
public class DomainBlockRule implements Rule {

    // HashSet gives us fast lookups for domain names
    private final Set<String> blockedDomains = new HashSet<>();

    public void addDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
    }

    @Override
    public Optional<String> evaluate(Flow flow) {
        Optional<String> sniOrHost = flow.getSniOrHost();

        if (sniOrHost.isPresent()) {
            String domain = sniOrHost.get().toLowerCase();

            // Direct exact match
            if (blockedDomains.contains(domain)) {
                return Optional.of("Domain block: " + domain);
            }

            // Check if it's a subdomain (e.g. "www.badguy.net" should match "badguy.net")
            for (String blocked : blockedDomains) {
                if (domain.endsWith("." + blocked)) {
                    return Optional.of("Domain block (subdomain): " + blocked);
                }
            }
        }

        return Optional.empty();
    }
}
