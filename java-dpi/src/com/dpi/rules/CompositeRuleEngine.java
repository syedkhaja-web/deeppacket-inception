package com.dpi.rules;

import com.dpi.flow.Flow;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Runs a flow through a list of different rules (like IP blocking, Domain
 * blocking).
 * Returns the first reason it finds for blocking, or empty if it's safe.
 */
public class CompositeRuleEngine implements Rule {

    // Keep a list of all active rules
    private final List<Rule> rules = new ArrayList<>();

    public void addRule(Rule rule) {
        rules.add(rule);
    }

    @Override
    public Optional<String> evaluate(Flow flow) {
        // Go through each rule one by one
        for (Rule rule : rules) {
            Optional<String> reason = rule.evaluate(flow);

            // If any rule says to block, we immediately return the reason
            if (reason.isPresent()) {
                return reason;
            }
        }

        // If we get here, no rules were broken! Traffic is allowed.
        return Optional.empty();
    }
}
