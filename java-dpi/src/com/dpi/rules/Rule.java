package com.dpi.rules;

import com.dpi.flow.Flow;
import java.util.Optional;

/**
 * A simple interface for any rule we want to apply to our network flows.
 */
public interface Rule {

    /**
     * Checks a flow to see if it violates this rule.
     * Returns a reason string if it should be blocked, or empty if it's fine.
     */
    Optional<String> evaluate(Flow flow);
}
