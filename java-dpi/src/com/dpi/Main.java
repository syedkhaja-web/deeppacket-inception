package com.dpi;

import com.dpi.engine.DpiEngine;
import com.dpi.rules.CompositeRuleEngine;
import com.dpi.rules.DomainBlockRule;
import com.dpi.rules.IpBlockRule;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Main entry point for our final year DPI Engine project.
 */
public class Main {

    public static void main(String[] args) {
        // We need an input and output PCAP file to run the tool
        if (args.length < 2) {
            System.err.println("Usage: java com.dpi.Main <input.pcap> <output.pcap>");
            System.exit(1);
        }

        Path inputPcap = Paths.get(args[0]);
        Path outputPcap = Paths.get(args[1]);

        // Use a few threads to process packets faster
        int numWorkers = 4;

        // Setup the rules for blocking traffic
        CompositeRuleEngine rules = buildRules();

        try {
            DpiEngine engine = new DpiEngine(inputPcap, outputPcap, numWorkers, rules);

            long startTime = System.currentTimeMillis();
            engine.run();
            long elapsedTime = System.currentTimeMillis() - startTime;

            System.out.printf("Done! Total Time: %.2f seconds%n", elapsedTime / 1000.0);

        } catch (Exception e) {
            System.err.println("Something went wrong:");
            e.printStackTrace();
        }
    }

    /**
     * Builds our list of blocking rules.
     */
    private static CompositeRuleEngine buildRules() {
        CompositeRuleEngine engine = new CompositeRuleEngine();

        // Block specific domains
        DomainBlockRule domainRule = new DomainBlockRule();
        domainRule.addDomain("facebook.com");
        domainRule.addDomain("malware.badguy.net");
        engine.addRule(domainRule);

        // Block specific IPs
        IpBlockRule ipRule = new IpBlockRule();
        ipRule.addIpStr("1.1.1.1");
        ipRule.addIpStr("8.8.8.8");
        engine.addRule(ipRule);

        return engine;
    }
}
