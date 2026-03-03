package com.dpi.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// main class, just kicks everything off
@SpringBootApplication
public class DpiSpringApplication {

    public static void main(String[] args) {
        SpringApplication.run(DpiSpringApplication.class, args);

        // just a nice banner so we know its running
        System.out.println("""

                ╔══════════════════════════════════════════════════════════╗
                ║         DPI Spring Boot AI Server - STARTED             ║
                ║                                                          ║
                ║  REST API:   http://localhost:8080/api                   ║
                ║  Health:     http://localhost:8080/actuator/health       ║
                ║  Metrics:    http://localhost:8080/api/metrics           ║
                ║                                                          ║
                ║  AI Model:   SMILE Isolation Forest (local, no API key) ║
                ╚══════════════════════════════════════════════════════════╝
                """);
    }
}
