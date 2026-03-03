package com.dpi.metrics;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Lightweight HTTP Server to expose real-time metrics as JSON.
 * Uses the built-in Java com.sun.net.httpserver.HttpServer.
 */
public class MetricsServer {

    private final MetricsRegistry registry;
    private final int port;
    private HttpServer server;

    public MetricsServer(MetricsRegistry registry, int port) {
        this.registry = registry;
        this.port = port;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/metrics", new MetricsHandler(registry));
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(2)); // Dedicated small pool
        server.start();
        System.out.println("HTTP Metrics Server started on port " + port);
    }

    public void stop() {
        if (server != null) {
            server.stop(2); // 2 second max delay
            System.out.println("HTTP Metrics Server stopped.");
        }
    }

    private static class MetricsHandler implements HttpHandler {
        private final MetricsRegistry metrics;

        public MetricsHandler(MetricsRegistry metrics) {
            this.metrics = metrics;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                String response = buildJson();
                byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, bytes.length);

                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }

        private String buildJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            sb.append("  \"uptimeMillis\": ").append(metrics.getUptimeMillis()).append(",\n");
            sb.append("  \"packetsProcessed\": ").append(metrics.getPacketsProcessed()).append(",\n");
            sb.append("  \"packetsDropped\": ").append(metrics.getPacketsDropped()).append(",\n");
            sb.append("  \"bytesProcessed\": ").append(metrics.getBytesProcessed()).append(",\n");
            sb.append("  \"flowsBlocked\": ").append(metrics.getFlowsBlocked()).append(",\n");
            sb.append("  \"evictedFlows\": ").append(metrics.getEvictedFlows()).append(",\n");
            sb.append("  \"idsAlerts\": ").append(metrics.getIdsAlerts()).append(",\n");
            sb.append("  \"errors\": ").append(metrics.getErrors()).append(",\n");

            sb.append("  \"appUsageBytes\": {\n");
            Map<String, Long> appUsage = metrics.getAppUsageBytes();
            boolean first = true;
            for (Map.Entry<String, Long> entry : appUsage.entrySet()) {
                if (!first)
                    sb.append(",\n");
                // basic sanitization just in case for JSON formatting
                String safeKey = entry.getKey().replace("\"", "\\\"");
                sb.append("    \"").append(safeKey).append("\": ").append(entry.getValue());
                first = false;
            }
            sb.append("\n  }\n");
            sb.append("}\n");
            return sb.toString();
        }
    }
}
