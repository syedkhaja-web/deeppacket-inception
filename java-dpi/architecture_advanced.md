# Advanced Features Architecture Explanation

This document covers the advanced enterprise-level features added to the Java DPI Engine. The core philosophy remains: **Zero lock contention on the critical path, minimal memory allocation, and high-performance flow affinity.**

## 1. Flow Timeout & Lifecycle Management
Memory leaks are a primary concern for long-running DPI nodes handling millions of ephemeral flows.
- **TCP FIN/RST Tracking:** The `Worker` thread inspects the parsed TCP flags for every packet. If `FIN` or `RST` is detected, `flow.markClosed()` is called. 
- **Stale Eviction:** `FlowTable.evictStaleFlows()` is periodically called by the `Worker` thread. It walks the internal subset `HashMap` and cleanly removes flows that are marked closed OR have exceeded the idle timeout limit.
- **Why it’s fast:** The eviction runs directly on the `Worker` thread locally. There is NO pausing of global traffic, and NO global synchronization maps to lock. 

## 2. Bandwidth Analytics & HTTP Metrics
To track application usage (e.g., total bytes consumed by `TLS`, `HTTP`, or `YouTube`), we updated the `MetricsRegistry`.
- **Per-App Stats:** Handled via a `ConcurrentHashMap<String, LongAdder>`. Because strings like "TLS" act as the key, multiple workers might update "TLS" simultaneously. `LongAdder` completely prevents CPU cache line bouncing here.
- **HTTP Server:** We utilized the lightweight `com.sun.net.httpserver.HttpServer` built into the JVM. It runs on a dedicated tiny thread pool (2 threads) on port 8080 and asynchronously queries the `MetricsRegistry` `.sum()` methods.
- **Why it's fast:** The HTTP server never interacts with the `Worker` queues or the `FlowTable`. It strictly reads `LongAdders`, achieving true separation of concerns.

## 3. Token Bucket Rate Limiting
Rate limiting often becomes a massive bottleneck if implemented globally. We implemented it at the Flow level.
- **The Engine:** `TokenBucket.java` uses integer-based math to compute elapsed time versus byte accumulation. It does not use background threads to "refill" the bucket; instead, it retroactively computes the refill exactly at the moment a packet arrives: `refill(currentTimestampNanos)`.
- **Thread Safety:** 100% Lock-free. Because of flow affinity, the `Worker` thread is the only thread that ever mutates a particular Flow's `TokenBucket`. We use `long` primitives instead of `AtomicLong` natively.

## 4. Intrusion Detection System (IDS)
The `PayloadInspector` class was added to scan packet payloads for known malicious byte signatures.
- **The Parsing:** The scanner operates directly on the `ByteBuffer` using `payload.get(index)`. This avoids allocating `byte[]` arrays or converting the payload to a `String` (which would trigger JVM charset decoders and heavy heap allocation).
- **The Action:** Currently configured as an alert-only mechanism (`ids_alerts` metric in the JSON endpoint), fulfilling enterprise requirements for passive auditing.

## 5. Graceful Shutdown & Backpressure
- **Backpressure:** The `Worker` threads employ a `LinkedBlockingQueue` bounded to `65536` elements. If workers cannot keep up with the Reader thread, `queue.put()` will inherently block the Reader, providing organic JVM-level backpressure.
- **Shutdown Hooks:** A `Runtime` shutdown hook captures `Ctrl+C` inputs, cleanly stopping the TCP reader, allowing the bounded queues to fully drain over a 2-minute window before the JVM exits, ensuring no data loss in transit. 
