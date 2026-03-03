# Java DPI Engine Architecture

This document explains the core design decisions made to achieve a high-performance, enterprise-grade DPI engine in pure Java natively without using JNI or third-party wrappers like `Pcap4J`.

## 1. Zero-Copy I/O Layer
Standard `java.io` requires copying bytes from the kernel space to JVM heap arrays. At line-rate speeds, this causes massive Garbage Collection (GC) pauses.
- **Solution:** `java.nio.channels.FileChannel.map()` is used.
- **How it works:** `PcapReader` maps the PCAP file directly into virtual memory (`MappedByteBuffer`).
- **Result:** `RawPacket` objects hold a `.slice()` of this buffer. No `byte[]` allocation occurs for packet data during the critical reading path.

## 2. Multi-Threading & Concurrency Model
A single thread cannot inspect 10Gbps+ traffic.
- **Reader Thread:** One thread rapidly reads the memory-mapped PCAP, identifies the packet boundaries, and extracts only the L3/L4 `FiveTuple`.
- **Dispatcher:** Takes the `FiveTuple`, computes a consistent hash, and applies a modulo operation to select a target `Worker`.
- **Worker Threads:** A fixed thread pool processes flows.
- **Flow Affinity:** Because `hash(FiveTuple) % NUM_WORKERS` is deterministic, packets for the same TCP connection always go to the *same* worker thread.
- **Result:** **Zero Locks**. The `FlowTable` inside each `Worker` does not need to be a `ConcurrentHashMap`. It is a standard `HashMap` because only one thread ever accesses it. This drastically reduces CPU cache invalidations and lock contention.

## 3. Byte Allocation and Protocol Parsing
Object creation per-packet is the enemy of Java performance.
- Protocol parsers (`EthernetParser`, `IPv4Parser`, `TcpParser`) take a `ByteBuffer`.
- Instead of allocating new arrays or objects for headers, they read primitive types directly `buffer.getInt(offset)`.
- When passing the payload to the next layer, they use `buffer.slice()`, creating a new view without copying underlying bytes.

## 4. TLS SNI and HTTP Host Extraction
Extracting strings from payloads is risky because malformed packets can cause `IndexOutOfBoundsException` or buffer overflows.
- **TLS SNI:** `TlsSniExtractor` painstakingly walks the TLS Client Hello structure: Record Layer -> Handshake Layer -> Session ID -> Cipher Suites -> Extensions -> Server Name Indication. Every length marker is bounds-checked against `payload.limit()`.
- **HTTP Host:** `HttpHostExtractor` bypasses standard heavy string creation. It performs a raw byte comparison looking for `H-o-s-t-:- ` in the first few kilobytes of the TCP frame.
- **Result:** Fast fail, preventing CPU starvation attacks on the regex/parser engine.

## 5. Flow State and Blocking
A DPI engine should not inspect *every* packet of a long-lived video stream or file download.
- **Early Classification:** Once a flow is marked as `fullyParsed` (e.g., SNI extracted) or `isBlocked() == true`, deep inspection stops.
- Subsequent packets hitting the worker immediately check `flow.isBlocked()`. If true, they are dropped (`packetWriter` is not called) and metrics are updated.
- **Result:** O(1) processing time for middle and end-of-flow packets.

## 6. Metrics Design
- Using `AtomicLong` under heavy contention (e.g., 8 workers updating `packetsProcessed`) causes CPU cache line bouncing.
- **Solution:** `LongAdder` is used in `MetricsRegistry`. It maintains an array of counters to absorb concurrent updates locally per-thread, summarizing only when `.sum()` is called by the `MetricsReporterThread`.
