# Java DPI Engine - Deep Packet Inspection System

This document explains **everything** about this Java-based Deep Packet Inspection (DPI) project - from basic networking concepts to the complete enterprise-grade Java architecture designed for maximum performance without native libraries.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet](#5-the-journey-of-a-packet)
6. [High-Performance Concurrency Model](#6-high-performance-concurrency-model)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Spring Boot + AI Extension](#12-spring-boot--ai-extension)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [Java DPI Engine] → Filtered Traffic (PCAP)
                               ↓
                        - Identifies apps (HTTPS, HTTP, etc.)
                        - Extracts SNI/Hostnames safely
                        - Blocks based on rule chains
                        - Generates metrics and reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP (17) |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection.
- If we block one packet of a connection, we must block all future packets from that flow to securely enforce the rules.

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:
1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────────────┐     ┌─────────────┐
│ Wireshark   │     │ Java DPI Engine     │     │ Output      │
│ Capture     │ ──► │                     │ ──► │ PCAP        │
│ (input.pcap)│     │ - Mmap Zero-Copy    │     │ (filtered)  │
└─────────────┘     │ - Hash Dispatching  │     └─────────────┘
                    │ - Rule Evaluation   │
                    └─────────────────────┘
```

This project focuses on executing DPI at **line rate** in a pure Java 17+ environment. Instead of utilizing JNI or `libpcap` wrappers (which suffer from JNI boundaries and object allocation penalties), this engine uses Memory-Mapped Files (`java.nio.channels.FileChannel`) to map the entire traffic capture directly into the JVM process. 

---

## 4. File Structure

```
java-dpi/
├── src/com/dpi/
│   ├── Main.java               # Engine entry point and rule setup
│   ├── concurrent/             # Threading Model
│   │   ├── Dispatcher.java     # Hashes 5-tuple and assigns to workers
│   │   └── Worker.java         # Independent processing thread
│   ├── engine/                 # Core logic
│   │   └── DpiEngine.java      # Pipeline assembly
│   ├── flow/                   # Connection Tracking
│   │   ├── FiveTuple.java      # Immutable flow identifier
│   │   ├── Flow.java           # Mutable flow state
│   │   └── FlowTable.java      # Segmented flow cache
│   ├── inspect/                # L7 DPI Extractor
│   │   ├── HttpHostExtractor.java 
│   │   └── TlsSniExtractor.java   
│   ├── io/                     # Zero-Copy I/O
│   │   ├── PcapReader.java     # Memory mapped buffers
│   │   ├── PcapWriter.java     # Fast file appender
│   │   └── RawPacket.java      # Buffer Slices
│   ├── metrics/                # Performance Telemetry
│   │   ├── MetricsRegistry.java 
│   │   └── MetricsReporterThread.java
│   ├── parser/                 # L2/L3/L4 Parsing
│   │   ├── EthernetParser.java
│   │   ├── IPv4Parser.java
│   │   ├── TcpParser.java
│   │   └── UdpParser.java
│   └── rules/                  # Execution Rules Layer
│       ├── Rule.java
│       ├── CompositeRuleEngine.java
│       ├── AppBlockRule.java
│       ├── DomainBlockRule.java
│       └── IpBlockRule.java
│
├── build.md                    # Instructions to build & run
├── architecture_explanation.md # Deep dive into JVM performance techniques
└── README.md                   # This file!
```

---

## 5. The Journey of a Packet

Here's how a typical packet is handled from disk to DPI engine to disk:

1. **Zero-Copy Reading (`PcapReader`)**: The `PcapReader` utilizes `FileChannel.map` to load the entire PCAP into memory. For each packet, it creates a lightweight `RawPacket` object consisting only of metadata and a `ByteBuffer.slice()` view. **No packet bytes are copied to standard Java arrays.**
2. **Superficial Tuple Extraction (`DpiEngine`)**: The main reader thread lightly touches the Ethernet/IP/Transport boundaries to extract the `FiveTuple`.
3. **Dispatching (`Dispatcher`)**: A mathematical hash of the `FiveTuple` is computed. A modulo operation maps this flow deterministically to a specific `Worker` thread. This concept is called **Flow Affinity**.
4. **Queueing**: The packet is pushed onto an intermediate bounded `LinkedBlockingQueue` for that worker to protect against severe memory inflation.
5. **DPI Inspection (`Inspector/Rules`)**: In isolation from the rest of the threads, the `Worker` pops the packet, deeply parses the TCP/UDP data to find HTTP/TLS boundaries, and extracts domain identifiers.
6. **Writing (`PcapWriter`)**: Packets that survive all `Rule` checks are handed sequentially to a fast-buffered `PcapWriter` channel.

---

## 6. High-Performance Concurrency Model

### Thread Architecture
```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 4      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  Worker 0 Q     │           │  Worker 1 Q     │
    └────────┬────────┘           └────────┬────────┘
             │                             │
    ┌─────────────────┐           ┌─────────────────┐
    │ Worker 0 Thread │           │ Worker 1 Thread │
    │ (FlowTable 0)   │           │ (FlowTable 1)   │
    └────────┬────────┘           └────────┬────────┘
             │                             │
    ┌────────┴─────────────────────────────┴────────┐
    │              Output Callback                  │
    └────────┬──────────────────────────────────────┘
             │
             ▼
    ┌─────────────────┐
    │  PcapWriter     │
    └─────────────────┘
```

#### Why are there no `ConcurrentHashMap`s in the `Worker`?
Because of **Flow Affinity** (deterministic hashing), all packets that belong to `Protocol 6, Port 443, Src 192.168.1.10 -> Dst 8.8.8.8` will always hash to the same value and invariably land in the same `Worker`. This guarantees that multiple threads will never write to the same flow concurrently. Therefore, our standard `FlowTable` internally uses a fast, thread-unsafe `HashMap` to completely bypass cache-line bouncing and lock contention penalties. 

---

## 7. Deep Dive: Each Component

### `PcapReader` (Package: `io`)
```java
// Simplified mapped buffer slice extraction
int oldLimit = mappedBuffer.limit();
mappedBuffer.limit(mappedBuffer.position() + inclLen);
ByteBuffer packetData = mappedBuffer.slice();
// Zero copy!
```

### `Parsers` (Package: `parser`)
We avoid creating wrapper objects for headers. The `ByteBuffer` continues to be shifted recursively through parsers (`Ethernet` -> `IP` -> `TCP`) without allocating a new buffer:
```java
// Example TCP Slice
int oldLimit = tcpData.limit();
tcpData.position(startPos + headerLength);
ByteBuffer payload = tcpData.slice(); // Passed to DPI Layer
```

### `MetricsRegistry` (Package: `metrics`)
Multi-threaded architectures often suffer from CPU cache synchronization (False Sharing) when tracking metrics like `totalPackets`. The solution? `LongAdder` tracking:
```java
private final LongAdder packetsProcessed = new LongAdder();
```
`LongAdder` maintains arrays of counters inside standard `java.util.concurrent` to absorb massive concurrent inputs without causing blocking operations across CPU cores.

---

## 8. How SNI Extraction Works

Extracting the Server Name Indication (SNI) string from a TLS connection correctly in Java requires delicate buffer handling to prevent `IndexOutOfBoundsException` failures.

**The Strategy (`TlsSniExtractor.java`)**:
1. Check `Record Header` for Type `22` (Handshake).
2. Check `Handshake Layer` for Type `1` (Client Hello).
3. Safely skip Random bytes, Session Identifiers, and Cipher Suites.
4. Reach the TLS Extensions array and scan sequentially for an `Extension Type` equal to `0` (Server Name).
5. Fast-capture the variable-length hostname utilizing minimal String allocation.

---

## 9. How Blocking Works

Blocking packets follows a "fail-fast" pipeline nested inside the `Worker` thread.

### Rule Hierarchy
| Rule Type | Role | Implementation |
|-----------|---------|----------------|
| **IP Rules** | Blocks matching origins/destinations | `IpBlockRule.java`
| **App Rules** | Blocks identified applications (e.g. `TLS`) | `AppBlockRule.java`
| **Domain Rules** | Matches precise and suffix-based domains | `DomainBlockRule.java`

We execute these at the Flow-level:
1. First packet (TCP SYN) occurs. The DPI engine does not know the App or Domain yet. It is allowed to pass.
2. Second/Third packet occur (SYN-ACK, ACK). Allowed to pass.
3. Fourth packet (Client Hello) occurs. DPI Engine parses and flags the flow. `domain = "facebook.com"`.
4. The `DomainBlockRule` intercepts the `Flow` object and marks the `flow.blocked = true`.
5. The Fourth packet is immediately **dropped**.
6. Every single packet associated with this flow mapping moving forward executes an `if (flow.isBlocked())` in exactly **O(1) time complexity** and drops early without triggering further inspection. Connection naturally hangs/fails for the client. 

---

## 10. Building and Running

This system boasts ZERO external library dependencies—leveraging pure Java internals. 
Requires **JDK 17** or above.

```bash
# Compilation (Inside src directory)
cd src
dir /s /b *.java > sources.txt
javac @sources.txt

# Execution
java com.dpi.Main "C:\path\to\input.pcap" "C:\path\to\output.pcap"
```

*For more extensive build options, refer to the included `build.md`.*

---

## 11. Understanding the Output

Expected terminal console outputs during execution:

```
Starting DPI Engine...
Input: C:\captures\input.pcap
Output: C:\captures\output_filtered.pcap
Workers: 8
Starting Metrics Reporter...
[Metrics] Metrics: [pkts=154230, drops=2340, bytes=123040123, block_flows=42, evict=0, errs=0] | Rate: 154230 pps, 984.32 Mbps
Finished reading PCAP. Waiting for workers to finish...
Final Metrics: [pkts=250000, drops=5000, bytes=200000000, block_flows=80, evict=0, errs=0]
DPI Engine processing complete.
Total Execution Time: 1.54 seconds
```

**Key Definitions**:
* **pkts**: The raw number of packets traversed from top to bottom.
* **drops**: Target blocked packets stripped from the output file.
* **block_flows**: Established sessions marked as terminated by our Rules engine.
* **pps**: Packets Per Second (velocity measurement).
* **Mbps**: Megabits Per Second processed.

---

### Questions?
Check `architecture_explanation.md` for a deeper dive into the specific JVM optimization techniques implemented, or poke around the `com.dpi` project directly. Happy inspecting! 🚀

---

## 12. Spring Boot + AI Extension

This project includes a **Spring Boot REST API server** with a **local AI anomaly detection engine** built on the SMILE Isolation Forest model. No cloud API keys are needed — all intelligence runs on your machine.

### Project Structure

```
deeppacket-inception/
├── java-dpi/                  ← Original DPI engine (unchanged)
├── dpi-spring-server/         ← NEW: Spring Boot AI server
│   ├── pom.xml                # Maven build (Spring Boot 3.2 + SMILE 3.0)
│   ├── Dockerfile             # Container build (multi-stage)
│   └── src/main/java/com/dpi/server/
│       ├── DpiSpringApplication.java   # Entry point
│       ├── controller/                 # REST endpoints
│       ├── service/                    # Business logic
│       ├── ml/                         # AI feature extraction
│       └── model/                      # Response DTOs
├── Dockerfile                 ← Root Docker build
├── docker-compose.yml         ← One-command deployment
└── .github/workflows/build.yml ← CI/CD pipeline
```

### REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | Upload a PCAP → get AI threat report |
| `GET` | `/api/anomalies` | List ML-flagged flows from last analysis |
| `GET` | `/api/anomalies/critical` | Only CRITICAL (score ≥ 85%) flows |
| `GET` | `/api/anomalies/summary` | Count by threat level |
| `GET` | `/api/rules` | View current block rules |
| `POST` | `/api/rules/ip` | Add IP block rule |
| `DELETE` | `/api/rules/ip` | Remove IP block rule |
| `POST` | `/api/rules/domain` | Add domain block rule |
| `DELETE` | `/api/rules/domain` | Remove domain block rule |
| `GET` | `/api/metrics` | Engine stats + ML model status |
| `GET` | `/actuator/health` | Health check |

### How the AI Works

```
PCAP Upload
    ↓
[DPI Engine] → extracts 7 features per flow:
  • packetsPerSec  • bytesPerSec  • dstPort
  • protocol       • isTls        • isHttp
  • flowDuration
    ↓
[SMILE IsolationForest] → anomaly score (0–100%)
    ↓
Risk Level: NORMAL | SUSPICIOUS | MALICIOUS | CRITICAL
```

The Isolation Forest model is trained at startup on **synthetic normal traffic profiles** (HTTP, HTTPS, DNS, SSH). Flows that deviate significantly from this baseline receive a high risk score.

### Building and Running

```bash
# From the dpi-spring-server directory
cd dpi-spring-server
mvn clean package -DskipTests
java -jar target/dpi-spring-server-1.0.0.jar
```

Then test:
```bash
# Analyze a PCAP file
curl -X POST http://localhost:8080/api/analyze -F "file=@demo.pcap"

# View metrics
curl http://localhost:8080/api/metrics

# Add a new block rule
curl -X POST http://localhost:8080/api/rules/domain \
     -H "Content-Type: application/json" \
     -d '{"value": "tiktok.com"}'
```

### Docker Deployment (One Command)

```bash
# From the project root (deeppacket-inception/)
docker-compose up --build
```

Server will be live at `http://localhost:8080`. 🚀
