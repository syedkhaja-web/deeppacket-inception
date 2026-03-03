# Java DPI Engine Architecture

This project is a Deep Packet Inspection (DPI) engine written entirely in Java. It reads network traffic from a `.pcap` file, inspects the packets to understand the application layer (like HTTP or TLS), checks if the traffic should be blocked based on our rules, and writes the safe traffic to a new `.pcap` file.

## Core Components

### 1. Parsers
Instead of using heavy libraries, we wrote custom parsers using Java `ByteBuffer`. 
- `PcapReader` / `PcapWriter`: Reads and writes the raw bytes of the PCAP file format.
- `EthernetParser`, `IPv4Parser`, `TcpParser`, `UdpParser`: Peels back the layers of the OSI model step by step.
- `TlsSniExtractor`, `HttpHostExtractor`: Looks at the raw application payload to find domain names without converting everything to expensive Java Strings.

### 2. Flow Tracking
Network traffic isn't just random packets; it's made of connections called "Flows".
- `FiveTuple`: A unique record identifying a connection based on Source IP, Destination IP, Source Port, Destination Port, and Protocol.
- `Flow`: Stores stats like bytes transferred and the extracted domain name.
- `FlowTable`: A `ConcurrentHashMap` that safely holds all active flows across different processing threads. It CLEANS up old flows automatically so we don't run out of memory.

### 3. Rules Engine
A flexible system to block traffic. 
We can easily plug in new rules (like `DomainBlockRule` or `IpBlockRule`) into our `CompositeRuleEngine`. If any rule returns a block reason, the packet is dropped.

### 4. DpiEngine
This is the heart of the project. It uses an `ExecutorService` (a built-in Java thread pool) to process packets concurrently. 
1. The main thread reads a packet from the PCAP.
2. It submits the packet to a background worker thread.
3. The worker parses the IP and ports, tracks the Flow, and inspects the payload.
4. If it's safe, the worker synchronizes and writes the packet to the output file.

We kept it simple but highly effective!
