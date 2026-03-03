"""
Demo PCAP Generator for DPI Engine
====================================
This script creates a fake network capture file (PCAP) that contains
a mix of normal traffic and traffic aimed at blocked domains/IPs.

Run it with:  python generate_demo_pcap.py
Then feed it to the engine:  java -cp out com.dpi.Main demo.pcap clean.pcap
"""

import struct
import socket
import random

# ─── PCAP File Format Constants ──────────────────────────────────────────────
PCAP_MAGIC       = 0xA1B2C3D4  # Standard PCAP magic (big-endian timestamps)
PCAP_VERSION_MAJ = 2
PCAP_VERSION_MIN = 4
PCAP_SNAPLEN     = 65535
PCAP_LINKTYPE    = 1  # Ethernet

# ─── Helper: Build Raw Ethernet + IPv4 + TCP + HTTP Packet ───────────────────
def build_http_packet(src_ip, dst_ip, src_port, dst_port, http_host):
    """Creates a raw HTTP GET request packet targeting a specific Host header."""

    http_payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {http_host}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")

    # TCP Header (20 bytes, no options)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,       # Source port
        dst_port,       # Destination port
        1000,           # Sequence number
        0,              # Ack number
        (5 << 4),       # Data offset (5 * 4 = 20 bytes) + reserved
        0x18,           # Flags: PSH + ACK
        65535,          # Window size
        0,              # Checksum (skipped for pcap replay)
        0               # Urgent pointer
    )

    # IPv4 Header (20 bytes)
    total_length = 20 + len(tcp_header) + len(http_payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,                           # Version (4) + IHL (5)
        0,                              # DSCP/ECN
        total_length,                   # Total length
        random.randint(1, 65535),       # Identification
        0x4000,                         # Flags: Don't fragment
        64,                             # TTL
        6,                              # Protocol: TCP
        0,                              # Checksum (skipped)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )

    # Ethernet Header (14 bytes)
    eth_header = struct.pack(
        "!6s6sH",
        bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]),  # Destination MAC
        bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x01]),  # Source MAC
        0x0800  # EtherType: IPv4
    )

    return eth_header + ip_header + tcp_header + http_payload


# ─── Helper: Write a Packet to the PCAP File ─────────────────────────────────
def write_packet(file, timestamp_sec, packet_data):
    """Writes a single packet with its 16-byte PCAP header."""
    inc_len = len(packet_data)
    orig_len = inc_len
    # Packet record header: ts_sec, ts_usec, incl_len, orig_len
    file.write(struct.pack("<IIII", timestamp_sec, 0, inc_len, orig_len))
    file.write(packet_data)


# ─── Main Script ─────────────────────────────────────────────────────────────
def generate(output_file="demo.pcap"):
    packets = [
        # (description, src_ip, dst_ip, src_port, dst_port, http_host)
        # --- These should be PASSED (not in block list) ---
        ("Normal - Google",    "192.168.1.10", "142.250.80.46",  54321, 80, "google.com"),
        ("Normal - GitHub",    "192.168.1.10", "140.82.112.4",   54322, 80, "github.com"),
        ("Normal - Wikipedia", "192.168.1.10", "198.35.26.96",   54323, 80, "en.wikipedia.org"),

        # --- These should be BLOCKED (matching block rules in Main.java) ---
        ("BLOCKED - Facebook",  "192.168.1.10", "157.240.229.35", 54324, 80, "facebook.com"),
        ("BLOCKED - Malware",   "192.168.1.10", "203.0.113.99",   54325, 80, "malware.badguy.net"),

        # --- Repeat flow (same connection returning more data) ---
        ("Normal - Google (2nd packet)", "192.168.1.10", "142.250.80.46", 54321, 80, "google.com"),
        ("BLOCKED - Facebook (2nd pkt)", "192.168.1.10", "157.240.229.35", 54324, 80, "facebook.com"),
    ]

    with open(output_file, "wb") as f:
        # Write PCAP global header
        f.write(struct.pack(
            "<IHHiIII",
            PCAP_MAGIC, PCAP_VERSION_MAJ, PCAP_VERSION_MIN,
            0,           # Timezone (UTC)
            0,           # Timestamp accuracy
            PCAP_SNAPLEN,
            PCAP_LINKTYPE
        ))

        base_time = 1740000000  # Some fake Unix timestamp
        for i, (desc, src, dst, sport, dport, host) in enumerate(packets):
            pkt = build_http_packet(src, dst, sport, dport, host)
            write_packet(f, base_time + i, pkt)
            print(f"  [{i+1}] {desc}")

    print(f"\nGenerated: {output_file} with {len(packets)} packets")
    print("\nNow run the engine:")
    print("  java -cp out com.dpi.Main demo.pcap clean.pcap")
    print("\nExpected result:")
    print("  - 4 packets PASSED (Google, GitHub, Wikipedia, Google repeat)")
    print("  - 3 packets DROPPED (Facebook x2, malware.badguy.net)")


if __name__ == "__main__":
    generate()
