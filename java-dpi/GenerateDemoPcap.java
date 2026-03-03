import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Generates a demo PCAP file with a mix of normal and blocked HTTP traffic.
 * Run: java -cp out GenerateDemoPcap
 * Then: java -cp out com.dpi.Main demo.pcap clean.pcap
 */
public class GenerateDemoPcap {

    public static void main(String[] args) throws IOException {
        String outputFile = "demo.pcap";

        // All the packets we want to generate
        // Format: { src_ip, dst_ip, src_port, dst_port, http_host }
        String[][] packets = {
                { "192.168.1.10", "142.250.80.46", "54321", "80", "google.com" }, // PASS
                { "192.168.1.10", "140.82.112.4", "54322", "80", "github.com" }, // PASS
                { "192.168.1.10", "198.35.26.96", "54323", "80", "en.wikipedia.org" }, // PASS
                { "192.168.1.10", "1.1.1.1", "54320", "80", "cloudflare.com" }, // BLOCKED (IP rule)
                { "192.168.1.10", "157.240.229.35", "54324", "80", "facebook.com" }, // BLOCKED (domain rule)
                { "192.168.1.10", "203.0.113.99", "54325", "80", "malware.badguy.net" }, // BLOCKED (domain rule)
                { "192.168.1.10", "142.250.80.46", "54321", "80", "google.com" }, // PASS (2nd packet same flow)
                { "192.168.1.10", "157.240.229.35", "54324", "80", "facebook.com" }, // BLOCKED (repeat)
        };

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            // Write PCAP global header (24 bytes)
            ByteBuffer globalHeader = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
            globalHeader.putInt(0xA1B2C3D4); // Magic number
            globalHeader.putShort((short) 2); // Version major
            globalHeader.putShort((short) 4); // Version minor
            globalHeader.putInt(0); // Timezone offset
            globalHeader.putInt(0); // Timestamp accuracy
            globalHeader.putInt(65535); // Snapshot length
            globalHeader.putInt(1); // Link type: Ethernet
            fos.write(globalHeader.array());

            int timestamp = 1740000000;
            int passed = 0, blocked = 0;

            for (String[] pkt : packets) {
                String srcIp = pkt[0];
                String dstIp = pkt[1];
                int srcPort = Integer.parseInt(pkt[2]);
                int dstPort = Integer.parseInt(pkt[3]);
                String host = pkt[4];

                byte[] packetBytes = buildHttpPacket(srcIp, dstIp, srcPort, dstPort, host);

                // Write PCAP packet header (16 bytes)
                ByteBuffer ph = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
                ph.putInt(timestamp++); // Timestamp seconds
                ph.putInt(0); // Timestamp microseconds
                ph.putInt(packetBytes.length); // Captured length
                ph.putInt(packetBytes.length); // Original length
                fos.write(ph.array());
                fos.write(packetBytes);

                System.out.println("  Added packet: Host = " + host + " -> " + dstIp);
            }

            System.out.println("\nGenerated: " + outputFile);
            System.out.println("Total packets: " + packets.length);
            System.out.println("\nNow run the engine:");
            System.out.println("  java -cp out com.dpi.Main demo.pcap clean.pcap");
            System.out.println("\nExpected: 3 passed, 3 blocked (facebook x2, malware, cloudflare IP)");
        }
    }

    private static byte[] buildHttpPacket(String srcIp, String dstIp,
            int srcPort, int dstPort, String host) {
        byte[] httpPayload = ("GET / HTTP/1.1\r\n" +
                "Host: " + host + "\r\n" +
                "User-Agent: Mozilla/5.0\r\n" +
                "Connection: close\r\n" +
                "\r\n").getBytes();

        // TCP header (20 bytes)
        ByteBuffer tcp = ByteBuffer.allocate(20);
        tcp.putShort((short) srcPort); // Source port
        tcp.putShort((short) dstPort); // Destination port
        tcp.putInt(1000); // Sequence number
        tcp.putInt(0); // Ack number
        tcp.put((byte) 0x50); // Data offset: 5 (20 bytes)
        tcp.put((byte) 0x18); // Flags: PSH + ACK
        tcp.putShort((short) 65535); // Window size
        tcp.putShort((short) 0); // Checksum
        tcp.putShort((short) 0); // Urgent pointer

        // IPv4 header (20 bytes)
        int totalLen = 20 + 20 + httpPayload.length;
        ByteBuffer ip = ByteBuffer.allocate(20);
        ip.put((byte) 0x45); // Version 4 + IHL 5
        ip.put((byte) 0); // DSCP
        ip.putShort((short) totalLen); // Total length
        ip.putShort((short) 1234); // ID
        ip.putShort((short) 0x4000); // Don't fragment
        ip.put((byte) 64); // TTL
        ip.put((byte) 6); // Protocol: TCP
        ip.putShort((short) 0); // Checksum
        ip.put(ipToBytes(srcIp));
        ip.put(ipToBytes(dstIp));

        // Ethernet header (14 bytes)
        ByteBuffer eth = ByteBuffer.allocate(14);
        eth.put(new byte[] { (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0x01 }); // Dst MAC
        eth.put(new byte[] { (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x01 }); // Src MAC
        eth.putShort((short) 0x0800); // EtherType: IPv4

        // Combine everything
        ByteBuffer packet = ByteBuffer.allocate(14 + 20 + 20 + httpPayload.length);
        packet.put(eth.array());
        packet.put(ip.array());
        packet.put(tcp.array());
        packet.put(httpPayload);
        return packet.array();
    }

    private static byte[] ipToBytes(String ip) {
        String[] parts = ip.split("\\.");
        return new byte[] {
                (byte) Integer.parseInt(parts[0]),
                (byte) Integer.parseInt(parts[1]),
                (byte) Integer.parseInt(parts[2]),
                (byte) Integer.parseInt(parts[3])
        };
    }
}
