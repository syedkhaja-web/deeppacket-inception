# DPI Engine — How to Run

Everything you need to compile and run this project on your own.

---

## Prerequisites

- **Java 17+** installed — check by running: `java -version`
- **VS Code** with the project open

---

## Step 1 — Open the VS Code Terminal

Press `Ctrl + `` ` `` `` (backtick key, above Tab).

Make sure your terminal shows this folder path:
```
C:\Users\SYED TAQHI\Desktop\deeppacket   inception\java-dpi>
```

If it doesn't, type:
```cmd
cd "C:\Users\SYED TAQHI\Desktop\deeppacket   inception\java-dpi"
```

---

## Step 2 — Compile the Code

Run this every time you change any `.java` file:
```cmd
.\build.bat
```

You should see:
```
BUILD SUCCESSFUL!
```

---

## Step 3 — Generate Demo Traffic (first time only)

```cmd
javac GenerateDemoPcap.java
java GenerateDemoPcap
```

This creates a `demo.pcap` file with a mix of normal and blocked traffic.

---

## Step 4 — Run the DPI Engine

```cmd
java -cp out com.dpi.Main demo.pcap clean.pcap
```

### Expected Output:
```
Starting DPI Engine...
Processing: demo.pcap -> clean.pcap
Finished reading PCAP. Waiting for processing to finish...
DPI Engine completed.
Packets Passed:   4
Packets Dropped:  4
Done! Total Time: 0.05 seconds
```

The `clean.pcap` file contains only the packets that were NOT blocked.

---

## Quick Reference — All Commands

| What | Command |
|------|---------|
| Compile | `.\build.bat` |
| Generate demo PCAP | `javac GenerateDemoPcap.java && java GenerateDemoPcap` |
| Run engine | `java -cp out com.dpi.Main demo.pcap clean.pcap` |
| Run on your own PCAP | `java -cp out com.dpi.Main yourfile.pcap output.pcap` |

---

## What Gets Blocked?

Defined in `src\com\dpi\Main.java` inside `buildRules()`:

| Rule | Blocked Value |
|------|--------------|
| Domain | `facebook.com` |
| Domain | `malware.badguy.net` |
| IP Address | `1.1.1.1` |
| IP Address | `8.8.8.8` |

To add more, open `Main.java` and add:
```java
domainRule.addDomain("twitter.com");
ipRule.addIpStr("93.184.216.34");
```
Then recompile with `.\build.bat` and run again.

---

## Use a Real Wireshark Capture (Optional)

1. Open **Wireshark** → Start capture on your Wi-Fi adapter
2. Browse to `facebook.com` in your browser
3. Stop capture → **File → Save As** → name it `mytraffic.pcap`
4. Move it into the `java-dpi` folder
5. Run: `java -cp out com.dpi.Main mytraffic.pcap filtered.pcap`
