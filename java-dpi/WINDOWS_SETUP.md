# Windows Setup Guide for Java DPI Engine

Hey! This is a simple guide on how to get our Java Deep Packet Inspection (DPI) project up and running on your Windows machine. I've laid out a few ways you can run it, whether you like the classic command line or use ideas like VS Code or IntelliJ.

## Basic Setup (Everyone needs to do this!)

### 1. Install Java (JDK 17)
We used Java 17 for this project, so it's highly recommended.
1. Download JDK 17 for Windows from the Oracle website or adoptium.net.
2. Run the installer. It's a standard next-next-finish setup.

### 2. Set Up JAVA_HOME
You have to tell Windows where Java lives so it knows how to execute our code.
1. Open up your Windows Start Menu, type "Environment Variables", and click "Edit the system environment variables".
2. Click the "Environment Variables" button at the bottom.
3. Under "System variables", click "New".
   - **Variable name**: `JAVA_HOME`
   - **Variable value**: `C:\Program Files\Java\jdk-17` (make sure this perfectly matches where yours installed!)
4. Now, find the `Path` variable in that same System list, click "Edit", and click "New" to add an entry:
   - `%JAVA_HOME%\bin`
5. Hit OK on all the windows.

### 3. Verify it works
Open a brand new Command Prompt (cmd) and type:
```cmd
java -version
javac -version
```
If you see the version numbers pop up, you did it right! If it says "command not found", double-check your Path variable setup.

---

## How to Run It!

You need an `input.pcap` file for the engine to read, and an `output.pcap` file for it to write to. Just place your input file right next to your code.

### Option 1: Using Command Prompt (The classic way)
If you just want to run it from the terminal without any fancy tools:

**Step 1:** Open `cmd` and `cd` into the project root folder (the folder containing the `src` folder).

**Step 2:** Compile the code using `javac`:
```cmd
javac -d out src\com\dpi\**\*.java
```
*(This tells Java to compile everything in the `src` folder and stick the generated class files into a folder named `out`.)*

**Step 3:** Run the code:
```cmd
java -cp out com.dpi.Main input.pcap output.pcap
```

### Option 2: Using VS Code
VS Code is super lightweight and easy for Java.
1. Install the "Extension Pack for Java" from the VS Code extensions tab.
2. Open the main project folder in VS Code.
3. Open `src/com/dpi/Main.java`.
4. VS Code will show little "Run" and "Debug" buttons floating right above the `public static void main` method. Keep in mind you will need to edit your `launch.json` file inside the `.vscode` folder to pass the `args` (`["input.pcap", "output.pcap"]`) to the main method!

### Option 3: Using IntelliJ IDEA (Community Edition)
This is what a lot of us use for bigger Java stuff.
1. Open IntelliJ and click "Open", then select the main project folder.
2. Wait a minute for IntelliJ to scan your files.
3. Once done, find `Main.java` inside `src/com/dpi/` in the left sidebar.
4. Right-click `Main.java` and click "Modify Run Configuration...".
5. In the "Program arguments" box, type: `input.pcap output.pcap`
6. Click Apply, then click the green Play button near the top right!

---

## Creating your own PCAP files with Wireshark

Instead of just using ours, you can easily make your own traffic files to test!
1. Download and install [Wireshark](https://www.wireshark.org/).
2. Open it, double click your active Wi-Fi or Ethernet connection to start sniffing.
3. Open a browser and do some random things (like loading a website) to generate traffic.
4. Go back to Wireshark and click the red Stop square at the top left.
5. Click **File -> Save As...** and save it as `input.pcap` in your project folder!

---

## Troubleshooting List 

Things usually break the first time. Here's how to fix common problems:

- **'javac is not recognized as an internal or external command'**
  - Your `Path` variable is wrong. You either forgot to put `%JAVA_HOME%\bin` in Path, or you didn't restart Command Prompt after saving it. Restart CMD!

- **'Error: Could not find or load main class com.dpi.Main'**
  - You are either running the `java` command from the wrong folder, or the code didn't compile properly. Make sure you compile first, and make sure you typed `-cp out` (which means Classpath = out folder) exactly.

- **Wrong classpath errors / ClassNotFoundException**
  - This usually means you ran `java com.dpi.Main` instead of `java -cp out com.dpi.Main`. You must tell Java where to look for the compiled `.class` files.

- **Missing input file (FileNotFoundException)**
  - Make sure `input.pcap` is actually in the exact same directory that your Command Prompt or IDE is open in.

- **Permission Errors (Access Denied)**
  - Sometimes Windows blocks writing to the `output.pcap` if your user doesn't have permissions in that specific folder. Try running Command Prompt as Administrator, or just move the project folder to somewhere basic like your Desktop or Documents.

---

## Quick Reference

If you forget everything else, just remember these two lines:

**Compile Command:**
```cmd
javac -d out src\com\dpi\**\*.java
```

**Run Command:**
```cmd
java -cp out com.dpi.Main input.pcap output.pcap
```

---

## Running the Spring Boot AI Server on Windows

The project now includes a **Spring Boot REST API + local AI anomaly detection server**. Here's how to run it on Windows.

### Prerequisites

In addition to JDK 17, you need **Apache Maven**:

1. Download Maven from: https://maven.apache.org/download.cgi
2. Extract it (e.g., to `C:\Program Files\Apache\maven`)
3. Add `C:\Program Files\Apache\maven\bin` to your `Path` environment variable
4. Verify with: `mvn -version`

### Option 1: Run with Maven (Development)

Open a Command Prompt and run:

```cmd
cd "C:\path\to\deeppacket   inception\dpi-spring-server"
mvn clean package -DskipTests
java -jar target\dpi-spring-server-1.0.0.jar
```

The server starts at **http://localhost:8080**. You'll see:

```
╔══════════════════════════════════════════════════════════╗
║         DPI Spring Boot AI Server - STARTED             ║
║  REST API:   http://localhost:8080/api                   ║
║  Health:     http://localhost:8080/actuator/health       ║
╚══════════════════════════════════════════════════════════╝
```

### Option 2: Run with Docker Desktop (Easiest)

1. Install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)
2. Open Command Prompt in the project root:

```cmd
cd "C:\path\to\deeppacket   inception"
docker-compose up --build
```

Server will be live at `http://localhost:8080` — no Java or Maven install needed!

### Testing the API

**Analyze a PCAP file** (PowerShell):
```powershell
$file = Get-Item "java-dpi\demo.pcap"
Invoke-RestMethod -Uri "http://localhost:8080/api/analyze" `
  -Method Post `
  -Form @{ file = $file }
```

**Or with curl** (if installed):
```cmd
curl -X POST http://localhost:8080/api/analyze -F "file=@java-dpi\demo.pcap"
curl http://localhost:8080/api/metrics
curl http://localhost:8080/api/anomalies/summary
```

**Add a new domain block rule:**
```cmd
curl -X POST http://localhost:8080/api/rules/domain ^
  -H "Content-Type: application/json" ^
  -d "{\"value\": \"tiktok.com\"}"
```

### Testing with Postman (Recommended for Windows)

1. Download [Postman](https://www.postman.com/downloads/)
2. Create a new `POST` request to `http://localhost:8080/api/analyze`
3. Under **Body** → **form-data** → add a key `file` → change type to **File** → select your `.pcap` file
4. Click **Send** → you'll get the full JSON threat report!

### Troubleshooting

- **Port 8080 already in use**: Change `server.port=8081` in `dpi-spring-server\src\main\resources\application.properties`
- **Maven not found**: Make sure `mvn` is on your `Path` environment variable and restart CMD
- **Build fails**: Ensure you are running the command from inside `dpi-spring-server\` directory, not from the project root
