@echo off
echo =======================================
echo   DPI Engine - Build Script
echo =======================================

:: Create output folder if it doesn't exist
if not exist out mkdir out

:: Compile all Java files explicitly
javac -d out ^
 src\com\dpi\Main.java ^
 src\com\dpi\engine\DpiEngine.java ^
 src\com\dpi\flow\FiveTuple.java ^
 src\com\dpi\flow\Flow.java ^
 src\com\dpi\flow\FlowTable.java ^
 src\com\dpi\parser\EthernetParser.java ^
 src\com\dpi\parser\IPv4Parser.java ^
 src\com\dpi\parser\TcpParser.java ^
 src\com\dpi\parser\UdpParser.java ^
 src\com\dpi\io\PcapGlobalHeader.java ^
 src\com\dpi\io\PcapPacketHeader.java ^
 src\com\dpi\io\PcapReader.java ^
 src\com\dpi\io\PcapWriter.java ^
 src\com\dpi\io\RawPacket.java ^
 src\com\dpi\inspect\HttpHostExtractor.java ^
 src\com\dpi\inspect\TlsSniExtractor.java ^
 src\com\dpi\rules\Rule.java ^
 src\com\dpi\rules\IpBlockRule.java ^
 src\com\dpi\rules\DomainBlockRule.java ^
 src\com\dpi\rules\AppBlockRule.java ^
 src\com\dpi\rules\CompositeRuleEngine.java

if %errorlevel%==0 (
    echo.
    echo BUILD SUCCESSFUL!
    echo.
    echo To run: java -cp out com.dpi.Main test.pcap blocked.pcap
) else (
    echo.
    echo BUILD FAILED - Check errors above.
)
pause
