@echo off
echo =======================================
echo   DPI Engine - Unit Test Runner
echo =======================================
echo.

:: Compile all source + test files together
echo Compiling tests...
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
 src\com\dpi\rules\CompositeRuleEngine.java ^
 test\FiveTupleTest.java ^
 test\HttpHostExtractorTest.java ^
 test\IPv4ParserTest.java

if %errorlevel% neq 0 (
    echo Compilation failed.
    pause
    exit /b 1
)

echo.
echo ----------------------------------------
echo Running FiveTupleTest...
java -ea -cp out test.FiveTupleTest
echo.
echo Running HttpHostExtractorTest...
java -ea -cp out test.HttpHostExtractorTest
echo.
echo Running IPv4ParserTest...
java -ea -cp out test.IPv4ParserTest
echo ----------------------------------------
echo.
echo All tests complete!
pause
