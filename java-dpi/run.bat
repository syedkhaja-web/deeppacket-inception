@echo off
echo =======================================
echo   DPI Engine - Full Demo Runner
echo =======================================
echo.

:: Only compile if the out folder is missing or empty (skip if already compiled)
if not exist out\com\dpi\Main.class (
    echo [1/3] Compiling DPI Engine...
    call build.bat >nul 2>&1
    if %errorlevel% neq 0 (
        echo ERROR: Compilation failed! Run build.bat manually to see errors.
        pause
        exit /b 1
    )
    javac GenerateDemoPcap.java >nul 2>&1
    echo       Compiled!
) else (
    echo [1/3] Already compiled - skipping. ^(Run build.bat to force recompile^)
)

:: Generate demo.pcap only if it doesn't exist yet
if not exist demo.pcap (
    echo [2/3] Generating demo traffic...
    java GenerateDemoPcap
    echo.
) else (
    echo [2/3] demo.pcap already exists - skipping generation.
    echo       ^(Delete demo.pcap to regenerate^)
)

:: Run the DPI Engine
echo [3/3] Running DPI Engine...
echo ----------------------------------------
java -cp out com.dpi.Main demo.pcap clean.pcap
echo ----------------------------------------
echo.
echo Output saved to: clean.pcap
echo.
pause
