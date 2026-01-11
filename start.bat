@echo off
echo Building...
go build -o spambot.exe
if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)
echo Build completed!
echo Stopping existing bot instances...
taskkill /F /IM spambot.exe >nul 2>&1
timeout /t 2 /nobreak >nul
echo Starting bot...
spambot.exe
