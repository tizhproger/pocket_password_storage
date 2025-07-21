@echo off
setlocal

:: === SETTINGS ===
set COM_PORT=COM5
set SPIFFS_OFFSET=0x290000
set MKSPIFFS_PATH="C:\Users\Zeus\AppData\Local\Arduino15\packages\esp32\tools\mkspiffs\0.2.3\mkspiffs.exe"
set ESPTOOL_PATH=esptool
set SPIFFS_SIZE=0x160000
set DATA_DIR=data
set OUTPUT_BIN=spiffs.bin

echo Creating SPIFFS-image...
%MKSPIFFS_PATH% -c %DATA_DIR% -b 4096 -p 256 -s %SPIFFS_SIZE% %OUTPUT_BIN%

if errorlevel 1 (
    echo Error on creation SPIFFS-image
    pause
    exit /b 1
)

echo Uploading SPIFFS into ESP32-C3...
%ESPTOOL_PATH% --chip esp32c3 --port %COM_PORT% write_flash %SPIFFS_OFFSET% %OUTPUT_BIN%

if errorlevel 1 (
    echo Error on uploading SPIFFS
    pause
    exit /b 1
)

echo === Deleting temporary file ===
del /F /Q %OUTPUT_BIN%

echo === Done! ===
pause
