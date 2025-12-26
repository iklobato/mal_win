#!/bin/bash

echo "=== Building command_monitor.exe ==="
echo ""

# Check for cross-compiler
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[+] Cross-compiler found: x86_64-w64-mingw32-gcc"
    CC="x86_64-w64-mingw32-gcc"
elif command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[+] Cross-compiler found: i686-w64-mingw32-gcc"
    CC="i686-w64-mingw32-gcc"
else
    echo "[!] Windows cross-compiler not found!"
    echo "[!] Install with: brew install mingw-w64"
    echo ""
    echo "Alternatively, compile on Windows with:"
    echo "  make -f Makefile.win"
    exit 1
fi

# Check for libcurl
CURL_INCLUDE=""
CURL_LIB=""

if [ -d "/usr/local/include/curl" ]; then
    CURL_INCLUDE="-I/usr/local/include"
    CURL_LIB="-L/usr/local/lib"
elif [ -d "/opt/homebrew/include/curl" ]; then
    CURL_INCLUDE="-I/opt/homebrew/include"
    CURL_LIB="-L/opt/homebrew/lib"
fi

echo "[*] Compiling command_monitor.exe..."
echo ""

$CC -Wall -Wextra -std=c11 -O2 \
    -o command_monitor.exe command_monitor.c \
    -lcurl -lws2_32 -lwldap32 -lshell32 \
    $CURL_INCLUDE $CURL_LIB \
    2>&1

if [ $? -eq 0 ]; then
    echo ""
    echo "[+] Build successful!"
    echo "[+] Binary: command_monitor.exe"
    ls -lh command_monitor.exe 2>/dev/null || echo "Binary created"
else
    echo ""
    echo "[!] Build failed!"
    echo "[!] Make sure libcurl is installed for Windows"
    echo "[!] You may need to compile on a Windows system"
    exit 1
fi
