#!/bin/bash
# Direct Binary Transfer Script - bypasses expect issues
# Uses sshpass for reliable SCP transfer

set -e

WINDOWS_HOST="YOUR_TARGET_IP"
WINDOWS_USER="administrator"
WINDOWS_PASSWORD="YOUR_WINDOWS_PASSWORD"
WINDOWS_TARGET_DIR="C:/temp"

# Find latest binary
BINARY_PATTERN="remote_command_executor_cpp_*.exe"
latest_binary=""
latest_mtime=0

for file in $BINARY_PATTERN; do
    if [ -f "$file" ]; then
        mtime=$(stat -f "%m" "$file" 2>/dev/null || stat -c "%Y" "$file" 2>/dev/null || echo "0")
        if [ "$mtime" -gt "$latest_mtime" ]; then
            latest_mtime="$mtime"
            latest_binary="$file"
        fi
    fi
done

if [ -z "$latest_binary" ]; then
    echo "ERROR: No binary files found matching pattern $BINARY_PATTERN"
    exit 1
fi

echo "Found binary: $latest_binary"
ls -lh "$latest_binary"

# Get file size
binary_size=$(stat -f "%z" "$latest_binary" 2>/dev/null || stat -c "%s" "$latest_binary" 2>/dev/null || echo "0")
echo "Binary size: $binary_size bytes"

# Check if sshpass is available
if ! command -v sshpass &> /dev/null; then
    echo "ERROR: sshpass not found. Installing..."
    if command -v brew &> /dev/null; then
        brew install hudochenkov/sshpass/sshpass
    else
        echo "Please install sshpass manually"
        exit 1
    fi
fi

# Transfer using sshpass
echo "Transferring binary to Windows..."
sshpass -p "$WINDOWS_PASSWORD" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$latest_binary" "${WINDOWS_USER}@${WINDOWS_HOST}:${WINDOWS_TARGET_DIR}/remote_cmd.exe"

if [ $? -eq 0 ]; then
    echo "Transfer successful!"
    
    # Verify transfer
    echo "Verifying transfer..."
    remote_size=$(sshpass -p "$WINDOWS_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "${WINDOWS_USER}@${WINDOWS_HOST}" \
        "powershell -Command \"(Get-Item '${WINDOWS_TARGET_DIR}/remote_cmd.exe').Length\"" | tr -d '\r\n')
    
    echo "Remote file size: $remote_size bytes"
    
    if [ "$remote_size" = "$binary_size" ]; then
        echo "✅ File size matches! Transfer verified."
    else
        echo "⚠️  File size mismatch: local=$binary_size, remote=$remote_size"
        exit 1
    fi
else
    echo "❌ Transfer failed!"
    exit 1
fi

echo ""
echo "Binary successfully transferred and verified!"
echo "You can now execute it on Windows with:"
echo "ssh ${WINDOWS_USER}@${WINDOWS_HOST} \"${WINDOWS_TARGET_DIR}\\remote_cmd.exe YOUR_SERVER_IP 8080 --debug\""
