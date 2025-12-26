#!/bin/bash
# Script to start the C&C server on Linux

echo "Starting Command and Control Server..."

# Kill any existing Python processes
pkill -9 -f python3

# Wait a moment
sleep 2

# Start the server
cd /root/asd
nohup python3 -u server_new.py > /tmp/server_cnc.log 2>&1 &

# Get the PID
SERVER_PID=$!

echo "Server started with PID: $SERVER_PID"
echo "Waiting for server to initialize..."
sleep 2

# Check if server is running
if ps -p $SERVER_PID > /dev/null; then
    echo "Server is running"
    echo "Testing server response..."
    curl http://localhost:8080/
else
    echo "Server failed to start"
    echo "Log output:"
    cat /tmp/server_cnc.log
    exit 1
fi
