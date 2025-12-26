# Installation Guide

## Dependencies

This project requires **libcurl** for HTTP/HTTPS operations.

### Installing libcurl on Windows

#### Option 1: Using vcpkg (Recommended)

1. Install vcpkg if you haven't already:
   ```bash
   git clone https://github.com/Microsoft/vcpkg.git
   cd vcpkg
   .\bootstrap-vcpkg.bat
   ```

2. Install curl:
   ```bash
   .\vcpkg install curl:x64-windows
   ```

3. Integrate with Visual Studio:
   ```bash
   .\vcpkg integrate install
   ```

4. Compile with:
   ```bash
   gcc -I"path\to\vcpkg\installed\x64-windows\include" -L"path\to\vcpkg\installed\x64-windows\lib" command_monitor.c -lcurl -o command_monitor.exe
   ```

#### Option 2: Pre-built Binaries

1. Download libcurl from: https://curl.se/windows/
2. Extract to a directory (e.g., `C:\curl\`)
3. Update your Makefile or compile command:
   ```bash
   gcc -IC:\curl\include -LC:\curl\lib command_monitor.c -lcurl -lws2_32 -lwldap32 -o command_monitor.exe
   ```

#### Option 3: MSYS2/MinGW

```bash
pacman -S mingw-w64-x86_64-curl
```

Then compile normally with the Makefile.

## Compilation

### Using MinGW

```bash
make -f Makefile.win
```

Or manually:
```bash
gcc -Wall -Wextra -std=c11 -O2 -o command_monitor.exe command_monitor.c -lcurl -lws2_32 -lwldap32
```

### Using Visual Studio

1. Install libcurl via vcpkg (see Option 1 above)
2. Open Developer Command Prompt
3. Compile:
   ```bash
   cl /Fe:command_monitor.exe command_monitor.c libcurl.lib ws2_32.lib wldap32.lib /link /SUBSYSTEM:CONSOLE
   ```

## Benefits of Using libcurl

- **Simplified HTTP code**: Reduced from ~200 lines to ~50 lines
- **Automatic HTTPS support**: No manual SSL/TLS handling
- **Cross-platform**: Same code works on Windows, Linux, macOS
- **Well-tested**: Industry standard, used by millions of applications
- **Feature-rich**: Handles redirects, cookies, authentication automatically
- **Better error handling**: Comprehensive error codes and diagnostics
