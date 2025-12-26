# Compilation Instructions

## Windows Compilation

This code is Windows-specific and requires Windows headers and libraries.

### Prerequisites

1. **MinGW-w64** or **MSVC** compiler
2. **libcurl** development libraries
3. **Windows SDK** (for Windows.h)

### Option 1: Using MinGW-w64 (Recommended for cross-compilation)

#### Install MinGW-w64 on macOS/Linux:
```bash
# macOS
brew install mingw-w64

# Then compile:
x86_64-w64-mingw32-gcc -Wall -Wextra -std=c11 -O2 \
  -o command_monitor.exe command_monitor.c \
  -lcurl -lws2_32 -lwldap32 -lshell32 \
  -I/path/to/curl/include -L/path/to/curl/lib
```

#### Install MinGW-w64 on Windows:
```bash
# Using MSYS2
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-curl

# Then compile:
gcc -Wall -Wextra -std=c11 -O2 \
  -o command_monitor.exe command_monitor.c \
  -lcurl -lws2_32 -lwldap32 -lshell32
```

### Option 2: Using Microsoft Visual C++

```bash
cl /Fe:command_monitor.exe command_monitor.c \
   libcurl.lib ws2_32.lib wldap32.lib shell32.lib \
   /link /SUBSYSTEM:CONSOLE \
   /I"C:\path\to\curl\include" \
   /LIBPATH:"C:\path\to\curl\lib"
```

### Option 3: Using the Makefile

```bash
# Normal build
make -f Makefile.win

# Obfuscated build
make -f Makefile.win obfuscated
```

### Required Libraries

- **libcurl**: HTTP/HTTPS client library
- **ws2_32**: Windows Sockets API
- **wldap32**: Windows LDAP API (for libcurl)
- **shell32**: Windows Shell API (for SHGetFolderPath)

### Dependencies Installation

See `INSTALL.md` for detailed dependency installation instructions.

### Cross-Compilation from macOS/Linux

To cross-compile from macOS/Linux, you need:

1. Install MinGW-w64:
   ```bash
   brew install mingw-w64
   ```

2. Install libcurl for Windows (pre-built binaries):
   - Download from: https://curl.se/windows/
   - Extract and note the include/lib paths

3. Compile with cross-compiler:
   ```bash
   x86_64-w64-mingw32-gcc -Wall -Wextra -std=c11 -O2 \
     -o command_monitor.exe command_monitor.c \
     -lcurl -lws2_32 -lwldap32 -lshell32 \
     -I/path/to/curl/include -L/path/to/curl/lib
   ```

### Notes

- The binary will be `command_monitor.exe` (Windows executable)
- For obfuscated version, use `make -f Makefile.win obfuscated`
- Ensure all Windows libraries are available in the library path
