# Makefile for Remote Command Executor (Windows)
# Compile with gcc (MinGW on Windows or MinGW-w64 cross-compiler on Linux/macOS)
#
# For cross-compilation from Linux/macOS, override CC:
#   make CC=x86_64-w64-mingw32-gcc

CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -mwindows -s
TARGET = remote_command_executor.exe
SOURCE = remote_command_executor.c
LIBS = -lws2_32 -ladvapi32

OBFUSCATED_CFLAGS = -std=c99 -mwindows -s -O3 -ffunction-sections -fdata-sections -fno-ident -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fomit-frame-pointer -Wl,--gc-sections -Wl,--strip-all -Wl,--build-id=none

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

c: $(SOURCE)
	$(CC) $(OBFUSCATED_CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)
	@if command -v upx >/dev/null 2>&1; then \
		echo "Packing with UPX..."; \
		upx --best --lzma $(TARGET) 2>/dev/null || upx --best $(TARGET) 2>/dev/null || true; \
	fi

clean:
	rm -f $(TARGET) *.o

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run c
