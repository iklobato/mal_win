# Makefile for C++ Remote Command Executor (MinGW-w64)
# Cross-compilation from Linux/macOS to Windows

CC = x86_64-w64-mingw32-g++
CFLAGS = -std=c++11 -O3 -static-libgcc -static-libstdc++ -static \
         -s -Wl,--strip-all \
         -fno-stack-protector -fno-ident \
         -ffunction-sections -fdata-sections \
         -Wl,--gc-sections -Wl,--build-id=none \
         -fomit-frame-pointer -fno-unroll-loops \
         -Wl,--disable-auto-import -Wl,--enable-auto-image-base
TIMESTAMP = $(shell date +%Y%m%d_%H%M%S)
TARGET = remote_command_executor_cpp_$(TIMESTAMP).exe
SOURCE = remote_command_executor.cpp
LIBS = -lws2_32 -ladvapi32 -lkernel32 -lntdll

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)
	@echo "Build complete: $(TARGET)"
	@echo "Usage: $(TARGET) [domain] [port]"

# Clean
clean:
	rm -f remote_command_executor_cpp_*.exe *.o
	@echo "Cleaned build artifacts"

.PHONY: all clean
