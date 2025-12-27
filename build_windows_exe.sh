#!/bin/bash
# Build Windows .exe from macOS/Linux using Docker

set -e

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TARGET="hansen-tcap_${TIMESTAMP}.exe"

echo "Building Windows .exe executable..."

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: Docker is required to build Windows .exe from macOS/Linux"
    echo "Please install Docker Desktop and ensure it's running"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker daemon is not running"
    echo "Please start Docker Desktop"
    exit 1
fi

echo "Building Docker image with Wine and Python..."
docker build -f Dockerfile.windows -t hansen-tcap-builder . || {
    echo "Docker build failed. Trying alternative method..."
    exit 1
}

echo "Running PyInstaller in Docker container..."
docker run --rm \
    -v "$(pwd)/dist:/build/dist" \
    hansen-tcap-builder || {
    echo "Docker run failed"
    exit 1
}

if [ -f "dist/hansen-tcap.exe" ]; then
    mv "dist/hansen-tcap.exe" "$TARGET"
    echo "✓ Build complete: $TARGET"
    echo "  File size: $(ls -lh "$TARGET" | awk '{print $5}')"
    rm -rf build dist __pycache__ *.spec.bak 2>/dev/null || true
else
    echo "Error: Windows .exe not found in dist/"
    exit 1
fi

