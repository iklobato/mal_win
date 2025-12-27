#!/bin/bash
# Cross-compile Windows .exe using Docker with Windows container

set -e

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TARGET="hansen-tcap_${TIMESTAMP}.exe"

echo "Building Windows .exe using Docker Windows container..."

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: Docker is required"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker daemon is not running"
    exit 1
fi

echo "Building Docker image with Windows Python..."
docker build -f Dockerfile.windows-pyinstaller -t hansen-tcap-windows-builder .

echo "Extracting Windows .exe from container..."
CONTAINER_ID=$(docker create hansen-tcap-windows-builder)
docker cp ${CONTAINER_ID}:/build/dist/hansen-tcap.exe ./dist/ 2>/dev/null || \
docker cp ${CONTAINER_ID}:/build/hansen-tcap.exe ./ 2>/dev/null || true
docker rm ${CONTAINER_ID}

if [ -f dist/hansen-tcap.exe ]; then
    mv dist/hansen-tcap.exe "$TARGET"
    echo "✓ Build complete: $TARGET"
    ls -lh "$TARGET"
elif [ -f hansen-tcap.exe ]; then
    mv hansen-tcap.exe "$TARGET"
    echo "✓ Build complete: $TARGET"
    ls -lh "$TARGET"
else
    echo "Error: Windows .exe not found"
    exit 1
fi
