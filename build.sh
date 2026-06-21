#!/bin/bash
# XConf Agent Compilation Script
# Generates native binaries for macOS (Universal Binary), Linux, and Windows.
set -e

# Change directory to script's location
cd "$(dirname "$0")"

echo "========================================================"
echo "⚡ Starting XConf Agent Multi-Platform Compilation"
echo "========================================================"

# Create clean distribution directory
rm -rf bin
mkdir -p bin

# 1. Compile macOS ARM64 (Apple Silicon)
echo "  ↳ Building macOS ARM64 (Apple Silicon)..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/xconf-agent-darwin-arm64 .

# 2. Compile macOS AMD64 (Intel)
echo "  ↳ Building macOS AMD64 (Intel)..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/xconf-agent-darwin-amd64 .

# 3. Create macOS Universal Binary using lipo
if command -v lipo >/dev/null 2>&1; then
    echo "  ↳ Merging slices into macOS Universal Binary..."
    lipo -create -output bin/xconf-agent-darwin bin/xconf-agent-darwin-arm64 bin/xconf-agent-darwin-amd64
    echo "  [OK] macOS Universal Binary created successfully!"
else
    echo "  ⚠️ 'lipo' command not found, skipping universal binary creation."
fi

# 4. Compile Linux AMD64
echo "  ↳ Building Linux AMD64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/xconf-agent-linux-amd64 .

# 5. Compile Linux ARM64
echo "  ↳ Building Linux ARM64..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/xconf-agent-linux-arm64 .

# 6. Compile Windows AMD64
echo "  ↳ Building Windows AMD64..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/xconf-agent-windows-amd64.exe .

# 7. Compile Windows ARM64
echo "  ↳ Building Windows ARM64..."
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/xconf-agent-windows-arm64.exe .

echo "========================================================"
echo "🎉 Compilation Completed Successfully!"
echo "========================================================"
ls -lh bin

# 8. Generate Checksums
echo "  ↳ Generating SHA-256 checksums..."
(
    cd bin
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum * | grep -v "checksums.txt" > checksums.txt
    else
        shasum -a 256 * | grep -v "checksums.txt" > checksums.txt
    fi
)
echo "  [OK] checksums.txt generated in bin/"
