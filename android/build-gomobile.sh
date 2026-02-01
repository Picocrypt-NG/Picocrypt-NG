#!/bin/bash
# Build script for Go Mobile bindings
# This script builds the Go mobile AAR library for Android

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_SRC_DIR="$SCRIPT_DIR/../src"
OUTPUT_DIR="$SCRIPT_DIR/app/libs"

# Set Android SDK/NDK paths
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"

# Find NDK - prefer NDK 21.x for gomobile compatibility (supports API 16)
if [ -d "$ANDROID_HOME/ndk" ]; then
    # Try NDK 21.x first (best gomobile compatibility, supports API 16)
    NDK_21=$(ls -1d "$ANDROID_HOME/ndk"/21.* 2>/dev/null | sort -V | tail -1)
    if [ -n "$NDK_21" ] && [ -d "$NDK_21" ]; then
        export ANDROID_NDK_HOME="$NDK_21"
        echo "Using NDK 21.x: $ANDROID_NDK_HOME"
    else
        # Fall back to latest NDK version
        NDK_VERSION=$(ls -1 "$ANDROID_HOME/ndk" | sort -V | tail -1)
        if [ -n "$NDK_VERSION" ]; then
            export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
            echo "Using NDK: $ANDROID_NDK_HOME"
        fi
    fi
elif [ -d "$ANDROID_HOME/ndk-bundle" ]; then
    export ANDROID_NDK_HOME="$ANDROID_HOME/ndk-bundle"
    echo "Using NDK: $ANDROID_NDK_HOME"
else
    echo "Warning: NDK not found. gomobile may fail."
fi

echo "Building Go Mobile bindings for Android..."
echo "Go source directory: $GO_SRC_DIR"
echo "Output directory: $OUTPUT_DIR"
echo "Android SDK: $ANDROID_HOME"
echo "Android NDK: ${ANDROID_NDK_HOME:-not set}"

# Check if gomobile is installed
if ! command -v gomobile &> /dev/null; then
    echo "gomobile not found. Installing..."
    go install golang.org/x/mobile/cmd/gomobile@latest
    gomobile init
fi

# Ensure golang.org/x/mobile/bind is available
echo "Ensuring Go mobile bind package is available..."
cd "$GO_SRC_DIR"
go get golang.org/x/mobile/bind 2>/dev/null || true

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build AAR
echo "Building AAR..."
cd "$GO_SRC_DIR"

# gomobile uses ANDROID_NDK_HOME environment variable (already set above)
gomobile bind -target android -o "$OUTPUT_DIR/picocrypt-mobile.aar" ./mobile

echo "✓ Build successful!"
echo "  AAR location: $OUTPUT_DIR/picocrypt-mobile.aar"

