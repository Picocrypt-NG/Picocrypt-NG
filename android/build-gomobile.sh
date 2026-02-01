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

# Extract NDK version from path and validate it's 29.0+
# Returns the major version number (e.g., "29" from "29.0.14206865")
get_ndk_major_version() {
    local ndk_path="$1"
    # Extract version from path like /path/to/ndk/29.0.14206865
    local version=$(basename "$ndk_path")
    # Extract major version (first number before first dot)
    echo "${version%%.*}"
}

# Validate NDK version is 29.0 or higher
validate_ndk_version() {
    local ndk_path="$1"
    if [ ! -d "$ndk_path" ]; then
        echo "Error: NDK path does not exist: $ndk_path" >&2
        return 1
    fi
    
    local major_version=$(get_ndk_major_version "$ndk_path")
    if [ -z "$major_version" ] || ! [[ "$major_version" =~ ^[0-9]+$ ]]; then
        echo "Error: Could not determine NDK version from path: $ndk_path" >&2
        return 1
    fi
    
    if [ "$major_version" -lt 29 ]; then
        echo "Error: NDK version $major_version is too old. NDK 29.0 or higher is required." >&2
        echo "  Found NDK at: $ndk_path" >&2
        echo "  Please install NDK 29.0 or higher." >&2
        return 1
    fi
    
    return 0
}

# Find and validate NDK 29+
if [ -n "$ANDROID_NDK_HOME" ] && [ -d "$ANDROID_NDK_HOME" ]; then
    # ANDROID_NDK_HOME is already set (e.g., by GitHub Actions)
    echo "Using NDK from ANDROID_NDK_HOME: $ANDROID_NDK_HOME"
    if ! validate_ndk_version "$ANDROID_NDK_HOME"; then
        exit 1
    fi
elif [ -d "$ANDROID_HOME/ndk" ]; then
    # Find the latest NDK version (should be 29+)
    NDK_VERSION=$(ls -1 "$ANDROID_HOME/ndk" | sort -V | tail -1)
    if [ -n "$NDK_VERSION" ]; then
        export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
        echo "Using NDK: $ANDROID_NDK_HOME"
        if ! validate_ndk_version "$ANDROID_NDK_HOME"; then
            exit 1
        fi
    else
        echo "Error: No NDK found in $ANDROID_HOME/ndk" >&2
        exit 1
    fi
elif [ -d "$ANDROID_HOME/ndk-bundle" ]; then
    export ANDROID_NDK_HOME="$ANDROID_HOME/ndk-bundle"
    echo "Using NDK: $ANDROID_NDK_HOME"
    if ! validate_ndk_version "$ANDROID_NDK_HOME"; then
        exit 1
    fi
else
    echo "Error: NDK not found. Please install NDK 29.0 or higher." >&2
    echo "  Expected location: $ANDROID_HOME/ndk" >&2
    exit 1
fi

# Always use API level 24 (matches app's minSdk, required for NDK 29+)
USE_ANDROID_API="-androidapi 24"

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
# Always use API level 24 (matches app's minSdk, required for NDK 29+)
gomobile bind -target android $USE_ANDROID_API -o "$OUTPUT_DIR/picocrypt-mobile.aar" ./mobile

echo "✓ Build successful!"
echo "  AAR location: $OUTPUT_DIR/picocrypt-mobile.aar"

