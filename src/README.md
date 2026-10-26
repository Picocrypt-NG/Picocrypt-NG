# Building from Source

## Prerequisites

**Linux:**
```bash
apt install -y gcc xorg-dev libgtk-3-dev libgl1-mesa-dev libglu1-mesa
```

**macOS:**
```bash
xcode-select --install
brew install glfw glew
```

**Windows:** TDM-GCC or MinGW-w64

## Install Go

Download from [go.dev/dl](https://go.dev/dl/) or use your package manager. Use exactly Go 1.27.3 for development and release builds.

## Build

```bash
git clone https://github.com/Picocrypt-NG/Picocrypt-NG.git
cd Picocrypt-NG/src

# Linux/macOS
CGO_ENABLED=1 go build -tags migrated_fynedo -ldflags="-s -w" -o Picocrypt-NG ./cmd/picocrypt

# Windows
CGO_ENABLED=1 go build -tags migrated_fynedo -ldflags="-s -w -H=windowsgui -extldflags=-static" -o Picocrypt-NG.exe ./cmd/picocrypt
```

## Run

```bash
./Picocrypt-NG
```

## Android

The Android build path now lives in the repository root `android/` project and uses gomobile bindings from `src/mobile/`. See `../android/README.md` for the native Android app build instructions.

## WebAssembly

The in-memory single-file bridge creates PCV3 and reads supported PCV1/PCV2/PCV3 volumes. PCV3 accepts a password, keyfiles, or both; D1 requires explicit selection. It supports comments, Paranoid mode, Reed-Solomon and visibly unverified Force output. `picocryptCapabilities()` advertises the size limits; admission preserves the fixed 1 GiB KDF but cannot observe physical browser headroom. Folder, split and streaming workflows remain native features. Owned Go buffers are wiped best-effort, without a guarantee for JavaScript/runtime copies. See `../API.md` for the bridge contract. The separately deployed website requires its own runtime checks.

## Test

```bash
# Default local suite; serialize packages that run the fixed 1 GiB KDF
go test -p 1 -tags migrated_fynedo ./...

# PCV3 production-KDF vectors and operation checks (run separately)
go test -count=1 -p 1 -tags pcv3_production_kdf ./internal/pcv3operation/...

# Golden compatibility checks with production KDF
go test -count=1 -run '^TestGolden' ./internal/volume

# Actual JavaScript/WASM bridge and independent memory-codec fixtures.
# Includes serial production KDFs; run separately from other heavy suites.
../.github/scripts/test-wasm.sh

# CLI package tests, including default binary-regression coverage
go test ./internal/cli

# Opt-in stdin/stdout CLI integration tests
PICOCRYPT_RUN_CLI_INTEGRATION=1 go test ./internal/cli

# Race-sensitive Go work; serialize KDF-heavy packages
CGO_ENABLED=1 go test -tags migrated_fynedo -race -p 1 -timeout 15m ./...
```

## Notes

- On Linux without hardware OpenGL: `LIBGL_ALWAYS_SOFTWARE=1 ./Picocrypt-NG`
- If accessibility bus causes issues: `NO_AT_BRIDGE=1 ./Picocrypt-NG`
