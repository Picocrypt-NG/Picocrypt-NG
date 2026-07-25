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

Download from [go.dev/dl](https://go.dev/dl/) or use your package manager. Go 1.26.0 or newer; release builds use Go 1.26.5.

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

The browser WASM build supports in-memory single-file encryption and decryption on modern browsers, including mobile devices. In this repository, the WASM bridge caps inputs at 1 GiB and supports comments, Paranoid mode, Reed-Solomon payload protection, force decrypt, deniability, and decryption of legacy v2 keyfile volumes; legacy v1 keyfile volumes remain unsupported by this bridge. Picocrypt-NG 2.19 encryption is password-only: any non-empty keyfile list is rejected with error code 12, an empty ordinary encryption password with code 13, and an empty deniability password with code 11. Supported legacy v1/v2 reads remain available; a well-formed unknown major returns the existing unsupported-feature code before KDF work. The browser workflow is still intentionally non-streaming and single-file oriented; folder workflows, split volumes, and large streaming jobs remain desktop/CLI/native-app features. Go-owned byte buffers are wiped best-effort after use, but JavaScript engine copies and garbage-collected runtime copies cannot be guaranteed wiped. The hosted website is a separately deployed consumer and must map the 2.19 error contract; this repository's bridge tests do not by themselves verify that deployment.

## Test

```bash
# Fast default local suite
go test -tags migrated_fynedo ./...

# Golden compatibility checks with production KDF
go test -count=1 -run '^TestGolden' ./internal/volume

# Actual JavaScript/WASM bridge guard (Go 1.26 runtime uses one OS thread)
GOMAXPROCS=1 GOOS=js GOARCH=wasm go test -count=1 \
  -exec="$(go env GOROOT)/lib/wasm/go_js_wasm_exec" \
  -run '^(TestInvalidArgErrorCodeContract|TestBridgeRejectsV2KeyfileWriteBeforeRandomness)$' ./cmd/wasm

# CLI package tests, including default binary-regression coverage
go test ./internal/cli

# Opt-in stdin/stdout CLI integration tests
PICOCRYPT_RUN_CLI_INTEGRATION=1 go test ./internal/cli
```

## Notes

- On Linux without hardware OpenGL: `LIBGL_ALWAYS_SOFTWARE=1 ./Picocrypt-NG`
- If accessibility bus causes issues: `NO_AT_BRIDGE=1 ./Picocrypt-NG`
