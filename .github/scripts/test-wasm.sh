#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../../src"

# Serialize the real 1-GiB KDFs. The native writer is checked against frozen
# independent bytes; the actual JS bridge checks credentials and publication.
CGO_ENABLED=0 go test -v -count=1 -p 1 -tags pcv3_production_kdf \
  -timeout 5m -run '^TestMemory' ./internal/pcv3operation/internal/pcv3

# Go's js/wasm runtime supports one OS thread, including when tests run in Node.
GOMAXPROCS=1 CGO_ENABLED=0 GOOS=js GOARCH=wasm go test -v -count=1 -p 1 \
  -tags pcv3_production_kdf -timeout 30m \
  -exec="$(go env GOROOT)/lib/wasm/go_js_wasm_exec" \
  ./cmd/wasm

# The facade package also contains native filesystem operation tests. Only
# its js/wasm browser facade tests belong in this runtime.
GOMAXPROCS=1 CGO_ENABLED=0 GOOS=js GOARCH=wasm go test -v -count=1 -p 1 \
  -timeout 2m -exec="$(go env GOROOT)/lib/wasm/go_js_wasm_exec" \
  -run '^TestBrowser' ./internal/pcv3operation

GOMAXPROCS=1 CGO_ENABLED=0 GOOS=js GOARCH=wasm go test -v -count=1 -p 1 \
  -timeout 5m -exec="$(go env GOROOT)/lib/wasm/go_js_wasm_exec" \
  -run '^TestWASMTamperedPaddingFlagFailsHeaderAuthentication$' ./internal/wasm
