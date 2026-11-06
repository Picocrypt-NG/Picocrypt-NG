#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "${BASH_SOURCE[0]}")/../.."
uv run --no-project python .github/scripts/hk-integration-test.py
uv run --no-project python .github/scripts/appimage-verifier-test.py AppImageArchiveTests
cd src
helpers=(../.github/scripts/production-kdf.go ../.github/scripts/production-kdf_test.go)
host_os=$(go env GOHOSTOS)
host_arch=$(go env GOHOSTARCH)
if [[ $host_os == linux ]]; then
  GOOS=$host_os GOARCH=$host_arch CGO_ENABLED=1 go test -count=1 "${helpers[@]}"
  GOOS=$host_os GOARCH=$host_arch CGO_ENABLED=1 go test -race -count=1 "${helpers[@]}"
else
  compile_dir=$(mktemp -d)
  trap 'rm -rf -- "$compile_dir"' EXIT
  GOOS=linux GOARCH=$host_arch CGO_ENABLED=0 go test -c -o "$compile_dir/production-kdf.test" "${helpers[@]}"
  echo "Linux helper compile check passed. Helper unit and race tests NOT RUN on this host; Linux is required."
fi
