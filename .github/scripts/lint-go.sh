#!/usr/bin/env bash
set -euo pipefail

if (( $# < 1 || $# > 2 )) || [[ ! $1 =~ ^(json|sarif)$ || ${2-tooling} != tooling ]]; then
    echo "usage: $0 json|sarif [tooling]" >&2
    exit 2
fi
format=$1

cd "$(dirname -- "$0")/../../src"
path_options=()
if [[ $format == sarif ]]; then
    path_options=(--path-mode abs)
fi

targets=(./...)
config_options=(--build-tags migrated_fynedo)
if (( $# == 2 )); then
    targets=(../.github/scripts/production-kdf.go ../.github/scripts/production-kdf_test.go)
    config_options=(--no-config --default standard)
    export GOOS=linux CGO_ENABLED=0
fi

exec golangci-lint run "${config_options[@]}" --show-stats=false \
    --output.text.path /dev/null "${path_options[@]}" \
    "--output.${format}.path" stdout "${targets[@]}"
