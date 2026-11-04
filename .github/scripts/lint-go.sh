#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )) || [[ ! $1 =~ ^(json|sarif)$ ]]; then
    echo "usage: $0 json|sarif" >&2
    exit 2
fi
format=$1

cd "$(dirname -- "$0")/../../src"
path_options=()
if [[ $format == sarif ]]; then
    path_options=(--path-mode abs)
fi

exec golangci-lint run --build-tags migrated_fynedo --show-stats=false \
    --output.text.path /dev/null "${path_options[@]}" \
    "--output.${format}.path" stdout ./...
