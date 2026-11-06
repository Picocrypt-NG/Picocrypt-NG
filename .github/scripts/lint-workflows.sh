#!/usr/bin/env bash
set -euo pipefail

format=text
if (( $# != 0 )); then
    if (( $# != 2 )) || [[ $1 != --format || ! $2 =~ ^(text|sarif)$ ]]; then
        echo "usage: $0 [--format text|sarif]" >&2
        exit 2
    fi
    format=$2
fi

cd "$(dirname -- "$0")/../.."
shopt -s nullglob globstar
workflows=(.github/workflows/*.yml .github/workflows/*.yaml)
actions=(.github/actions/**/action.yml .github/actions/**/action.yaml)
if (( ${#workflows[@]} == 0 )); then
    echo 'No GitHub Actions workflows found' >&2
    exit 1
fi

exec jactionlint --no-online --no-baseline --profile default \
    --shellcheck=shellcheck --ruff=ruff --format "$format" "${workflows[@]}" "${actions[@]}"
