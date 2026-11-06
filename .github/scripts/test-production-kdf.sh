#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo "The complete native production-KDF lane requires Linux" >&2
  exit 2
fi
if (( $# != 0 )); then
  echo "usage: $0 (no test selectors or arguments)" >&2
  exit 2
fi
if [[ -n ${GOFLAGS:-} ]]; then
  echo "Unset GOFLAGS before running the complete production-KDF lane" >&2
  exit 2
fi
for name in "${!PICOCRYPT_@}"; do
  case "$name" in
    PICOCRYPT_RUN_CLI_INTEGRATION|PICOCRYPT_RUN_RECOVERY_LARGE|PICOCRYPT_PRODUCTION_KDF_REPORT_DIR) continue ;;
  esac
  if [[ -n ${!name:-} ]]; then
    echo "Unset unsupported parent environment control $name before the complete production-KDF lane" >&2
    exit 2
  fi
done

cd "$(dirname -- "${BASH_SOURCE[0]}")/../../src"
export CGO_ENABLED=1 PICOCRYPT_RUN_CLI_INTEGRATION=1
ulimit -c 0
runner_dir=$(mktemp -d)
runner_pid=
trap 'rm -rf -- "$runner_dir"' EXIT
interrupt() {
  trap '' INT TERM
  if [[ -n $runner_pid ]]; then
    kill -TERM "$runner_pid" 2>/dev/null || true
    wait "$runner_pid" || true
  fi
  exit "$1"
}
trap 'interrupt 130' INT
trap 'interrupt 143' TERM

if [[ $(timeout --version) != *"GNU coreutils"* ]]; then
  echo "GNU timeout is required to bound production-KDF bootstrap" >&2
  exit 2
fi

timeout --kill-after=2s 30s go env GOFLAGS > "$runner_dir/go-flags" &
runner_pid=$!
wait "$runner_pid"
runner_pid=
effective_go_flags=$(< "$runner_dir/go-flags")
if [[ -n $effective_go_flags ]]; then
  echo "Effective GOFLAGS must be empty, including saved go env configuration" >&2
  exit 2
fi

timeout --kill-after=2s 5m go build -o "$runner_dir/production-kdf" ../.github/scripts/production-kdf.go &
runner_pid=$!
wait "$runner_pid"
runner_pid=
"$runner_dir/production-kdf" &
runner_pid=$!
wait "$runner_pid"
