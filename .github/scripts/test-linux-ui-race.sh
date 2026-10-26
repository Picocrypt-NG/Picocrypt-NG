#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../../src"
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
test_binary="$test_dir/ui.test"
CGO_ENABLED=1 go test -c -race -tags migrated_fynedo -p 1 -o "$test_binary" ./internal/ui
cd internal/ui

# Fresh processes keep Fyne caches and race overhead from accumulating across tests.
parents=$("$test_binary" -test.list '^(Test|Fuzz|Example)' \
  | sed -n -E '/^(Test|Fuzz|Example)/p' | LC_ALL=C sort)
if [[ -z "$parents" ]]; then
  echo "No UI race test parents discovered" >&2
  exit 1
fi
echo "::group::Discovered UI race test parents"
printf '%s\n' "$parents"
echo "::endgroup::"

executed=0
failed=0
while IFS= read -r parent; do
  echo "::group::Picocrypt-NG/internal/ui/$parent"
  if ! "$test_binary" -test.run "^${parent}$" -test.count=1 -test.timeout=15m -test.v; then
    failed=$((failed + 1))
  fi
  echo "::endgroup::"
  executed=$((executed + 1))
done <<< "$parents"
echo "UI race parents: $executed executed, $failed failed"
if (( failed > 0 )); then
  exit 1
fi
