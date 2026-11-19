#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || ! $1 =~ ^[0-9]+$ || ! $2 =~ ^[1-9][0-9]*$ ]] || (( $1 >= $2 )); then
  echo "usage: $0 <zero-based shard index> <shard count>" >&2
  exit 2
fi
shard_index=$1
shard_count=$2
cd "$(dirname "$0")/../../src"
if [[ "$(go env GOOS)/$(go env GOARCH)/$(go env CGO_ENABLED)" != darwin/arm64/1 ]]; then
  echo "This lane requires native macOS ARM64 with CGO enabled" >&2
  exit 1
fi

# Observe the real admission inputs for the failing legacy sequence. The
# overlay applies only to this test and is excluded from the application build.
legacy_package=Picocrypt-NG/internal/volume
legacy_parent=TestGoldenCompressedDecryption
diagnostics=$(mktemp -d)
trap 'rm -rf -- "$diagnostics"' EXIT
snapshot="$PWD/internal/pcv3operation/internal/pcv3resource/snapshot_darwin.go"
awk '
  $0 == "\treturn kdfSnapshotFromDarwinFacts(facts)" {
    matches++
    print "\tsnapshot := kdfSnapshotFromDarwinFacts(facts)"
    print "\tprintln(\"Darwin KDF bytes: observed\", facts.observed, \"free\", facts.freePages * facts.pageSize,"
    print "\t\t\"inactive\", facts.inactivePages * facts.pageSize, \"internal\", facts.internalPages * facts.pageSize,"
    print "\t\t\"footprint\", facts.physicalFootprint, \"resident\", facts.residentBytes,"
    print "\t\t\"reusable\", facts.reusableBytes, \"released\", facts.releasedHeapBytes,"
    print "\t\t\"available\", snapshot.effectiveAvailable, \"reserve\", snapshot.codeOwnedReserve)"
    print "\treturn snapshot"
    next
  }
  { print }
  END { if (matches != 1) exit 1 }
' "$snapshot" > "$diagnostics/snapshot_darwin.go"
jq -n --arg source "$snapshot" --arg target "$diagnostics/snapshot_darwin.go" \
  '{Replace: {($source): $target}}' > "$diagnostics/overlay.json"
if (( shard_index == 0 )); then
  sudo -n /usr/sbin/purge
  go test -overlay "$diagnostics/overlay.json" -v -count=1 -p 1 -timeout 5m \
    -run "^${legacy_parent}$" "$legacy_package"
fi

# Discover from this checkout so new packages and parents join the required lane.
packages=$(go list ./internal/pcv3operation/... ./internal/app/... ./internal/volume/... | LC_ALL=C sort -u)
parent_index=0
selected=0
while IFS= read -r package; do
  case "$package" in
    Picocrypt-NG/internal/pcv3operation|Picocrypt-NG/internal/pcv3operation/internal/pcv3|Picocrypt-NG/internal/pcv3operation/internal/pcv3recovery|Picocrypt-NG/internal/volume)
      parents=$(go test -p 1 -list '^(Test|Fuzz|Example)' "$package" \
        | sed -n -E '/^(Test|Fuzz|Example)/p' | LC_ALL=C sort)
      if [[ -z "$parents" ]]; then
        echo "No test parents discovered in $package" >&2
        exit 1
      fi
      echo "::group::Discovered parents in $package"
      printf '%s\n' "$parents"
      echo "::endgroup::"
      while IFS= read -r parent; do
        if (( parent_index % shard_count == shard_index )); then
          echo "::group::$package/$parent"
          # Keep real KDFs in fresh native processes on the 7 GB runner. Linux
          # runs the full heavy race suite; pure/platform packages race below.
          sudo -n /usr/sbin/purge
          args=()
          if [[ $package == "$legacy_package" && $parent == "$legacy_parent" ]]; then
            args=(-overlay "$diagnostics/overlay.json")
          fi
          go test "${args[@]}" -v -count=1 -p 1 -timeout 60m -run "^${parent}$" "$package"
          echo "::endgroup::"
          selected=$((selected + 1))
        fi
        parent_index=$((parent_index + 1))
      done <<< "$parents"
      ;;
    *)
      if (( shard_index == 0 )); then
        go test -v -race -count=1 -p 1 -timeout 60m "$package"
      fi
      ;;
  esac
done <<< "$packages"
if (( selected == 0 )); then
  echo "No heavy test parents assigned to shard $shard_index/$shard_count" >&2
  exit 1
fi
echo "Shard $shard_index/$shard_count passed $selected of $parent_index heavy test parents"
