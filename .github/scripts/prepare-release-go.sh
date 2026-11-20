#!/usr/bin/env bash
set -euo pipefail

platform=${1:?expected Go host platform}
work=${2:?fresh release Go directory}
lock=.github/toolchains/release-go.json
case "$(uname -s):$(uname -m):$platform" in
    Linux:x86_64:linux-amd64|Linux:aarch64:linux-arm64|Darwin:arm64:darwin-arm64) ;;
    *) printf 'Release Go host does not match %s\n' "$platform" >&2; exit 1 ;;
esac

version=$(jq -er '.version | select(test("^go[0-9]+[.][0-9]+[.][0-9]+$"))' "$lock")
expected=$(jq -er --arg platform "$platform" '.archives[$platform] | select(test("^[0-9a-f]{64}$"))' "$lock")
mkdir -m 0700 -- "$work"
mkdir -m 0700 -- "$work/home" "$work/modcache" "$work/buildcache"
archive="$work/$version.$platform.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --retry 3 --connect-timeout 20 --max-time 300 --output "$archive" "https://go.dev/dl/$version.$platform.tar.gz"
actual=$(shasum -a 256 -b "$archive")
test "${actual%% *}" = "$expected"
tar -xzf "$archive" -C "$work"

export GOROOT="$work/go"
export PATH="$GOROOT/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export GOENV=off GOTOOLCHAIN=local GOWORK=off
export GOFLAGS=-mod=readonly GOMODCACHE="$work/modcache" GOCACHE="$work/buildcache"
test "$(go env GOVERSION)" = "$version"
test "$(go env GOHOSTOS)-$(go env GOHOSTARCH)" = "$platform"
git diff --exit-code HEAD -- src/go.mod src/go.sum
GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go -C src mod download
GOPROXY=off go -C src mod verify
git diff --exit-code HEAD -- src/go.mod src/go.sum

printf '%s\n' "$expected" > "$work/archive.sha256"
printf '%s\n' "$work/go/bin" >> "$GITHUB_PATH"
printf 'GOENV=off\nGOTOOLCHAIN=local\nGOWORK=off\nGOFLAGS=-mod=readonly\nGOPROXY=off\nGOROOT=%s\nGOMODCACHE=%s\nGOCACHE=%s\n' \
    "$GOROOT" "$GOMODCACHE" "$GOCACHE" >> "$GITHUB_ENV"
