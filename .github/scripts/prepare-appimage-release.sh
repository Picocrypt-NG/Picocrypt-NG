#!/usr/bin/env bash
set -euo pipefail

work=${1:?prepared Go directory}
toolchain=.github/toolchains/appimage-release
lock=$toolchain/manifest.json
base=$(jq -er 'select(.schema_version == 1) | .base_image' "$lock")
snapshot=$(jq -er '.snapshot' "$lock")
glibc=$(jq -er '.glibc | select(. == "2.35")' "$lock")
roots=$(jq -er '.root_packages | select(type == "array" and length > 0
    and all(.[]; test("^[a-z0-9.+-]+$"))) | .[]' "$lock")
mapfile -t root_packages <<< "$roots"

test -x "$work/go/bin/go"
materials=$(bash .github/scripts/release-materials.sh build-appimage.yml amd64)
materials=$(jq -ce --arg go "$(<"$work/archive.sha256")" 'select(.go_sha256 == $go)' \
    <<<"$materials")

bash .github/scripts/prepare-debian-release-image.sh amd64 "$work" "$base" "$snapshot" \
    "$toolchain/os-packages-amd64.lock"
image=$(<"$work/image.id")
docker run --rm --platform linux/amd64 --pull never --network none "$image" \
    bash -euo pipefail -c '
        expected_glibc=$1
        shift
        test "$(getconf GNU_LIBC_VERSION)" = "glibc $expected_glibc"
        for package in "$@"; do
            test "$(dpkg-query --show --showformat='"'"'${Status}'"'"' "$package")" = "install ok installed"
        done
    ' _ "$glibc" "${root_packages[@]}"
printf '%s\n' "$materials" > "$work/appimage-materials.json"
printf 'RELEASE_APPIMAGE_IMAGE=%s\n' "$image" >> "$GITHUB_ENV"
