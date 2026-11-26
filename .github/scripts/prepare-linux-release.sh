#!/usr/bin/env bash
set -euo pipefail

arch=${1:?expected release architecture}
work=${2:?prepared Go directory}
upx_package=${3:?expected UPX package}
upx_digest=${4:?expected UPX checksum}
[[ $arch == amd64 || $arch == arm64 ]]
test "$(dpkg --print-architecture)" = "$arch"
toolchain=.github/toolchains/linux-release
lock=$toolchain/manifest.json
snapshot=$(jq -er '.snapshot | select(test("^[0-9]{8}T[0-9]{6}Z$"))' "$lock")
upx_version=$(jq -er '.upx_version | select(test("^[0-9]+[.][0-9]+[.][0-9]+$"))' "$lock")
test "$upx_package" = "upx-$upx_version-${arch}_linux"
test "$upx_digest" = "$(jq -er --arg arch "$arch" '.architectures[$arch].upx_sha256 | select(test("^[0-9a-f]{64}$"))' "$lock")"
base=$(jq -er --arg arch "$arch" '.architectures[$arch].base_image | select(test("^ubuntu@sha256:[a-f0-9]{64}$"))' "$lock")

fetch() {
    local url=$1 file=$2 digest=$3
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 3 --connect-timeout 20 --max-time 300 --output "$file" "$url"
    printf '%s  %s\n' "$digest" "$file" | sha256sum --check --strict --status
}

fetch "https://github.com/upx/upx/releases/download/v$upx_version/$upx_package.tar.xz" "$work/upx.tar.xz" "$upx_digest"
tar -xJf "$work/upx.tar.xz" -C "$work" "$upx_package/upx"
test -x "$work/$upx_package/upx"
bash .github/scripts/prepare-debian-release-image.sh "$arch" "$work" "$base" "$snapshot" \
    "$toolchain/os-packages-$arch.lock"
image=$(<"$work/image.id")
materials=$(bash .github/scripts/release-materials.sh build-linux.yml "$arch")
jq -ce --arg go "$(<"$work/archive.sha256")" --arg upx "$upx_digest" \
    'select(.go_sha256 == $go and .upx_sha256 == $upx)' <<<"$materials" > "$work/materials.json"
printf 'RELEASE_LINUX_IMAGE=%s\nRELEASE_UPX=%s\n' "$image" "$work/$upx_package/upx" >> "$GITHUB_ENV"
