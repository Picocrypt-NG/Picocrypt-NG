#!/usr/bin/env bash
set -euo pipefail

scripts=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
toolchains=$scripts/../toolchains
signer=$toolchains/appimage-signer
verifier=$toolchains/appimage-verifier
mode=${1:-}
bundle=${2:?usage: prepare-appimage-signer.sh fetch|verify|build BUNDLE [WORK]}

fail() { printf 'AppImage signing tools: %s\n' "$1" >&2; exit 1; }

verify_digest() {
    local file=$1 expected=$2
    [[ -f $file && ! -L $file && $expected =~ ^[a-f0-9]{64}$ ]] || fail 'missing file or invalid digest'
    printf '%s  %s\n' "$expected" "$file" | sha256sum --check --strict --status || fail 'tool digest mismatch'
}

transfer() {
    local name=$1 expected=$2 url=$3
    if [[ $mode == fetch ]]; then
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
            --retry 3 --connect-timeout 20 --max-time 300 --output "$bundle/$name" "$url"
    fi
    verify_digest "$bundle/$name" "$expected"
}

case "$mode" in
    fetch) mkdir -- "$bundle"; mkdir -- "$bundle/packages" ;;
    verify|build) ;;
    *) fail 'invalid command' ;;
esac

verify_digest "$verifier/os-packages.lock.json" "$(jq -er '.packages_sha256' "$verifier/manifest.json")"
for name in appimagetool runtime; do
    record=$(jq -er --arg name "$name" '.tools[] | select(.name == $name) | [.sha256, .url] | @tsv' "$toolchains/appimage-build.json")
    IFS=$'\t' read -r digest url <<<"$record"
    transfer "$name" "$digest" "$url"
done

packages=(gpg gpg-agent gpgconf libassuan0 libksba8 libnpth0 libreadline8 libsqlite3-0 pinentry-curses readline-common)
declare -a package_files=()
for name in "${packages[@]}"; do
    record=$(jq -er --arg name "$name" '
        .packages[] | select((.url | split("/") | last) | startswith($name + "_"))
        | select(.url | test("^https://snapshot[.]ubuntu[.]com/ubuntu/[0-9]{8}T[0-9]{6}Z/pool/"))
        | [.sha256, .url] | @tsv
    ' "$verifier/os-packages.lock.json")
    IFS=$'\t' read -r digest url <<<"$record"
    [[ $digest =~ ^[a-f0-9]{64}$ ]] || fail 'invalid package digest'
    file=packages/$digest.deb
    transfer "$file" "$digest" "$url"
    package_files+=("$bundle/$file")
done

snapshot=$(jq -er '.snapshot | select(test("^[0-9]{8}T[0-9]{6}Z$"))' "$signer/os-packages.lock.json")
extra_packages=$(jq -er '.packages[] | [.sha256, .path] | @tsv' "$signer/os-packages.lock.json")
while IFS=$'\t' read -r digest path; do
    [[ $digest =~ ^[a-f0-9]{64}$ && $path =~ ^pool/main/f/file/[a-zA-Z0-9.+_-]+[.]deb$ ]] || fail 'invalid file package lock'
    file=packages/$digest.deb
    transfer "$file" "$digest" "https://snapshot.ubuntu.com/ubuntu/$snapshot/$path"
    package_files+=("$bundle/$file")
done <<<"$extra_packages"

[[ $mode == build ]] || exit 0

work=${3:?build requires a fresh work directory}
mkdir -- "$work"
work=$(cd "$work" && pwd)
bundle=$(cd "$bundle" && pwd)
mkdir -- "$work/packages"
cp -- "${package_files[@]}" "$work/packages/"
install -m 755 -- "$bundle/appimagetool" "$work/appimagetool"
cp -- "$bundle/runtime" "$signer/Dockerfile" "$signer/sign.sh" "$work/"
base=$(jq -er '.base_image | select(test("^ubuntu@sha256:[a-f0-9]{64}$"))' "$verifier/manifest.json")
docker pull --platform linux/amd64 "$base" >&2
docker build --platform linux/amd64 --network none --pull=false --iidfile "$work/image.id" \
    --build-arg "BASE_IMAGE=$base" "$work" >&2
image=$(<"$work/image.id")
[[ $image =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'build did not return a local image ID'
