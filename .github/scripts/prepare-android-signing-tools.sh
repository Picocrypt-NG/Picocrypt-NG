#!/usr/bin/env bash
set -euo pipefail

scripts=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
toolchain=$scripts/../toolchains/android-signer
lock=$toolchain/manifest.json
mode=${1:-}
bundle=${2:?usage: prepare-android-signing-tools.sh fetch|verify|build BUNDLE [WORK]}

fail() { printf 'Android signing tools: %s\n' "$1" >&2; exit 1; }

verify_digest() {
    local file=$1 expected=$2
    [[ -f $file && ! -L $file && $expected =~ ^[a-f0-9]{64}$ ]] || fail 'missing file or invalid digest'
    printf '%s  %s\n' "$expected" "$file" | sha256sum --check --strict --status || fail 'tool digest mismatch'
}

sdk_digest=$(jq -er '.sdk.sha256' "$lock")
jdk_digest=$(jq -er '.jdk.sha256' "$lock")
case "$mode" in
    fetch)
        mkdir -- "$bundle"
        for item in sdk jdk; do
            case "$item" in
                sdk) name=build-tools.zip ;;
                jdk) name=temurin.tar.gz ;;
            esac
            url=$(jq -er --arg item "$item" '.[$item].url' "$lock")
            curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
                --retry 3 --connect-timeout 20 --max-time 300 --output "$bundle/$name" "$url"
        done
        ;;
    verify|build) ;;
    *) fail 'invalid command' ;;
esac

verify_digest "$bundle/build-tools.zip" "$sdk_digest"
verify_digest "$bundle/temurin.tar.gz" "$jdk_digest"
[[ $mode == build ]] || exit 0

work=${3:?build requires a fresh work directory}
mkdir -- "$work"
work=$(cd "$work" && pwd)
mkdir -p "$work/extracted" "$work/sdk/build-tools" "$work/image/java"
unzip -q "$bundle/build-tools.zip" -d "$work/extracted"
mv -- "$work/extracted/android-16" "$work/sdk/build-tools/36.0.0"
rmdir -- "$work/extracted"
sdk=$work/sdk/build-tools/36.0.0
for tool in aapt apksigner lib/apksigner.jar zipalign; do
    verify_digest "$sdk/$tool" "$(jq -er --arg tool "$tool" '.sdk.files[$tool]' "$lock")"
done
tar -xzf "$bundle/temurin.tar.gz" -C "$work/image/java" --strip-components=1 --no-same-owner --no-same-permissions
cp -- "$sdk/lib/apksigner.jar" "$scripts/AndroidApkSigner.java" "$work/image/"
cp -- "$toolchain/Dockerfile" "$toolchain/sign.sh" "$work/image/"

base=$(jq -er '.base_image | select(test("^ubuntu@sha256:[a-f0-9]{64}$"))' "$lock")
docker pull --platform linux/amd64 "$base" >&2
docker build --platform linux/amd64 --network none --pull=false --iidfile "$work/image.id" \
    --build-arg "BASE_IMAGE=$base" "$work/image" >&2
image=$(<"$work/image.id")
[[ $image =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'build did not return a local image ID'
