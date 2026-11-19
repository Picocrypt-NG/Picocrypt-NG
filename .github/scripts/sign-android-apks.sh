#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
ulimit -c 0

image=${1:?usage: sign-android-apks.sh IMAGE_ID INPUT_DIR OUTPUT_DIR}
input=${2:?missing input directory}
target=${3:?missing output directory}
scripts=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[[ $image =~ ^sha256:[a-f0-9]{64}$ ]]
input=$(cd "$input" && pwd -P)

: "${ANDROID_KEYSTORE_BASE64:?missing Android keystore}"
: "${ANDROID_KEYSTORE_PASSWORD:?missing Android keystore password}"
: "${ANDROID_KEY_PASSWORD:?missing Android key password}"
: "${ANDROID_KEY_ALIAS:?missing Android key alias}"
abis=(armeabi-v7a arm64-v8a x86 x86_64 universal)
for abi in "${abis[@]}"; do
    apk=$input/app-$abi-release-unsigned.apk
    [[ -f $apk && ! -L $apk && -s $apk ]]
done

target_parent=$(cd "$(dirname -- "$target")" && pwd -P)
target=$target_parent/$(basename -- "$target")
[[ ! -e $target && ! -L $target ]]
output=$(mktemp -d -- "$target_parent/.android-signed.XXXXXXXX")
trap 'test ! -e "$output" || rm -rf -- "$output"' EXIT

cancel_signer() {
    kill -TERM "$signer" 2>/dev/null || true
    wait "$signer" || true
    exit "$1"
}

env -u ANDROID_KEYSTORE_BASE64 -u ANDROID_KEYSTORE_PASSWORD -u ANDROID_KEY_PASSWORD -u ANDROID_KEY_ALIAS \
    bash "$scripts/run-release-signing-container.sh" "$image" "$input" "$output" \
    < <(printf '%s\0' "$ANDROID_KEYSTORE_BASE64" "$ANDROID_KEYSTORE_PASSWORD" "$ANDROID_KEY_PASSWORD" "$ANDROID_KEY_ALIAS") \
    >/dev/null 2>&1 &
signer=$!
trap 'cancel_signer 130' INT
trap 'cancel_signer 143' TERM
if ! wait "$signer"; then
    printf '%s\n' 'APK signing failed. Private signing diagnostics were withheld.' >&2
    exit 1
fi

shopt -s nullglob dotglob
files=("$output"/*)
(( ${#files[@]} == ${#abis[@]} ))
for abi in "${abis[@]}"; do
    apk=$output/app-$abi-release.apk
    [[ -f $apk && ! -L $apk && -s $apk ]]
done
mv -T --no-clobber -- "$output" "$target"
[[ ! -e $output ]]
