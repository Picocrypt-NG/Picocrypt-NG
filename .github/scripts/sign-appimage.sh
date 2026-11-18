#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
ulimit -c 0

image=${1:?usage: sign-appimage.sh IMAGE_ID APPDIR OUTPUT_DIR FINGERPRINT NAME UPDATE_INFO}
input=${2:?missing AppDir}
target=${3:?missing output directory}
fingerprint=${4:?missing expected fingerprint}
filename=${5:?missing output name}
update=${6:?missing update information}
scripts=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[[ $image =~ ^sha256:[a-f0-9]{64}$ && $fingerprint =~ ^[A-F0-9]{40}$ ]]
[[ $filename =~ ^Picocrypt-NG-[0-9][0-9.A-Za-z-]*-x86_64\.AppImage$ ]]
: "${GPG_PRIVATE_KEY:?missing AppImage private key}"
: "${APPIMAGETOOL_SIGN_PASSPHRASE?missing AppImage passphrase}"

input=$(cd "$input" && pwd -P)
target_parent=$(cd "$(dirname -- "$target")" && pwd -P)
target=$target_parent/$(basename -- "$target")
[[ ! -e $target && ! -L $target ]]
output=$(mktemp -d -- "$target_parent/.appimage-signed.XXXXXXXX")
trap 'test ! -e "$output" || rm -rf -- "$output"' EXIT

cancel_signer() {
    kill -TERM "$signer" 2>/dev/null || true
    wait "$signer" || true
    exit "$1"
}

env -u GPG_PRIVATE_KEY -u APPIMAGETOOL_SIGN_PASSPHRASE \
    bash "$scripts/run-release-signing-container.sh" "$image" "$input" "$output" \
    "$fingerprint" "$filename" "$update" \
    < <(printf '%s\0' "$GPG_PRIVATE_KEY" "$APPIMAGETOOL_SIGN_PASSPHRASE") \
    >/dev/null 2>&1 &
signer=$!
trap 'cancel_signer 130' INT
trap 'cancel_signer 143' TERM
if ! wait "$signer"; then
    printf '%s\n' 'AppImage signing failed. Private signing diagnostics were withheld.' >&2
    exit 1
fi

shopt -s nullglob dotglob
files=("$output"/*)
(( ${#files[@]} == 2 ))
for artifact in "$filename" "$filename.zsync"; do
    [[ -f $output/$artifact && ! -L $output/$artifact && -s $output/$artifact ]]
done
mv -T --no-clobber -- "$output" "$target"
[[ ! -e $output ]]
