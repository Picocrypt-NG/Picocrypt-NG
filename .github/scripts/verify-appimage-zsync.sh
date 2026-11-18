#!/usr/bin/env bash
set -euo pipefail

image=${1:?usage: verify-appimage-zsync.sh IMAGE_ID APPIMAGE}
appimage=${2:?missing AppImage}
scripts=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
input=$(cd "$(dirname -- "$appimage")" && pwd -P)
filename=$(basename -- "$appimage")
[[ $filename =~ ^Picocrypt-NG-[0-9][0-9.A-Za-z-]*-x86_64\.AppImage$ ]]
[[ -f $input/$filename && ! -L $input/$filename && -s $input/$filename ]]
[[ -f $input/$filename.zsync && ! -L $input/$filename.zsync && -s $input/$filename.zsync ]]

output=$(mktemp -d)
trap 'rm -r -- "$output"' EXIT
bash "$scripts/run-release-signing-container.sh" "$image" "$input" "$output" regenerate-zsync "$filename" </dev/null
if ! cmp -s -- "$input/$filename.zsync" "$output/$filename.zsync"; then
    printf '%s\n' 'AppImage zsync metadata or checksums do not match the signed artifact.' >&2
    exit 1
fi
printf '%s\n' 'Verified AppImage zsync metadata and all block checksums.'
