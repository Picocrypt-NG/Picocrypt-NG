#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
fail() { printf 'AppImage verifier: %s\n' "$*" >&2; exit 1; }
[[ $# == 0 ]] || fail 'Usage: install-appimage-verifier.sh'
for dependency in jq curl sha256sum mktemp cp chmod mv rm mkdir dirname uname docker cat; do
  command -v "$dependency" >/dev/null || fail "required command not found: $dependency"
done
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'Linux x86_64 is required'
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
toolchain="$script_dir/../toolchains/appimage-verifier"
manifest="$toolchain/manifest.json"
jq -e '.schema_version==2 and (.base_image|test("^ubuntu@sha256:[0-9a-f]{64}$")) and all(.sources_sha256,.packages_sha256,.patch_sha256; test("^[0-9a-f]{64}$")) and (.expected_fingerprint|test("^[0-9A-F]{40}$"))' "$manifest" >/dev/null || fail 'invalid or incomplete manifest'
check_hash() { local actual; actual=$(sha256sum < "$1"); [[ ${actual%% *} == "$2" ]] || fail 'checksum mismatch'; }
check_hash "$toolchain/sources.lock.json" "$(jq -r .sources_sha256 "$manifest")"
check_hash "$toolchain/os-packages.lock.json" "$(jq -r .packages_sha256 "$manifest")"
check_hash "$toolchain/nul-terminate-mkdtemp-template.patch" "$(jq -r .patch_sha256 "$manifest")"
jq -e '.schema_version==1 and ([.archives[].name]|sort)==["appimageupdate","args","cpr","libappimage","zsync2"] and all(.archives[]; .file==(.name+".tar.gz") and (.sha256|test("^[0-9a-f]{64}$")) and (.commit|test("^[0-9a-f]{40}$")) and .url==("https://codeload.github.com/"+.repository+"/tar.gz/"+.commit))' "$toolchain/sources.lock.json" >/dev/null || fail 'invalid source lock'
jq -e '.schema_version==1 and (.packages|length)>0 and all(.packages[]; (.sha256|test("^[0-9a-f]{64}$")) and .file==(.sha256+".deb") and (.url|test("^https://snapshot[.]ubuntu[.]com/ubuntu/[0-9]{8}T[0-9]{6}Z/pool/")))' "$toolchain/os-packages.lock.json" >/dev/null || fail 'invalid package lock'
cache_root="${XDG_CACHE_HOME:-${HOME:?HOME or XDG_CACHE_HOME is required}/.cache}/picocrypt-ng/appimage-verifier/blobs"
mkdir -p "$cache_root"
chmod 700 "$cache_root"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/inputs"
fetch() {
  local filename=$1 expected=$2 url=$3 blob="$cache_root/$2.blob"
  if [[ -e $blob || -L $blob ]]; then
    [[ -f $blob && ! -L $blob ]] || fail 'cached blob is not a regular file'
    check_hash "$blob" "$expected"
  else
    curl --fail --location --proto '=https' --proto-redir '=https' --silent --show-error --connect-timeout 20 --max-time 180 --retry 2 --retry-max-time 180 --output "$work/download" "$url" || fail "cannot download pinned input $filename from $url"
    check_hash "$work/download" "$expected"
    chmod 600 "$work/download"
    mv -T "$work/download" "$blob"
  fi
  cp --reflink=auto "$blob" "$work/inputs/$filename"
  printf '%s  inputs/%s\n' "$expected" "$filename" >> "$work/SHA256SUMS"
}
while IFS=$'\t' read -r file digest url; do fetch "$file" "$digest" "$url"; done < <(jq -r '.archives[]|[.file,.sha256,.url]|@tsv' "$toolchain/sources.lock.json")
while IFS=$'\t' read -r file digest url; do fetch "$file" "$digest" "$url"; done < <(jq -r '.packages[]|[.file,.sha256,.url]|@tsv' "$toolchain/os-packages.lock.json")
cp "$toolchain/nul-terminate-mkdtemp-template.patch" "$work/inputs/"
printf '%s  inputs/nul-terminate-mkdtemp-template.patch\n' "$(jq -r .patch_sha256 "$manifest")" >> "$work/SHA256SUMS"
cp "$toolchain/"{Dockerfile,build.sh,manifest.json,sources.lock.json,os-packages.lock.json} "$work/"
base=$(jq -r .base_image "$manifest")
IFS= read -r first_line < "$work/Dockerfile"
[[ $first_line == "FROM $base AS build" ]] || fail 'base image pin does not match recipe'
docker image inspect "$base" >/dev/null 2>&1 || docker pull --platform linux/amd64 "$base" >&2
docker build --platform linux/amd64 --pull=false --network none --iidfile "$work/image.id" --file "$work/Dockerfile" "$work" >&2
image=$(cat "$work/image.id")
[[ $image =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'build did not return an image ID'
printf '%s\n' "$image"
