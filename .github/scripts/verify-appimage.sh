#!/usr/bin/env bash
set -euo pipefail
umask 077
ulimit -c 0
export LC_ALL=C
unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT APPIMAGE_EXTRACT_AND_RUN APPDIR
fail() { printf 'AppImage verifier: %s\n' "$*" >&2; exit 2; }
refuse() { printf 'AppImage verifier: %s\n' "$*" >&2; exit 1; }
trap 'exit 2' ERR
[[ $# == 1 ]] || fail 'Usage: verify-appimage.sh APPIMAGE'
for dependency in jq timeout mktemp cp chmod rm dirname awk docker cat grep; do
  command -v "$dependency" >/dev/null || fail "required command not found: $dependency"
done
[[ -f $1 && -r $1 ]] || fail 'input is not a readable regular file'
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
image=$(bash "$script_dir/install-appimage-verifier.sh") || fail 'verifier setup failed'
[[ $image =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'installer did not return an image ID'
expected=$(jq -er '.expected_fingerprint' "$script_dir/../toolchains/appimage-verifier/manifest.json")
work=$(mktemp -d)
cid=
cleanup() {
  local failed=0
  if [[ -z $cid && -f $work/container.id ]]; then cid=$(cat "$work/container.id"); fi
  if [[ -n $cid ]]; then timeout --kill-after=2s 10s docker rm --force "$cid" >/dev/null || failed=1; fi
  rm -rf -- "$work" || failed=1
  cid=
  return "$failed"
}
finish() { local code=$?; cleanup || code=2; exit "$code"; }
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cp -- "$1" "$work/input.AppImage"
chmod 444 "$work/input.AppImage"
cid=$(docker create --cidfile "$work/container.id" --pull never --entrypoint /usr/local/bin/validate --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65532:65532 --pids-limit 64 --memory 512m --memory-swap 512m --cpus 1 --ulimit core=0 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=65532,gid=65532 --mount "type=bind,src=$work/input.AppImage,dst=/input/AppImage,readonly" "$image" /input/AppImage)
client_status=0
timeout --kill-after=5s 30s docker start --attach "$cid" > "$work/report" 2>&1 || client_status=$?
if [[ $client_status == 124 || $client_status == 137 ]]; then
  cat "$work/report" >&2
  fail 'validator timed out'
fi
state=$(docker inspect "$cid" --format '{{.State.Running}} {{.State.OOMKilled}} {{.State.ExitCode}} {{.State.StartedAt}}') || fail 'cannot inspect validator outcome'
read -r running oom process_status started <<< "$state"
[[ $running == false && $oom == false && $started != 0001-* ]] || fail 'validator did not run and stop normally'
if [[ $client_status != 0 || $process_status != 0 ]]; then
  cat "$work/report" >&2
  if [[ $client_status == 1 && $process_status == 1 ]] && ! grep -Fxq 'unexpected error' "$work/report" && grep -Eq '^(Validation result: (validation failed|validation yielded warning state)|Error: AppImage not signed)$' "$work/report"; then
    refuse 'signature or format refused'
  fi
  fail 'validator tool or runtime failed'
fi
signers=$(awk '/^Signatures found with key fingerprints: / { print }' "$work/report")
[[ $signers == "Signatures found with key fingerprints: $expected" ]] || refuse "verified signer does not match expected $expected"
cleanup || fail 'owned container cleanup failed'
trap - EXIT
printf 'Verified AppImage signer: %s\n' "$expected"
