#!/usr/bin/env bash
set -euo pipefail

image=${1:?missing verified signing image ID}
input=${2:?missing input directory}
output=${3:?missing output directory}
shift 3
[[ $image =~ ^sha256:[a-f0-9]{64}$ ]]
uid=$(id -u)
gid=$(id -g)
[[ $uid != 0 ]]

state=$(mktemp -d)
cidfile=$state/container.id
finish() {
    local status=$? cid
    if [[ -s $cidfile ]]; then
        cid=$(<"$cidfile")
        if ! timeout --kill-after=2s 10s docker rm --force "$cid" >/dev/null; then status=1; fi
        unlink "$cidfile" || status=1
    fi
    rmdir "$state" || status=1
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cid=$(docker create --cidfile "$cidfile" --interactive --pull never --network none --read-only --log-driver none \
    --user "$uid:$gid" --cap-drop ALL --security-opt no-new-privileges \
    --ulimit core=0 --pids-limit 128 --memory 2g --memory-swap 2g \
    --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=$uid,gid=$gid" \
    --mount "type=bind,src=$input,dst=/input,readonly" \
    --mount "type=bind,src=$output,dst=/output" "$image" "$@")
[[ $cid =~ ^[a-f0-9]{64}$ ]]
docker start --attach --interactive "$cid" <&0 &
wait "$!"
