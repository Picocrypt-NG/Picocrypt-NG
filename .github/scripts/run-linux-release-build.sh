#!/usr/bin/env bash
set -euo pipefail

work=${RUNNER_TEMP:?}/picocrypt-release-materials
image=${RELEASE_LINUX_IMAGE:?}
[[ $image =~ ^sha256:[a-f0-9]{64}$ ]]
workspace=$(pwd -P)
step=$(realpath "${1:?workflow step script}")
arch=$(dpkg --print-architecture)

exec docker run --rm --init --pull never --network none --platform "linux/$arch" --cap-drop ALL \
    --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
    --mount "type=bind,source=$workspace,target=$workspace" --workdir "$workspace" \
    --mount "type=bind,source=$work/go,target=$work/go,readonly" \
    --mount "type=bind,source=$work/modcache,target=$work/modcache,readonly" \
    --mount "type=bind,source=$work/buildcache,target=$work/buildcache" \
    --mount "type=bind,source=$work/home,target=$work/home" \
    --mount "type=bind,source=${RELEASE_UPX:?},target=$RELEASE_UPX,readonly" \
    --mount "type=bind,source=$step,target=/workflow-step.sh,readonly" \
    --env "HOME=$work/home" --env "PATH=$work/go/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    --env GOENV=off --env GOTOOLCHAIN=local --env GOWORK=off --env GOFLAGS=-mod=readonly \
    --env GOPROXY=off --env "GOMODCACHE=$work/modcache" --env "GOCACHE=$work/buildcache" \
    --env ARCH --env GUI_BINARY --env CLI_BINARY --env RELEASE_UPX \
    "$image" bash --noprofile --norc -e -o pipefail /workflow-step.sh
