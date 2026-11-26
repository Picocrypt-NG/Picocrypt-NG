#!/usr/bin/env bash
set -euo pipefail

work=${RUNNER_TEMP:?}/picocrypt-release-materials
image=${RELEASE_APPIMAGE_IMAGE:?}
[[ $image =~ ^sha256:[a-f0-9]{64}$ ]]
workspace=$(pwd -P)
step=$(realpath -e -- "${1:?workflow step script}")
build="$work/appimage-build"
tools="$work/appimage-tools"

exec docker run --rm --init --pull never --network none --platform linux/amd64 --cap-drop ALL \
    --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
    --mount "type=bind,source=$workspace,target=$workspace,readonly" \
    --mount "type=bind,source=$work/go,target=$work/go,readonly" \
    --mount "type=bind,source=$work/modcache,target=$work/modcache,readonly" \
    --mount "type=bind,source=$tools,target=$tools,readonly" \
    --mount "type=bind,source=$work/buildcache,target=$work/buildcache" \
    --mount "type=bind,source=$work/home,target=$work/home" \
    --mount "type=bind,source=$build,target=$build" --workdir "$build" \
    --mount "type=bind,source=$step,target=/workflow-step.sh,readonly" \
    --env "HOME=$work/home" --env "PATH=$work/go/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    --env GOENV=off --env GOTOOLCHAIN=local --env GOWORK=off --env GOFLAGS=-mod=readonly \
    --env GOPROXY=off --env "GOMODCACHE=$work/modcache" --env "GOCACHE=$work/buildcache" \
    --env "SOURCE_ROOT=$workspace" --env "APPIMAGE_TOOLS=$tools" \
    --env GITHUB_REPOSITORY --env APPIMAGE_EXTRACT_AND_RUN --env NO_STRIP \
    "$image" bash --noprofile --norc -e -o pipefail /workflow-step.sh
