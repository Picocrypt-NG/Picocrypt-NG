#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"

digest() {
    local hash
    if [[ ! -f $1 || -L $1 || ! -s $1 ]]; then
        printf 'Missing or invalid release material: %s\n' "$1" >&2
        return 1
    fi
    hash=$(shasum -a 256 -b "$1") || return
    hash=${hash%% *}
    [[ $hash =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$hash"
}

case "$1:$2" in
    build-linux.yml:amd64|build-linux.yml:arm64)
        lock=.github/toolchains/linux-release/manifest.json
        packages=$(digest ".github/toolchains/linux-release/os-packages-$2.lock")
        platform=linux-$2
        extra=$(jq -ce --arg arch "$2" --arg packages_sha256 "$packages" \
            '.architectures[$arch] + {snapshot:$ARGS.named.snapshot,packages_sha256:$packages_sha256}' \
            --arg snapshot "$(jq -er .snapshot "$lock")" "$lock")
        ;;
    build-snapcraft.yml:amd64)
        lock=.github/toolchains/snap-release/manifest.json
        platform=linux-amd64
        packages=$(digest .github/toolchains/snap-release/os-packages-amd64.lock)
        host_lock=$(digest .github/toolchains/snap-host/manifest.json)
        host_packages=$(digest .github/toolchains/snap-host/os-packages-amd64.lock)
        host_dockerfile=$(digest .github/toolchains/snap-host/Dockerfile)
        extra=$(jq -cn --arg packages_sha256 "$packages" --arg host_lock_sha256 "$host_lock" \
            --arg host_packages_sha256 "$host_packages" --arg host_dockerfile_sha256 "$host_dockerfile" \
            '{$packages_sha256,$host_lock_sha256,$host_packages_sha256,$host_dockerfile_sha256}')
        ;;
    build-macos.yml:arm64)
        lock=.github/toolchains/macos-release.json
        platform=darwin-arm64
        extra=$(jq -ce '{xcode_version,xcode_build,sdk_version}' "$lock")
        ;;
    build-android.yml:all)
        lock=.github/toolchains/android-release.json
        platform=linux-amd64
        jdk_sha256=$(jq -er '.jdk.sha256 | select(test("^[0-9a-f]{64}$"))' \
            .github/toolchains/android-signer/manifest.json)
        extra=$(jq -ce --arg jdk_sha256 "$jdk_sha256" \
            --arg gradle_verification_sha256 "$(digest android/gradle/verification-metadata.xml)" \
            --arg gradle_wrapper_sha256 "$(digest android/gradle/wrapper/gradle-wrapper.jar)" \
            --arg gradle_wrapper_properties_sha256 "$(digest android/gradle/wrapper/gradle-wrapper.properties)" \
            '.packages | map_values(.sha256) +
             {$jdk_sha256,$gradle_verification_sha256,$gradle_wrapper_sha256,$gradle_wrapper_properties_sha256}' "$lock")
        ;;
    *) printf 'Unsupported release materials: %s %s\n' "$1" "$2" >&2; exit 1 ;;
esac
go_lock=.github/toolchains/release-go.json
go_sha256=$(jq -er --arg platform "$platform" '.archives[$platform] | select(test("^[0-9a-f]{64}$"))' "$go_lock")
go_mod_sha256=$(digest src/go.mod)
go_sum_sha256=$(digest src/go.sum)
toolchain_lock_sha256=$(digest "$lock")
jq -cnS --arg go_sha256 "$go_sha256" --arg go_mod_sha256 "$go_mod_sha256" \
    --arg go_sum_sha256 "$go_sum_sha256" --arg toolchain_lock_sha256 "$toolchain_lock_sha256" \
    --argjson extra "$extra" '$extra + {$go_sha256,$go_mod_sha256,$go_sum_sha256,$toolchain_lock_sha256}'
