#!/usr/bin/env bash
# Review current Ubuntu candidates. This reads indexes and installs no packages.
set -euo pipefail
export LC_ALL=C

mode=${1:-}
if (( $# > 1 )) || [[ -n $mode && $mode != --advisory ]]; then
    printf 'Usage: %s [--advisory]\n' "$0" >&2
    exit 2
fi

toolchain=.github/toolchains/appimage-release
snapshot=$(jq -er '.snapshot | select(test("^[0-9]{8}T[0-9]{6}Z$"))' "$toolchain/manifest.json")

report() {
    tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
}

unavailable() {
    printf '::warning::AppImage dependency review incomplete\n'
    printf '### AppImage dependency review\n\nLocked Ubuntu snapshot: %s\n\n%s.\n' \
        "$snapshot" "$1" | report
    if [[ $mode == --advisory ]]; then
        exit 0
    fi
    exit 1
}

declare -a packages=()
declare -A versions=() candidates=()
while IFS=$'\t' read -r name version _; do
    if ! [[ $name =~ ^[a-z0-9][a-z0-9.+-]*$ && $version =~ ^[0-9][a-zA-Z0-9.+:~_-]*$ && -z ${versions[$name]:-} ]]; then
        printf '::error::Invalid or duplicate package in the AppImage lock\n'
        exit 1
    fi
    packages+=("$name")
    versions[$name]=$version
done < "$toolchain/os-packages-amd64.lock"
if (( ${#packages[@]} == 0 )); then
    printf '::error::The AppImage package lock is empty\n'
    exit 1
fi

work=$(mktemp -d)
trap 'find "$work" -depth -delete' EXIT
mkdir "$work/lists" "$work/cache"
cat > "$work/sources.list" <<'EOF'
deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu jammy main universe
deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu jammy-updates main universe
deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://security.ubuntu.com/ubuntu jammy-security main universe
EOF
apt_config=(
    -o "Dir::Etc::sourcelist=$work/sources.list"
    -o Dir::Etc::sourceparts=-
    -o "Dir::State::lists=$work/lists"
    -o Dir::State::status=/dev/null
    -o "Dir::Cache=$work/cache"
    -o APT::Architecture=amd64
    -o Acquire::Languages=none
    -o APT::Update::Error-Mode=any
)
timeout --kill-after=5s 90s apt-get "${apt_config[@]}" update ||
    unavailable "Could not refresh signed Ubuntu package indexes"
policy=$(apt-cache "${apt_config[@]}" policy "${packages[@]}") ||
    unavailable "Could not read current Jammy package candidates"
while IFS=$'\t' read -r name candidate; do
    candidates[$name]=$candidate
done < <(awk '
    /^[a-z0-9][a-z0-9.+-]*(:amd64)?:$/ {
        name = $0
        sub(/:$/, "", name)
        sub(/:amd64$/, "", name)
    }
    name != "" && $1 == "Candidate:" { print name "\t" $2 }
' <<< "$policy")

updates=()
for name in "${packages[@]}"; do
    locked=${versions[$name]}
    candidate=${candidates[$name]:-}
    [[ $candidate =~ ^[0-9][a-zA-Z0-9.+:~_-]*$ ]] || unavailable "No current Jammy candidate for $name"
    if dpkg --compare-versions "$candidate" gt "$locked"; then
        updates+=("| $name | $locked | $candidate |")
    elif dpkg --compare-versions "$candidate" lt "$locked"; then
        unavailable "Current Jammy candidate for $name is older than the locked package"
    fi
done

{
    printf '### AppImage dependency review\n\nLocked Ubuntu snapshot: %s\n\n' "$snapshot"
    if ((${#updates[@]} == 0)); then
        printf 'The locked packages match the current Jammy candidates.\n'
    else
        printf '%s\n' 'Newer packages are available for review.' '' \
            '| Package | Locked | Current Jammy |' '| --- | --- | --- |'
        printf '%s\n' "${updates[@]}"
    fi
} | report
if ((${#updates[@]} > 0)); then
    printf '::warning::%s locked AppImage packages have newer Jammy candidates\n' "${#updates[@]}"
fi
