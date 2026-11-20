#!/usr/bin/env bash
set -euo pipefail

work=${1:?expected a private work directory}
test -d "$work"
test ! -e "$work/image.id"
toolchain=.github/toolchains/snap-host
manifest="$toolchain/manifest.json"
lock="$toolchain/os-packages-amd64.lock"
base=$(jq -er '.base_image | select(test("^ubuntu@sha256:[0-9a-f]{64}$"))' "$manifest")
snapshot=$(jq -er '.snapshot | select(test("^[0-9]{8}T[0-9]{6}Z$"))' "$manifest")
context="$work/snap-host-context"
packages="$context/packages"
mkdir --mode=755 -- "$context" "$packages"
cp -- "$toolchain/Dockerfile" "$context/Dockerfile"

fetch_package() (
    set -euo pipefail
    local name=$1 version=$2 package_arch=$3 digest=$4 path=$5
    [[ $name =~ ^[a-z0-9.+-]+$ && $version =~ ^[a-zA-Z0-9.+:~_-]+$ && $digest =~ ^[a-f0-9]{64}$ ]]
    [[ $path =~ ^pool/(main|universe)/[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_~%-]+[.]deb$ ]]
    [[ $package_arch == amd64 || $package_arch == all ]]
    local file="$packages/$digest.deb" actual
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 3 --connect-timeout 20 --max-time 300 --output "$file" \
        "https://snapshot.ubuntu.com/ubuntu/$snapshot/$path"
    printf '%s  %s\n' "$digest" "$file" | sha256sum --check --strict --status
    # shellcheck disable=SC2016 # dpkg-deb expands the control fields.
    actual=$(dpkg-deb --show --showformat='${Package}\t${Version}\t${Architecture}' "$file")
    test "$actual" = "$(printf '%s\t%s\t%s' "$name" "$version" "$package_arch")"
    chmod 644 "$file"
)

wait_for_packages() {
    local pid failed=0
    for pid; do
        wait "$pid" || failed=1
    done
    return "$failed"
}

test -s "$lock"
pids=()
while IFS=$'\t' read -r name version arch digest path; do
    fetch_package "$name" "$version" "$arch" "$digest" "$path" &
    pids+=("$!")
    if (( ${#pids[@]} >= 8 )); then
        wait_for_packages "${pids[@]}"
        pids=()
    fi
done < "$lock"
wait_for_packages "${pids[@]}"

# The lock derives from the signature-verified Noble archive indexes.
# Create a file-only APT repository from just the verified package files.
while IFS=$'\t' read -r _name _version _arch digest _path; do
    file="$packages/$digest.deb"
    dpkg-deb --field "$file"
    printf 'Filename: ./%s.deb\nSize: %s\nSHA256: %s\n\n' "$digest" "$(stat -c %s "$file")" "$digest"
done < "$lock" > "$packages/Packages"
awk -F '\t' '{print $1 "=" $2}' "$lock" > "$packages/install.list"

docker pull --platform linux/amd64 "$base"
test "$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$base")" = linux/amd64
docker build --platform linux/amd64 --network none --pull=false --iidfile "$work/image.pending" \
    --build-arg "BASE_IMAGE=$base" "$context"
image=$(<"$work/image.pending")
[[ $image =~ ^sha256:[a-f0-9]{64}$ ]]
docker run --rm --platform linux/amd64 --pull never --network none \
    --mount "type=bind,source=$(realpath "$lock"),target=/os-packages.lock,readonly" "$image" \
    bash -euo pipefail -c '
        while IFS=$'"'"'\t'"'"' read -r name version arch _digest _path; do
            actual=$(dpkg-query --show --showformat='"'"'${Version}\t${Architecture}'"'"' "$name")
            test "$actual" = "$(printf "%s\t%s" "$version" "$arch")"
        done < /os-packages.lock
        qemu-system-x86_64 --version
        qemu-img --version
        genisoimage --version
    '
test -c /dev/kvm
printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"query-kvm"}' '{"execute":"quit"}' |
    timeout 30s docker run --rm --interactive --device /dev/kvm --platform linux/amd64 \
        --pull never --network none "$image" qemu-system-x86_64 -machine q35,accel=kvm \
        -smp 1 -m 64 -nodefaults -display none -serial none -monitor none -S -qmp stdio |
    jq -se 'any(.[]; .return.enabled == true and .return.present == true)' >/dev/null
mv -- "$work/image.pending" "$work/image.id"
