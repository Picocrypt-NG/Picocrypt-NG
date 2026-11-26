#!/usr/bin/env bash
set -euo pipefail

arch=${1:?expected Debian architecture}
work=${2:?prepared work directory}
base=${3:?digest-pinned Ubuntu base image}
snapshot=${4:?Ubuntu archive snapshot}
package_rows=${5:?package lock path}
[[ $arch == amd64 || $arch == arm64 ]]
[[ $base =~ ^ubuntu@sha256:[a-f0-9]{64}$ && $snapshot =~ ^[0-9]{8}T[0-9]{6}Z$ ]]
test "$(dpkg --print-architecture)" = "$arch"
[[ -f $package_rows && ! -L $package_rows && -s $package_rows ]]

mkdir -- "$work/container" "$work/container/packages"
cp -- .github/toolchains/linux-release/Dockerfile "$work/container/Dockerfile"
package_dir="$work/container/packages"

fetch_package() (
    set -euo pipefail
    local name=$1 version=$2 package_arch=$3 digest=$4 path=$5
    [[ $name =~ ^[a-z0-9.+-]+$ && $version =~ ^[a-zA-Z0-9.+:~_-]+$ && $digest =~ ^[a-f0-9]{64}$ ]]
    [[ $path =~ ^pool/(main|universe)/[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_~%-]+[.]deb$ ]]
    [[ $package_arch == "$arch" || $package_arch == all ]]
    local file="$package_dir/$digest.deb" actual
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 3 --connect-timeout 20 --max-time 300 --output "$file" \
        "https://snapshot.ubuntu.com/ubuntu/$snapshot/$path"
    printf '%s  %s\n' "$digest" "$file" | sha256sum --check --strict --status
    # shellcheck disable=SC2016 # dpkg-deb expands the format fields.
    actual=$(dpkg-deb --show --showformat='${Package}\t${Version}\t${Architecture}' "$file")
    test "$actual" = "$(printf '%s\t%s\t%s' "$name" "$version" "$package_arch")"
)

pids=()
while IFS=$'\t' read -r name version package_arch digest path; do
    fetch_package "$name" "$version" "$package_arch" "$digest" "$path" &
    pids+=("$!")
    if (( ${#pids[@]} >= 8 )); then
        for pid in "${pids[@]}"; do wait "$pid"; done
        pids=()
    fi
done < "$package_rows"
for pid in "${pids[@]}"; do wait "$pid"; done

# APT resolves the already verified files through an exclusively local index.
while IFS=$'\t' read -r name version _arch digest _path; do
    file="$package_dir/$digest.deb"
    dpkg-deb --field "$file"
    printf 'Filename: ./%s.deb\nSize: %s\nSHA256: %s\n\n' "$digest" "$(stat -c %s "$file")" "$digest"
done < "$package_rows" > "$package_dir/Packages"
awk -F '\t' '{print $1 "=" $2}' "$package_rows" > "$package_dir/install.list"

docker pull --platform "linux/$arch" "$base"
test "$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$base")" = "linux/$arch"
docker build --platform "linux/$arch" --network none --pull=false --iidfile "$work/image.id" \
    --build-arg "BASE_IMAGE=$base" "$work/container"
image=$(<"$work/image.id")
[[ $image =~ ^sha256:[a-f0-9]{64}$ ]]
docker run --rm --platform "linux/$arch" --pull never --network none \
    --mount "type=bind,source=$(realpath "$package_rows"),target=/os-packages.lock,readonly" "$image" \
    bash -euo pipefail -c '
        while IFS=$'"'"'\t'"'"' read -r name version arch _sha _path; do
            actual=$(dpkg-query --show --showformat='"'"'${Version}\t${Architecture}'"'"' "$name")
            test "$actual" = "$(printf "%s\t%s" "$version" "$arch")"
        done < /os-packages.lock
    '
