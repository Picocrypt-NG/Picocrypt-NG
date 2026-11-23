#!/usr/bin/env bash
set -euo pipefail

arch=${1:?expected release architecture}
work=${2:?prepared Go directory}
upx_package=${3:?expected UPX package}
upx_digest=${4:?expected UPX checksum}
[[ $arch == amd64 || $arch == arm64 ]]
test "$(dpkg --print-architecture)" = "$arch"
toolchain=.github/toolchains/linux-release
lock=$toolchain/manifest.json
snapshot=$(jq -er '.snapshot | select(test("^[0-9]{8}T[0-9]{6}Z$"))' "$lock")
upx_version=$(jq -er '.upx_version | select(test("^[0-9]+[.][0-9]+[.][0-9]+$"))' "$lock")
test "$upx_package" = "upx-$upx_version-${arch}_linux"
test "$upx_digest" = "$(jq -er --arg arch "$arch" '.architectures[$arch].upx_sha256 | select(test("^[0-9a-f]{64}$"))' "$lock")"
base=$(jq -er --arg arch "$arch" '.architectures[$arch].base_image | select(test("^ubuntu@sha256:[a-f0-9]{64}$"))' "$lock")

fetch() {
    local url=$1 file=$2 digest=$3
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 3 --connect-timeout 20 --max-time 300 --output "$file" "$url"
    printf '%s  %s\n' "$digest" "$file" | sha256sum --check --strict --status
}

fetch "https://github.com/upx/upx/releases/download/v$upx_version/$upx_package.tar.xz" "$work/upx.tar.xz" "$upx_digest"
tar -xJf "$work/upx.tar.xz" -C "$work" "$upx_package/upx"
test -x "$work/$upx_package/upx"
mkdir -- "$work/container" "$work/container/packages"
cp -- "$toolchain/Dockerfile" "$work/container/Dockerfile"
package_rows="$toolchain/os-packages-$arch.lock"

fetch_package() (
    set -euo pipefail
    local name=$1 version=$2 package_arch=$3 digest=$4 path=$5
    [[ $name =~ ^[a-z0-9.+-]+$ && $version =~ ^[a-zA-Z0-9.+:~_-]+$ && $digest =~ ^[a-f0-9]{64}$ ]]
    [[ $path =~ ^pool/(main|universe)/[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_~%-]+[.]deb$ ]]
    [[ $package_arch == "$arch" || $package_arch == all ]]
    local file="$work/container/packages/$digest.deb" actual
    fetch "https://snapshot.ubuntu.com/ubuntu/$snapshot/$path" "$file" "$digest"
    # shellcheck disable=SC2016 # dpkg-deb expands the format fields.
    actual=$(dpkg-deb --show --showformat='${Package}\t${Version}\t${Architecture}' "$file")
    test "$actual" = "$(printf '%s\t%s\t%s' "$name" "$version" "$package_arch")"
)

test -s "$package_rows"
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
package_dir="$work/container/packages"
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
[[ $image =~ ^sha256:[0-9a-f]{64}$ ]]
docker run --rm --platform "linux/$arch" --pull never --network none \
    --mount "type=bind,source=$(realpath "$package_rows"),target=/os-packages.lock,readonly" "$image" \
    bash -euo pipefail -c '
        while IFS=$'"'"'\t'"'"' read -r name version arch _sha _path; do
            actual=$(dpkg-query --show --showformat='"'"'${Version}\t${Architecture}'"'"' "$name")
            test "$actual" = "$(printf "%s\t%s" "$version" "$arch")"
        done < /os-packages.lock
    '
materials=$(bash .github/scripts/release-materials.sh build-linux.yml "$arch")
jq -ce --arg go "$(<"$work/archive.sha256")" --arg upx "$upx_digest" \
    'select(.go_sha256 == $go and .upx_sha256 == $upx)' <<<"$materials" > "$work/materials.json"
printf 'RELEASE_LINUX_IMAGE=%s\nRELEASE_UPX=%s\n' "$image" "$work/$upx_package/upx" >> "$GITHUB_ENV"
