#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C.UTF-8 DEBIAN_FRONTEND=noninteractive

work=${1:?guest build directory}
version=${2:?release version}
test "$(hostname)" = picocrypt-snap-build
test "$(dpkg --print-architecture)" = amd64
. /etc/os-release
test "$VERSION_ID" = 22.04
[[ $version =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]
cd "$work"

# Store lookups fail promptly. QEMU separately blocks guest egress.
timeout 60s snap wait system seed.loaded
test -z "$(ss -H -ltn 'sport = :9')"
snap set system proxy.http=http://127.0.0.1:9 proxy.https=http://127.0.0.1:9
systemctl restart snapd.service

check_digest() {
    printf '%s  %s\n' "$1" "$2" | sha256sum --check --strict --status
}

snap_dir=/var/lib/snapd/snaps
check_snaps() {
    while IFS=$'\t' read -r name revision checksum _; do
        check_digest "$checksum" "$snap_dir/${name}_${revision}.snap"
        test "$(readlink -e "/snap/$name/current")" = "/snap/$name/$revision"
    done < inputs/snaps.tsv
}
while IFS=$'\t' read -r name revision checksum seeded; do
    [[ $name =~ ^[a-z][a-z0-9-]*$ && $revision =~ ^[0-9]+$ && $checksum =~ ^[0-9a-f]{64}$ ]]
    if [[ $seeded != true ]]; then
        base="inputs/snaps/${name}_${revision}"
        check_digest "$checksum" "$base.snap"
        snap ack "$base.assert"
        options=()
        if [[ $name == snapcraft ]]; then options+=(--classic); fi
        snap install "${options[@]}" "$base.snap"
    fi
done < inputs/snaps.tsv
check_snaps

# Build APT's local index from the exact approved archives.
apt_repo=/var/lib/picocrypt-snap-packages
mv -- inputs/debs "$apt_repo"
packages=()
while IFS=$'\t' read -r name version_code arch checksum _; do
    package="$apt_repo/$checksum.deb"
    check_digest "$checksum" "$package"
    # shellcheck disable=SC2016 # dpkg-deb expands its format fields.
    actual=$(dpkg-deb -W --showformat='${Package}\t${Version}\t${Architecture}' "$package")
    test "$actual" = "$(printf '%s\t%s\t%s' "$name" "$version_code" "$arch")"
    dpkg-deb -f "$package"
    printf 'Filename: %s.deb\nSize: %s\nSHA256: %s\n\n' "$checksum" "$(stat -c %s "$package")" "$checksum"
    packages+=("$name=$version_code")
done < inputs/packages.lock > "$apt_repo/Packages"
test -s "$apt_repo/Packages"
test -z "$(find /etc/apt/sources.list.d -maxdepth 1 \( -name '*.list' -o -name '*.sources' \) -print -quit)"
printf 'deb [trusted=yes] file:%s ./\n' "$apt_repo" > /etc/apt/sources.list
apt-get -o Acquire::Retries=0 update
apt-get -y --no-install-recommends install "${packages[@]}"
while IFS=$'\t' read -r name version_code arch _; do
    test "$(dpkg-query -W -f='${Version}\t${Architecture}' "$name")" = "$(printf '%s\t%s' "$version_code" "$arch")"
done < inputs/packages.lock

sha256sum --check --strict inputs/go.sha256
mkdir inputs/go inputs/gocache
tar -xzf inputs/go.tar.gz --strip-components=1 -C inputs/go
export GOENV=off GOWORK=off GOPROXY=off GOTOOLCHAIN=local
export GOROOT="$work/inputs/go" GOMODCACHE="$work/inputs/modcache" GOCACHE="$work/inputs/gocache"
export PATH="$GOROOT/bin:$PATH"
go -C project mod verify
(
    cd project
    sha256sum --check --strict ../inputs/modules.sha256
    # The packaging contract comes from the checkout. Point its inputs at the verified bundle.
    awk -v archive="$work/inputs/go.tar.gz" -v modcache="$GOMODCACHE" -v gocache="$GOCACHE" '
        /^    source: https:\/\/go\.dev\/dl\/go[0-9.]+\.linux-amd64\.tar\.gz$/ {
            print "    source: " archive
            source_count++
            next
        }
        {print}
        /^      - GOWORK: "off"$/ {
            print "      - GOPROXY: \"off\""
            print "      - GOMODCACHE: " modcache
            print "      - GOCACHE: " gocache
            env_count++
        }
        END {if (source_count != 1 || env_count != 1) exit 1}
    ' snapcraft.yaml > snapcraft-offline.yaml
    mv -- snapcraft-offline.yaml snapcraft.yaml
    SNAPCRAFT_BUILD_INFO=1 timeout --kill-after=30s 45m /snap/bin/snapcraft pack --destructive-mode
    sha256sum --check --strict ../inputs/modules.sha256
    snap_path="picocrypt-ng_${version}_amd64.snap"
    test -f "$snap_path" && test ! -L "$snap_path" && test -s "$snap_path"
    snap install --dangerous "./$snap_path"
    test "$(timeout 45s runuser -u builder -- snap run picocrypt-ng --version)" = "Picocrypt-NG version v$version"
)
check_snaps
