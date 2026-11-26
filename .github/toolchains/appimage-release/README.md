# AppImage build package lock

The shared AppImage producer uses the digest-pinned Ubuntu 22.04 amd64 base and
the Jammy snapshot in `manifest.json`. The package closure includes the CGO
compiler, GTK and X11 libraries, and the desktop and image packaging tools.
The independent `../appimage-build.json` lock pins linuxdeploy, appimagetool,
and the AppImage runtime.

## Refresh the lock

Run from the repository root on Linux amd64 with Docker and jq. Review the new
base digest, snapshot, and package roots in the manifest before resolving
dependencies. The following command writes a proposed lock to a fresh temporary
directory. It configures APT to verify the Ubuntu snapshot's signed indexes
using the archive keyring from the pinned base. Checking the index expiry is
disabled for the explicitly selected historical snapshot. Signature and package
hash checks remain enabled.

```bash
set -euo pipefail
manifest=.github/toolchains/appimage-release/manifest.json
base=$(jq -er .base_image "$manifest")
snapshot=$(jq -er .snapshot "$manifest")
roots=$(jq -er '.root_packages[]' "$manifest")
mapfile -t packages <<<"$roots"
draft=$(mktemp -d)
ca=$(realpath /etc/ssl/certs/ca-certificates.crt)

docker pull --platform linux/amd64 "$base"
docker run --rm --pull never --platform linux/amd64 \
    --mount "type=bind,src=$ca,dst=/etc/ssl/certs/ca-certificates.crt,readonly" \
    --entrypoint /bin/bash -i "$base" -s -- "$snapshot" "${packages[@]}" \
    > "$draft/os-packages-amd64.lock" <<'RESOLVE'
set -euo pipefail
snapshot=$1
shift
archive=/appimage-lock-downloads
sources=/tmp/appimage.sources.list
mkdir "$archive"
for suite in jammy jammy-updates jammy-security; do
    printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/%s %s main universe\n' \
        "$snapshot" "$suite"
done > "$sources"
apt_options=(-o "Dir::Etc::sourcelist=$sources" -o Dir::Etc::sourceparts=/dev/null
             -o Acquire::Check-Valid-Until=false -o Acquire::Retries=2
             -o APT::Update::Error-Mode=any -o Acquire::https::Timeout=25
             -o "Dir::Cache::archives=$archive")
apt-get "${apt_options[@]}" update >&2
apt-get "${apt_options[@]}" --yes --download-only --no-install-recommends install "$@" >&2

shopt -s nullglob
files=("$archive"/*.deb)
(( ${#files[@]} > 0 ))
for file in "${files[@]}"; do
    IFS=$'\t' read -r name version arch \
        <<<"$(dpkg-deb --show --showformat='${Package}\t${Version}\t${Architecture}' "$file")"
    digest=$(sha256sum < "$file")
    digest=${digest%% *}
    record=$(apt-cache "${apt_options[@]}" show "$name=$version" |
        awk -v arch="$arch" -v digest="$digest" '
          BEGIN {RS=""; FS="\n"}
          { path=""; hash=""; architecture=""; for (i=1;i<=NF;i++) {
              if ($i ~ /^Architecture: /) architecture=substr($i,15)
              if ($i ~ /^Filename: /) path=substr($i,11)
              if ($i ~ /^SHA256: /) hash=substr($i,9)
            }
            if (architecture == arch && hash == digest && path ~ /^pool\//) print path;
          }' | LC_ALL=C sort -u)
    [[ $record =~ ^pool/(main|universe)/[^[:space:]]+[.]deb$ ]]
    printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$version" "$arch" "$digest" "$record"
done | LC_ALL=C sort -t $'\t' -k1,1
RESOLVE
printf '%s\n' "$draft/os-packages-amd64.lock"
```

Each row binds the downloaded package's name, version, architecture, SHA-256
and archive path to a record in the signed indexes. Review the proposed lock
and manifest together. The unsigned AppImage validation then verifies the
lock again, installs its package closure offline, builds the AppDir and runs
the packaged binary.
