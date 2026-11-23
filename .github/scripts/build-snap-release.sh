#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

work=${1:?fresh Snap build directory}
version=${2:?release version}
[[ $work == /* && $work != *','* && $version =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]
test "$(uname -sm)" = 'Linux x86_64'
test -c /dev/kvm
test "$version" = "$(<VERSION)"
test ! -e out
mkdir -m 0700 -- "$work"
mkdir -- "$work/inputs" "$work/inputs/debs" "$work/inputs/snaps" "$work/source"

locks=.github/toolchains/snap-release
lock="$locks/manifest.json"
materials=$(bash .github/scripts/release-materials.sh build-snapcraft.yml amd64)
snapshot=$(jq -er '.snapshot | select(test("^[0-9]{8}T[0-9]{6}Z$"))' "$lock")
cloud_url=$(jq -er '.cloud_image.url | select(test("^https://cloud-images[.]ubuntu[.]com/releases/jammy/release-[0-9]{8}/ubuntu-22[.]04-server-cloudimg-amd64[.]img$"))' "$lock")
cloud_sha=$(jq -er '.cloud_image.sha256 | select(test("^[0-9a-f]{64}$"))' "$lock")

check_digest() {
    printf '%s  %s\n' "$1" "$2" | sha256sum --check --strict --status ||
        { printf 'Snap release input digest mismatch: %s\n' "$2" >&2; return 1; }
}
download() {
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 3 --connect-timeout 20 --max-time 900 --output "$2" "$1"
    check_digest "$3" "$2"
}

download "$cloud_url" "$work/jammy.img" "$cloud_sha"
cp -- "$locks/os-packages-amd64.lock" "$work/inputs/packages.lock"
pids=()
while IFS=$'\t' read -r name version_code arch checksum path; do
    [[ $name =~ ^[a-z0-9.+-]+$ && $version_code =~ ^[a-zA-Z0-9.+:~_-]+$ && $checksum =~ ^[0-9a-f]{64}$ ]]
    [[ $arch == amd64 || $arch == all ]]
    [[ $path =~ ^pool/(main|universe|restricted|multiverse)/[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_~%-]+[.]deb$ ]]
    download "https://snapshot.ubuntu.com/ubuntu/$snapshot/$path" "$work/inputs/debs/$checksum.deb" "$checksum" &
    pids+=("$!")
    if (( ${#pids[@]} >= 8 )); then
        for pid in "${pids[@]}"; do wait "$pid"; done
        pids=()
    fi
done < "$work/inputs/packages.lock"
for pid in "${pids[@]}"; do wait "$pid"; done

jq -er '.snaps[] | [.name, .revision, .sha256, .seeded] | @tsv' "$lock" > "$work/inputs/snaps.tsv"
while IFS=$'\t' read -r name revision checksum seeded; do
    [[ $name =~ ^[a-z][a-z0-9-]*$ && $revision =~ ^[0-9]+$ && $checksum =~ ^[0-9a-f]{64}$ ]]
    case "$seeded" in
        true) ;;
        false)
            timeout --kill-after=5s 15m snap download --target-directory="$work/inputs/snaps" --revision="$revision" "$name"
            check_digest "$checksum" "$work/inputs/snaps/${name}_${revision}.snap"
            test -s "$work/inputs/snaps/${name}_${revision}.assert"
            ;;
        *) exit 1 ;;
    esac
done < "$work/inputs/snaps.tsv"

GITHUB_ENV="$work/go.env" GITHUB_PATH="$work/go.path" \
    bash .github/scripts/prepare-release-go.sh linux-amd64 "$work/go-work"
go_version=$(jq -er '.version | select(test("^go[0-9]+[.][0-9]+[.][0-9]+$"))' .github/toolchains/release-go.json)
mv -- "$work/go-work/$go_version.linux-amd64.tar.gz" "$work/inputs/go.tar.gz"
mv -- "$work/go-work/modcache" "$work/inputs/modcache"
jq -er '.go_sha256 + "  inputs/go.tar.gz"' <<<"$materials" > "$work/inputs/go.sha256"
jq -er '.go_mod_sha256 + "  go.mod", .go_sum_sha256 + "  go.sum"' <<<"$materials" > "$work/inputs/modules.sha256"

git archive HEAD src dist/snapcraft dist/mime images | tar -xf - -C "$work/source"
mv -- "$work/source/src" "$work/project"
cp -r -- "$work/source/dist/snapcraft/." "$work/project/"
install -Dm0644 "$work/source/dist/mime/application-x-pcv.xml" "$work/project/dist/mime/application-x-pcv.xml"
mv -- "$work/source/images" "$work/project/images"

mkdir -m 0700 -- "$work/host"
bash .github/scripts/prepare-snap-host.sh "$work/host"
host_image=$(<"$work/host/image.id")
[[ $host_image =~ ^sha256:[0-9a-f]{64}$ ]]
host_options=(--pull never --cap-drop ALL --security-opt no-new-privileges
    --user "$(id -u):$(id -g)" --mount "type=bind,src=$work,dst=$work" --workdir "$work")

ssh-keygen -q -t ed25519 -C picocrypt-snap-release -N '' -f "$work/client-key"
ssh-keygen -q -t ed25519 -C picocrypt-snap-release -N '' -f "$work/guest-key"
{
    cat <<'CLOUD'
#cloud-config
manage_etc_hosts: true
hostname: picocrypt-snap-build
ssh_pwauth: false
package_update: false
package_upgrade: false
ssh_keys:
  ed25519_private: |
CLOUD
    # This ephemeral host key is written only to the private seed directory.
    awk '{print "    " $0}' "$work/guest-key"
    printf '  ed25519_public: %s\n' "$(<"$work/guest-key.pub")"
    cat <<'CLOUD'
users:
  - name: builder
    shell: /bin/bash
    lock_passwd: true
    sudo: 'ALL=(ALL) NOPASSWD:ALL'
    ssh_authorized_keys:
CLOUD
    printf '      - %s\n' "$(<"$work/client-key.pub")"
} > "$work/user-data"
printf 'instance-id: picocrypt-snap-build\nlocal-hostname: picocrypt-snap-build\n' > "$work/meta-data"
docker run --rm "${host_options[@]}" "$host_image" \
    genisoimage -quiet -output seed.iso -volid cidata -joliet -rock user-data meta-data
docker run --rm "${host_options[@]}" "$host_image" \
    qemu-img create -f qcow2 -F qcow2 -b "$work/jammy.img" guest.qcow2 12G

port=22196
test -z "$(ss -H -ltn "sport = :$port")"
read -r key_type key_data _ < "$work/guest-key.pub"
printf '[127.0.0.1]:%s %s %s\n' "$port" "$key_type" "$key_data" > "$work/known-hosts"
guest=$(docker run --rm --detach "${host_options[@]}" --network host --device /dev/kvm \
    --group-add "$(stat -c %g /dev/kvm)" "$host_image" \
    qemu-system-x86_64 -accel kvm -cpu host -m 4096 -smp 4 -display none -monitor none \
    -drive file=guest.qcow2,if=virtio,format=qcow2 -drive file=seed.iso,media=cdrom,readonly=on \
    -netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$port-:22" \
    -device virtio-net-pci,netdev=net0 -serial file:serial.log)
trap 'docker rm -f "$guest" >/dev/null 2>&1 || true' EXIT

guest_ssh=(ssh -p "$port" -i "$work/client-key" -o BatchMode=yes -o IdentitiesOnly=yes
    -o ConnectTimeout=3 -o "UserKnownHostsFile=$work/known-hosts" -o StrictHostKeyChecking=yes builder@127.0.0.1)
for attempt in {1..45}; do
    if "${guest_ssh[@]}" true 2>/dev/null; then break; fi
    if [[ $attempt == 45 ]] || [[ $(docker inspect -f '{{.State.Running}}' "$guest") != true ]]; then
        echo 'The isolated Snap build guest did not start' >&2
        exit 1
    fi
    sleep 2
done
"${guest_ssh[@]}" 'timeout 60s cloud-init status --wait'
tar -C "$work" -cf - inputs project | \
    "${guest_ssh[@]}" 'mkdir /home/builder/snap-release; tar -xpf - -C /home/builder/snap-release'
"${guest_ssh[@]}" "sudo -n bash -se -- /home/builder/snap-release '$version'" < .github/scripts/build-snap-release-guest.sh
name="picocrypt-ng_${version}_amd64.snap"
"${guest_ssh[@]}" "cat '/home/builder/snap-release/project/$name'" > "$work/$name"
test -s "$work/$name"
test "$materials" = "$(bash .github/scripts/release-materials.sh build-snapcraft.yml amd64)"
install -Dm0644 "$work/$name" "out/$name"
printf '%s\n' "$materials" > "$work/materials.json"
