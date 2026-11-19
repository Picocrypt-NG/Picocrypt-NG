#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
ulimit -c 0

if [[ ${1:-} == regenerate-zsync ]]; then
    filename=${2:?missing AppImage name}
    [[ $filename =~ ^Picocrypt-NG-[0-9][0-9.A-Za-z-]*-x86_64\.AppImage$ ]]
    cd /output
    ln -s "/input/$filename" "$filename"
    exec /tools/appimagetool/usr/bin/zsyncmake -u "$filename" -o "$filename.zsync" "$filename"
fi

fingerprint=${1:?missing expected signing fingerprint}
filename=${2:?missing output name}
update=${3:?missing update information}
[[ $fingerprint =~ ^[A-F0-9]{40}$ && $filename =~ ^Picocrypt-NG-[0-9][0-9.A-Za-z-]*-x86_64\.AppImage$ ]]

export GNUPGHOME
GNUPGHOME=$(mktemp -d /tmp/gnupg.XXXXXXXX)
trap 'gpgconf --kill gpg-agent' EXIT
printf '%s\n' allow-loopback-pinentry > "$GNUPGHOME/gpg-agent.conf"

IFS= read -r -d '' private_key
IFS= read -r -d '' APPIMAGETOOL_SIGN_PASSPHRASE
export APPIMAGETOOL_SIGN_PASSPHRASE
[[ -n $private_key ]]
printf '%s\n' "$private_key" | gpg --batch --import
unset private_key
actual=$(gpg --batch --with-colons --list-secret-keys "$fingerprint" | awk -F: '$1 == "sec" { primary=1; next } primary && $1 == "fpr" { print $10; exit }')
[[ $actual == "$fingerprint" ]]

cd /output
ARCH=x86_64 /tools/appimagetool/AppRun \
    --runtime-file /tools/runtime --updateinformation "$update" \
    --sign --sign-key "$fingerprint" /input "$filename"
[[ -s $filename && -s $filename.zsync ]]
