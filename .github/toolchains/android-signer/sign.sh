#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
ulimit -c 0

IFS= read -r -d '' keystore
IFS= read -r -d '' ANDROID_KEYSTORE_PASSWORD
IFS= read -r -d '' ANDROID_KEY_PASSWORD
IFS= read -r -d '' ANDROID_KEY_ALIAS
export ANDROID_KEYSTORE_PASSWORD ANDROID_KEY_PASSWORD ANDROID_KEY_ALIAS
[[ -n $keystore && -n $ANDROID_KEYSTORE_PASSWORD && -n $ANDROID_KEY_PASSWORD && -n $ANDROID_KEY_ALIAS ]]
printf '%s' "$keystore" | base64 --decode > /tmp/release.keystore
unset keystore

for abi in armeabi-v7a arm64-v8a x86 x86_64 universal; do
    /opt/java/bin/java --enable-native-access=ALL-UNNAMED -Xmx1024M \
        -cp /signer:/signer/apksigner.jar AndroidApkSigner /tmp/release.keystore \
        "/output/app-$abi-release.apk" "/input/app-$abi-release-unsigned.apk"
done
