#!/usr/bin/env bash
set -euo pipefail
version="${1:?usage: release-manifest.sh <version>}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
    echo "release manifest: invalid version" >&2
    exit 2
fi
cat <<EOF
Picocrypt-NG build-linux.yml artifacts/build-linux-amd64/Picocrypt-NG
Picocrypt-NG-cli build-linux.yml artifacts/build-linux-amd64/Picocrypt-NG-cli
Picocrypt-NG.deb build-linux.yml artifacts/build-linux-amd64/Picocrypt-NG.deb
Picocrypt-NG-arm64 build-linux.yml artifacts/build-linux-arm64/Picocrypt-NG-arm64
Picocrypt-NG-cli-arm64 build-linux.yml artifacts/build-linux-arm64/Picocrypt-NG-cli-arm64
Picocrypt-NG.dmg build-macos.yml artifacts/build-macos/Picocrypt-NG.dmg
Picocrypt-NG-cli-macos build-macos.yml artifacts/build-macos/Picocrypt-NG-cli-macos
Picocrypt-NG-portable.exe build-windows.yml artifacts/build-windows/Picocrypt-NG-portable.exe
Picocrypt-NG-cli.exe build-windows.yml artifacts/build-windows/Picocrypt-NG-cli.exe
Picocrypt-NG-Setup.exe build-windows.yml artifacts/build-windows/Picocrypt-NG-Setup.exe
Picocrypt-NG-cli-Legacy.exe build-windows-legacy.yml artifacts/build-windows-legacy/Picocrypt-NG-cli-Legacy.exe
Picocrypt-NG-android-arm64-v8a.apk build-android.yml out/Picocrypt-NG-android-arm64-v8a.apk
Picocrypt-NG-android-x86_64.apk build-android.yml out/Picocrypt-NG-android-x86_64.apk
Picocrypt-NG-android-universal.apk build-android.yml out/Picocrypt-NG-android-universal.apk
Picocrypt-NG-${version}-x86_64.AppImage build-appimage.yml artifacts/Picocrypt-NG-${version}-x86_64.AppImage
Picocrypt-NG-${version}-x86_64.AppImage.zsync build-appimage.yml artifacts/Picocrypt-NG-${version}-x86_64.AppImage.zsync
picocrypt-ng_${version}_amd64.snap build-snapcraft.yml out/picocrypt-ng_${version}_amd64.snap
EOF
