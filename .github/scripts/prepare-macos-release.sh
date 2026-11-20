#!/usr/bin/env bash
set -euo pipefail

work=${1:?prepared Go directory}
lock=.github/toolchains/macos-release.json
app=$(jq -er '.xcode_path | select(test("^/Applications/Xcode_[0-9.]+[.]app$"))' "$lock")
xcode_version=$(jq -er .xcode_version "$lock")
xcode_build=$(jq -er .xcode_build "$lock")
sdk_version=$(jq -er .sdk_version "$lock")
export DEVELOPER_DIR="$app/Contents/Developer"
test -d "$DEVELOPER_DIR"
test "$(/usr/bin/xcodebuild -version)" = "$(printf 'Xcode %s\nBuild version %s' "$xcode_version" "$xcode_build")"
test "$(/usr/bin/xcrun --sdk macosx --show-sdk-version)" = "$sdk_version"
sdkroot=$(/usr/bin/xcrun --sdk macosx --show-sdk-path)
cc=$(/usr/bin/xcrun --sdk macosx --find clang)
cxx=$(/usr/bin/xcrun --sdk macosx --find clang++)
[[ $sdkroot == "$DEVELOPER_DIR/"* && -d $sdkroot ]]
[[ $cc == "$DEVELOPER_DIR/"* && -x $cc && $cxx == "$DEVELOPER_DIR/"* && -x $cxx ]]
os_build=$(/usr/bin/sw_vers -buildVersion)
[[ $os_build =~ ^[0-9]{2}[A-Z][0-9]+[a-z]?$ && ${ImageVersion:-} =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]

materials=$(bash .github/scripts/release-materials.sh build-macos.yml arm64)
jq -ce --arg go "$(<"$work/archive.sha256")" 'select(.go_sha256 == $go)' <<<"$materials" >/dev/null
jq -cS --arg os_build "$os_build" --arg image_version "$ImageVersion" '. + {$os_build,$image_version}' \
    <<<"$materials" > "$work/materials.json"
printf 'DEVELOPER_DIR=%s\nSDKROOT=%s\nCC=%s\nCXX=%s\n' "$DEVELOPER_DIR" "$sdkroot" "$cc" "$cxx" >> "$GITHUB_ENV"
