#!/usr/bin/env bash
set -euo pipefail

work=${1:?fresh Android build SDK directory}
go_work=${2:?verified Android Go directory}
lock=.github/toolchains/android-release.json
java_lock=.github/toolchains/android-signer/manifest.json
test "$(uname -s):$(uname -m)" = Linux:x86_64
ndk=$(<android/ndk-version.txt)
test "$(jq -er .packages.ndk.revision "$lock")" = "$ndk"
mkdir -m 0700 -- "$work"
mkdir -- "$work/downloads" "$work/sdk" "$work/unpack"

for name in platform build-tools ndk; do
    record=$(jq -er --arg name "$name" '.packages[$name] | [.archive,.sha256,.directory,.destination,.revision] | @tsv' "$lock")
    IFS=$'\t' read -r archive digest directory destination revision <<<"$record"
    [[ $archive =~ ^[a-z0-9._-]+[.]zip$ && $digest =~ ^[0-9a-f]{64}$ ]]
    [[ $directory =~ ^[a-z0-9][a-z0-9._-]+$ && $destination =~ ^(build-tools|ndk|platforms)/[a-z0-9][a-z0-9._-]+$ ]]
    file="$work/downloads/$archive"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 3 --connect-timeout 20 --max-time 900 --output "$file" "https://dl.google.com/android/repository/$archive"
    printf '%s  %s\n' "$digest" "$file" | sha256sum --check --strict --status
    mkdir -- "$work/unpack/$name"
    unzip -q "$file" -d "$work/unpack/$name"
    package="$work/unpack/$name/$directory"
    actual=$(sed -n 's/^[[:space:]]*Pkg[.]Revision[[:space:]]*=[[:space:]]*//p' "$package/source.properties" | tr -d '\r')
    test "$actual" = "$revision"
    if [[ $name == platform ]]; then
        # SDK Manager normally creates this index. AGP's legacy parser cannot
        # discover a platform whose API level includes a minor version.
        api=$(awk -F= '$1 == "AndroidVersion.ApiLevel" {print $2}' "$package/source.properties")
        extension=$(awk -F= '$1 == "AndroidVersion.ExtensionLevel" {print $2}' "$package/source.properties")
        base=$(awk -F= '$1 == "AndroidVersion.IsBaseSdk" {print $2}' "$package/source.properties")
        layoutlib=$(awk -F= '$1 == "Layoutlib.Api" {print $2}' "$package/source.properties")
        [[ $api =~ ^[0-9]+[.][0-9]+$ && $destination == "platforms/android-$api" ]]
        [[ $extension =~ ^[0-9]+$ && $layoutlib =~ ^[0-9]+$ && $revision =~ ^[0-9]+$ ]]
        [[ $base == true || $base == false ]]
        cat > "$package/package.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<common:repository xmlns:common="http://schemas.android.com/repository/android/common/02"
                   xmlns:android="http://schemas.android.com/sdk/android/repo/repository2/04"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <localPackage path="platforms;android-$api" obsolete="false">
        <type-details xsi:type="android:platformDetailsType">
            <api-level>$api</api-level>
            <extension-level>$extension</extension-level>
            <base-extension>$base</base-extension>
            <layoutlib api="$layoutlib"/>
        </type-details>
        <revision><major>$revision</major></revision>
        <display-name>Android SDK Platform $api</display-name>
    </localPackage>
</common:repository>
XML
    fi
    mkdir -p -- "$work/sdk/${destination%/*}"
    mv -- "$package" "$work/sdk/$destination"
done
test -s "$work/sdk/platforms/android-37.2/android.jar"
test -x "$work/sdk/build-tools/36.0.0/zipalign"
test -x "$work/sdk/ndk/$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"

jdk_url=$(jq -er '.jdk.url | select(startswith("https://github.com/adoptium/temurin21-binaries/releases/download/"))' "$java_lock")
jdk_sha256=$(jq -er '.jdk.sha256 | select(test("^[0-9a-f]{64}$"))' "$java_lock")
jdk_archive="$work/downloads/temurin.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --retry 3 --connect-timeout 20 --max-time 900 --output "$jdk_archive" "$jdk_url"
printf '%s  %s\n' "$jdk_sha256" "$jdk_archive" | sha256sum --check --strict --status
mkdir -- "$work/java" "$work/gradle"
tar -xzf "$jdk_archive" -C "$work/java" --strip-components=1 --no-same-owner --no-same-permissions
test -x "$work/java/bin/java"
test -x "$work/java/bin/javac"

materials=$(bash .github/scripts/release-materials.sh build-android.yml all)
jq -ceS --arg go "$(<"$go_work/archive.sha256")" --arg jdk "$jdk_sha256" \
    'select(.go_sha256 == $go and .jdk_sha256 == $jdk)' <<<"$materials" > "$work/materials.json"
printf 'ANDROID_HOME=%s/sdk\nANDROID_SDK_ROOT=%s/sdk\nANDROID_NDK_HOME=%s/sdk/ndk/%s\n' \
    "$work" "$work" "$work" "$ndk" >> "$GITHUB_ENV"
printf 'JAVA_HOME=%s/java\nGRADLE_USER_HOME=%s/gradle\nGRADLE_OPTS=-Dorg.gradle.project.android.builder.sdkDownload=false\n' \
    "$work" "$work" >> "$GITHUB_ENV"
printf '%s/java/bin\n' "$work" >> "$GITHUB_PATH"
