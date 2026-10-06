#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 5 ]]; then
    echo "Usage: $0 <apk-directory> <version-name> <base-version-code> <application-id> <unsigned|signed>" >&2
    exit 2
fi

apk_dir=$1
expected_version_name=$2
base_version_code=$3
expected_application_id=$4
build_kind=$5

if [[ ! -d "$apk_dir" ]]; then
    echo "APK directory does not exist: $apk_dir" >&2
    exit 1
fi
if [[ -z "$expected_version_name" ]]; then
    echo "Expected versionName must not be empty" >&2
    exit 2
fi
if [[ -z "$expected_application_id" ]]; then
    echo "Expected application ID must not be empty" >&2
    exit 2
fi
if [[ ! "$base_version_code" =~ ^[0-9]+$ ]]; then
    echo "Base versionCode must be a non-negative integer: $base_version_code" >&2
    exit 2
fi

case "$build_kind" in
    unsigned)
        filename_suffix=-unsigned
        ;;
    signed)
        filename_suffix=
        ;;
    *)
        echo "Build kind must be unsigned or signed: $build_kind" >&2
        exit 2
        ;;
esac

trusted_signer_sha256=
if [[ "$build_kind" == signed ]]; then
    : "${PICOCRYPT_ANDROID_SIGNING_CERT_SHA256_FILE:?Set PICOCRYPT_ANDROID_SIGNING_CERT_SHA256_FILE for signed APK verification}"
    if [[ ! -f "$PICOCRYPT_ANDROID_SIGNING_CERT_SHA256_FILE" ]]; then
        echo "Trusted Android signing certificate digest file does not exist: $PICOCRYPT_ANDROID_SIGNING_CERT_SHA256_FILE" >&2
        exit 1
    fi
    trusted_signer_sha256=$(< "$PICOCRYPT_ANDROID_SIGNING_CERT_SHA256_FILE")
    if [[ ! "$trusted_signer_sha256" =~ ^[0-9a-f]{64}$ ]]; then
        echo "Trusted Android signing certificate SHA-256 digest must be exactly 64 lowercase hexadecimal characters" >&2
        exit 1
    fi
fi

if [[ -z "${AAPT:-}" ]]; then
    : "${ANDROID_HOME:?Set AAPT or ANDROID_HOME to locate aapt}"
    AAPT="$ANDROID_HOME/build-tools/36.0.0/aapt"
fi
if [[ ! -x "$AAPT" ]]; then
    echo "aapt is not executable: $AAPT" >&2
    exit 1
fi
if ! aapt_version="$("$AAPT" version 2>&1)"; then
    echo "aapt health check failed: $AAPT" >&2
    printf '%s\n' "$aapt_version" >&2
    exit 1
fi
if [[ -z "${APKSIGNER:-}" ]]; then
    : "${ANDROID_HOME:?Set APKSIGNER or ANDROID_HOME to locate apksigner}"
    APKSIGNER="$ANDROID_HOME/build-tools/36.0.0/apksigner"
fi
if [[ ! -x "$APKSIGNER" ]]; then
    echo "apksigner is not executable: $APKSIGNER" >&2
    exit 1
fi
# Keep apksigner's diagnostics exact without filtering stderr when Java warns
# about the Conscrypt native library used by Android Build Tools 36.
apksigner_command=("$APKSIGNER" -J-enable-native-access=ALL-UNNAMED)
if ! apksigner_version="$("${apksigner_command[@]}" version 2>&1)" || [[ -z "$apksigner_version" ]]; then
    echo "apksigner health check failed: $APKSIGNER" >&2
    printf '%s\n' "$apksigner_version" >&2
    exit 1
fi
if [[ -z "${READELF:-}" ]]; then
    READELF=$(command -v readelf || true)
fi
if [[ -z "$READELF" || ! -x "$READELF" ]]; then
    echo "readelf is not executable: ${READELF:-<not found>}" >&2
    exit 1
fi
if ! readelf_version="$("$READELF" --version 2>&1)" || [[ -z "$readelf_version" ]]; then
    echo "readelf health check failed: $READELF" >&2
    printf '%s\n' "$readelf_version" >&2
    exit 1
fi
expected_files="$(printf '%s\n' \
    "app-arm64-v8a-release${filename_suffix}.apk" \
    "app-universal-release${filename_suffix}.apk" \
    "app-x86_64-release${filename_suffix}.apk")"
actual_files="$(find "$apk_dir" -maxdepth 1 -type f -name '*.apk' -printf '%f\n' | LC_ALL=C sort)"
if [[ "$actual_files" != "$expected_files" ]]; then
    echo "Release APK set does not match the exact $build_kind contract." >&2
    echo "Expected:" >&2
    printf '%s\n' "$expected_files" >&2
    echo "Actual:" >&2
    printf '%s\n' "${actual_files:-<none>}" >&2
    exit 1
fi

base_version_code=$((10#$base_version_code))
inspection_dir=$(mktemp -d)
trap 'rm -rf "$inspection_dir"' EXIT
genuine_unsigned_diagnostic=$'DOES NOT VERIFY\nERROR: Missing META-INF/MANIFEST.MF'

verify_apk() {
    local filename=$1
    local expected_version_code=$2
    local expected_abis=$3
    local apk="$apk_dir/$filename"
    local badging package_line actual_application_id actual_version_code actual_version_name entries actual_abis signature_output signer_count signer_digest abi jni_file elf_header actual_machine expected_machine expected_machine_code

    if signature_output="$("${apksigner_command[@]}" verify --Werr --verbose --print-certs "$apk" 2>&1)"; then
        if [[ "$build_kind" == unsigned ]]; then
            echo "$filename has a valid APK signature, want unsigned" >&2
            exit 1
        fi
    elif [[ "$build_kind" == signed ]]; then
        echo "$filename does not have a valid APK signature" >&2
        printf '%s\n' "$signature_output" >&2
        exit 1
    elif [[ "$signature_output" != "$genuine_unsigned_diagnostic" ]]; then
        echo "$filename apksigner result does not match the pinned genuine-unsigned diagnostic" >&2
        printf '%s\n' "$signature_output" >&2
        exit 1
    fi

    # Removing every signature record from a formerly signed APK produces the
    # same bytes/diagnostic class as an APK that was never signed. That case is
    # artifact-indistinguishable here; PR provenance comes from building and
    # verifying these APKs in the same controlled, blocking workflow job.

    if [[ "$build_kind" == signed ]]; then
        signer_count=$(sed -n 's/^Number of signers: //p' <<< "$signature_output")
        if [[ "$signer_count" != 1 ]]; then
            echo "$filename APK signer count = '${signer_count:-<missing>}', want exactly 1" >&2
            exit 1
        fi
        signer_digest=$(sed -n 's/^Signer #1 certificate SHA-256 digest: //p' <<< "$signature_output")
        if [[ ! "$signer_digest" =~ ^[0-9a-f]{64}$ ]]; then
            echo "$filename signer certificate SHA-256 digest is missing or malformed" >&2
            exit 1
        fi
        if [[ "$signer_digest" != "$trusted_signer_sha256" ]]; then
            echo "$filename signer certificate SHA-256 digest = '$signer_digest', want '$trusted_signer_sha256'" >&2
            exit 1
        fi
    fi

    badging="$("$AAPT" dump badging "$apk")"
    package_line=${badging%%$'\n'*}
    actual_application_id="$(sed -n "s/^package: name='\([^']*\)'.*/\1/p" <<< "$package_line")"
    actual_version_code="$(sed -n "s/^package: .* versionCode='\([^']*\)'.*/\1/p" <<< "$package_line")"
    actual_version_name="$(sed -n "s/^package: .* versionName='\([^']*\)'.*/\1/p" <<< "$package_line")"

    if [[ ! "$actual_version_code" =~ ^[0-9]+$ ]]; then
        echo "$filename versionCode metadata is not a decimal integer: '$actual_version_code'" >&2
        exit 1
    fi
    if [[ "$actual_application_id" != "$expected_application_id" ]]; then
        echo "$filename application ID = '$actual_application_id', want '$expected_application_id'" >&2
        exit 1
    fi
    if [[ "$actual_version_name" != "$expected_version_name" ]]; then
        echo "$filename versionName = '$actual_version_name', want '$expected_version_name'" >&2
        exit 1
    fi
    if [[ "$actual_version_code" != "$expected_version_code" ]]; then
        echo "$filename versionCode = '$actual_version_code', want '$expected_version_code'" >&2
        exit 1
    fi
    if ! grep -Fx "sdkVersion:'26'" <<< "$badging" >/dev/null; then
        echo "$filename does not declare minSdk 26" >&2
        exit 1
    fi

    entries="$(unzip -Z1 "$apk")"
    actual_abis="$(awk -F/ '$1 == "lib" && NF >= 3 { print $2 }' <<< "$entries" | LC_ALL=C sort -u)"
    if [[ "$actual_abis" != "$expected_abis" ]]; then
        echo "$filename native ABI set does not match." >&2
        echo "Expected:" >&2
        printf '%s\n' "$expected_abis" >&2
        echo "Actual:" >&2
        printf '%s\n' "${actual_abis:-<none>}" >&2
        exit 1
    fi
    while IFS= read -r abi; do
        if ! grep -Fx "lib/$abi/libgojni.so" <<< "$entries" >/dev/null; then
            echo "$filename is missing lib/$abi/libgojni.so" >&2
            exit 1
        fi
        jni_file="$inspection_dir/${filename%.apk}-$abi-libgojni.so"
        if ! unzip -p "$apk" "lib/$abi/libgojni.so" > "$jni_file"; then
            echo "failed to extract lib/$abi/libgojni.so from $filename" >&2
            exit 1
        fi
        if [[ ! -s "$jni_file" ]]; then
            echo "$filename lib/$abi/libgojni.so is empty" >&2
            exit 1
        fi
        if ! elf_header="$(LC_ALL=C "$READELF" -hW "$jni_file" 2>&1)"; then
            echo "$filename lib/$abi/libgojni.so is not a valid ELF file" >&2
            printf '%s\n' "$elf_header" >&2
            exit 1
        fi
        if ! grep -Eq '^[[:space:]]*Class:[[:space:]]+ELF64$' <<< "$elf_header"; then
            echo "$filename lib/$abi/libgojni.so is not ELF64" >&2
            exit 1
        fi
        if ! grep -Eq '^[[:space:]]*Type:[[:space:]]+DYN[[:space:]]+\(Shared object file\)$' <<< "$elf_header"; then
            echo "$filename lib/$abi/libgojni.so is not an ELF shared object (DYN)" >&2
            exit 1
        fi
        case "$abi" in
            arm64-v8a)
                expected_machine="AArch64"
                expected_machine_code="183/0xb7"
                ;;
            x86_64)
                expected_machine="Advanced Micro Devices X86-64"
                expected_machine_code="62/0x3e"
                ;;
            *)
                echo "No ELF machine contract is defined for unexpected ABI '$abi'" >&2
                exit 1
                ;;
        esac
        actual_machine=$(sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p' <<< "$elf_header")
        if [[ "$actual_machine" != "$expected_machine" ]]; then
            echo "$filename lib/$abi/libgojni.so Machine = '${actual_machine:-<missing>}', want '$expected_machine' (e_machine $expected_machine_code)" >&2
            exit 1
        fi
    done <<< "$expected_abis"
}

verify_apk \
    "app-arm64-v8a-release${filename_suffix}.apk" \
    "$((base_version_code * 10 + 2))" \
    "arm64-v8a"
verify_apk \
    "app-universal-release${filename_suffix}.apk" \
    "$base_version_code" \
    "$(printf '%s\n' arm64-v8a x86_64)"
verify_apk \
    "app-x86_64-release${filename_suffix}.apk" \
    "$((base_version_code * 10 + 4))" \
    "x86_64"

echo "Verified exact $build_kind Android release APK contract for $expected_application_id version $expected_version_name (base versionCode $base_version_code)."
