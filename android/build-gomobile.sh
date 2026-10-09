#!/bin/bash
# Build script for Go Mobile bindings
# This script builds the Go mobile AAR library for Android

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
GO_SRC_DIR="$(cd "$SCRIPT_DIR/../src" && pwd -P)"
OUTPUT_DIR="$SCRIPT_DIR/app/libs"
GOMOBILE_LDFLAGS="${GOMOBILE_LDFLAGS:--s -w -buildid=}"
NDK_VERSION_FILE="$SCRIPT_DIR/ndk-version.txt"
REQUIRED_GO_VERSION="go1.27.2"

# Set Android SDK/NDK paths
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"

if [ ! -s "$NDK_VERSION_FILE" ]; then
    echo "Error: Android NDK version pin is missing or empty: $NDK_VERSION_FILE" >&2
    exit 1
fi
EXPECTED_NDK_VERSION="$(< "$NDK_VERSION_FILE")"
if [ -z "$EXPECTED_NDK_VERSION" ]; then
    echo "Error: Android NDK version pin is empty: $NDK_VERSION_FILE" >&2
    exit 1
fi

if [ -n "${ANDROID_NDK_HOME:-}" ]; then
    if [ ! -d "$ANDROID_NDK_HOME" ]; then
        echo "Error: ANDROID_NDK_HOME does not exist: $ANDROID_NDK_HOME" >&2
        exit 1
    fi
else
    export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$EXPECTED_NDK_VERSION"
    if [ ! -d "$ANDROID_NDK_HOME" ]; then
        echo "Error: required Android NDK is not installed." >&2
        echo "  Expected version: $EXPECTED_NDK_VERSION" >&2
        echo "  Expected path: $ANDROID_NDK_HOME" >&2
        exit 1
    fi
fi

NDK_SOURCE_PROPERTIES="$ANDROID_NDK_HOME/source.properties"
if [ ! -f "$NDK_SOURCE_PROPERTIES" ]; then
    echo "Error: Android NDK metadata is missing: $NDK_SOURCE_PROPERTIES" >&2
    exit 1
fi
ACTUAL_NDK_VERSION="$(
    sed -n 's/^[[:space:]]*Pkg\.Revision[[:space:]]*=[[:space:]]*//p' "$NDK_SOURCE_PROPERTIES" \
        | head -n 1 \
        | tr -d '\r'
)"
if [ "$ACTUAL_NDK_VERSION" != "$EXPECTED_NDK_VERSION" ]; then
    echo "Error: Android NDK version mismatch." >&2
    echo "  Expected: $EXPECTED_NDK_VERSION" >&2
    echo "  Actual: ${ACTUAL_NDK_VERSION:-<missing>}" >&2
    echo "  Path: $ANDROID_NDK_HOME" >&2
    exit 1
fi
echo "Using NDK: $ANDROID_NDK_HOME ($ACTUAL_NDK_VERSION)"

if ! command -v go > /dev/null 2>&1; then
    echo "Error: go not found in PATH." >&2
    exit 1
fi
ACTUAL_GO_VERSION="$(go env GOVERSION)"
if [ "$ACTUAL_GO_VERSION" != "$REQUIRED_GO_VERSION" ]; then
    echo "Error: active Go version mismatch." >&2
    echo "  Expected: $REQUIRED_GO_VERSION" >&2
    echo "  Actual: ${ACTUAL_GO_VERSION:-<missing>}" >&2
    exit 1
fi
EXPECTED_MOBILE_VERSION="$(go -C "$GO_SRC_DIR" list -m -f '{{.Version}}' golang.org/x/mobile)"
if [ -z "$EXPECTED_MOBILE_VERSION" ]; then
    echo "Error: could not determine the required Go mobile toolchain version." >&2
    echo "  x/mobile: ${EXPECTED_MOBILE_VERSION:-<missing>}" >&2
    exit 1
fi

validate_mobile_tool() {
    local tool_name="$1"
    local expected_command_path="golang.org/x/mobile/cmd/$tool_name"
    local tool_path
    local metadata
    local actual_command_path
    local actual_module_path
    local actual_module_version
    local actual_go_version

    if ! tool_path="$(command -v "$tool_name")"; then
        echo "Error: $tool_name not found in PATH." >&2
        echo "  Install it with: go install $expected_command_path@$EXPECTED_MOBILE_VERSION" >&2
        return 1
    fi
    if ! metadata="$(go version -m "$tool_path" 2>&1)"; then
        echo "Error: could not inspect $tool_name build metadata." >&2
        echo "  Binary: $tool_path" >&2
        printf '%s\n' "$metadata" >&2
        return 1
    fi

    actual_command_path="$(printf '%s\n' "$metadata" | awk -F '\t' '$2 == "path" { print $3; exit }')"
    actual_module_path="$(printf '%s\n' "$metadata" | awk -F '\t' '$2 == "mod" { print $3; exit }')"
    actual_module_version="$(printf '%s\n' "$metadata" | awk -F '\t' '$2 == "mod" { print $4; exit }')"
    actual_go_version="$(printf '%s\n' "$metadata" | sed -n '1s/^.*: //p')"

    if [ "$actual_command_path" != "$expected_command_path" ]; then
        echo "Error: $tool_name command path mismatch." >&2
        echo "  Expected: $expected_command_path" >&2
        echo "  Actual: ${actual_command_path:-<missing>}" >&2
        echo "  Binary: $tool_path" >&2
        return 1
    fi
    if [ "$actual_module_path" != "golang.org/x/mobile" ]; then
        echo "Error: $tool_name module path mismatch." >&2
        echo "  Expected: golang.org/x/mobile" >&2
        echo "  Actual: ${actual_module_path:-<missing>}" >&2
        echo "  Binary: $tool_path" >&2
        return 1
    fi
    if [ "$actual_module_version" != "$EXPECTED_MOBILE_VERSION" ]; then
        echo "Error: $tool_name module version mismatch." >&2
        echo "  Expected: $EXPECTED_MOBILE_VERSION" >&2
        echo "  Actual: ${actual_module_version:-<missing>}" >&2
        echo "  Binary: $tool_path" >&2
        return 1
    fi
    if [ "$actual_go_version" != "$REQUIRED_GO_VERSION" ]; then
        echo "Error: $tool_name Go version mismatch." >&2
        echo "  Expected: $REQUIRED_GO_VERSION" >&2
        echo "  Actual: ${actual_go_version:-<missing>}" >&2
        echo "  Binary: $tool_path" >&2
        return 1
    fi

    echo "Validated $tool_name: $tool_path ($EXPECTED_MOBILE_VERSION, $REQUIRED_GO_VERSION)"
}

validate_mobile_tool gomobile
validate_mobile_tool gobind

# Always use API level 26 (matches app's minSdk)
USE_ANDROID_API="-androidapi 26"

echo "Building Go Mobile bindings for Android..."
echo "Go source directory: $GO_SRC_DIR"
echo "Output directory: $OUTPUT_DIR"
echo "Android SDK: $ANDROID_HOME"
echo "Android NDK: ${ANDROID_NDK_HOME:-not set}"
echo "Go linker flags: $GOMOBILE_LDFLAGS"

# Create output directory
mkdir -p "$OUTPUT_DIR"

REAL_GO="$(command -v go)"
REAL_GOBIND="$(command -v gobind)"
# Preserve effective Go linker settings while aligning LOAD and RELRO for 16 KB pages.
CGO_LDFLAGS="$($REAL_GO env CGO_LDFLAGS) -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"
export CGO_LDFLAGS
if ! JQ="$(command -v jq)"; then
    echo "Error: jq is required for generated-module replacement validation." >&2
    exit 1
fi
WRAPPER_DIR="$(mktemp -d)"
VERIFY_DIR=""
cleanup() {
    if [ -n "${WRAPPER_DIR:-}" ]; then
        rm -rf -- "$WRAPPER_DIR"
    fi
    if [ -n "${VERIFY_DIR:-}" ]; then
        rm -rf -- "$VERIFY_DIR"
    fi
}
trap cleanup EXIT
VERIFY_DIR="$(mktemp -d)"

if [ -z "${HOME:-}" ] || [ ! -d "$HOME" ]; then
    echo "Error: current user home is unavailable for AAR privacy validation." >&2
    exit 1
fi
USER_HOME="$(cd "$HOME" && pwd -P)"

case "$(uname -s)" in
    Linux)
        NDK_HOST_TAG="linux-x86_64"
        ;;
    Darwin)
        NDK_HOST_TAG="darwin-x86_64"
        ;;
    *)
        echo "Error: unsupported host for pinned NDK llvm-readelf validation." >&2
        exit 1
        ;;
esac
LLVM_READELF="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST_TAG/bin/llvm-readelf"
if [ ! -x "$LLVM_READELF" ]; then
    echo "Error: pinned NDK llvm-readelf is unavailable for AAR validation." >&2
    exit 1
fi

export PICOCRYPT_REAL_GO="$REAL_GO"
export PICOCRYPT_GO_SRC_DIR="$GO_SRC_DIR"
export PICOCRYPT_JQ="$JQ"

cat > "$WRAPPER_DIR/go" <<'EOF'
#!/bin/sh
set -e
REAL_GO="${PICOCRYPT_REAL_GO:?}"
GO_SRC_DIR="${PICOCRYPT_GO_SRC_DIR:?}"
JQ="${PICOCRYPT_JQ:?}"

if [ "$#" -eq 2 ] && [ "$1" = "mod" ] && [ "$2" = "tidy" ]; then
    generated_module="$($REAL_GO list -m -f '{{.Path}}' 2>/dev/null || true)"
    if [ "$generated_module" = "gobind" ]; then
        replacement_path="$($REAL_GO mod edit -json 2>/dev/null | "$JQ" -r '
            [.Replace[]? | select(.Old.Path == "Picocrypt-NG")] as $matches
            | if ($matches | length) == 1 and ($matches[0].Old.Version // "") == "" and ($matches[0].New.Version // "") == "" then $matches[0].New.Path else empty end
        ' 2>/dev/null || true)"
        if [ -z "$replacement_path" ] || [ "$(cd "$replacement_path" 2>/dev/null && pwd -P)" != "$GO_SRC_DIR" ]; then
            echo "Error: generated gobind replacement policy failed." >&2
            exit 1
        fi
        if [ -e localmod ] || [ -L localmod ]; then
            echo "Error: generated gobind localmod policy failed." >&2
            exit 1
        fi
        ln -s "$GO_SRC_DIR" localmod
        "$REAL_GO" mod edit -replace=Picocrypt-NG=./localmod

        replacement_path="$($REAL_GO mod edit -json 2>/dev/null | "$JQ" -r '
            [.Replace[]? | select(.Old.Path == "Picocrypt-NG")] as $matches
            | if ($matches | length) == 1 and ($matches[0].Old.Version // "") == "" and $matches[0].New.Path == "./localmod" and ($matches[0].New.Version // "") == "" then $matches[0].New.Path else empty end
        ' 2>/dev/null || true)"
        if [ "$replacement_path" != "./localmod" ] || [ "$(cd "$replacement_path" 2>/dev/null && pwd -P)" != "$GO_SRC_DIR" ]; then
            echo "Error: generated gobind replacement policy failed." >&2
            exit 1
        fi
    fi
fi

if [ -n "$GOFLAGS" ]; then
    export GOFLAGS="$GOFLAGS -trimpath"
else
    export GOFLAGS="-trimpath"
fi
exec "$REAL_GO" "$@"
EOF
chmod +x "$WRAPPER_DIR/go"

cat > "$WRAPPER_DIR/gobind" <<EOF
#!/bin/sh
set -e
if [ -n "\$GOFLAGS" ]; then
    export GOFLAGS="\$GOFLAGS -trimpath"
else
    export GOFLAGS="-trimpath"
fi
exec "$REAL_GOBIND" "\$@"
EOF
chmod +x "$WRAPPER_DIR/gobind"

# Build AAR
echo "Building AAR..."
cd "$GO_SRC_DIR"

# gomobile uses ANDROID_NDK_HOME environment variable (already set above)
# Always use API level 26 (matches app's minSdk)
PATH="$WRAPPER_DIR:$PATH" gomobile bind \
    -target android/arm64,android/amd64 \
    $USE_ANDROID_API \
    -ldflags="$GOMOBILE_LDFLAGS" \
    -o "$OUTPUT_DIR/picocrypt-mobile.aar" \
    ./mobile

expected_abis="$(printf '%s\n' arm64-v8a x86_64)"
actual_abis="$(
    unzip -Z1 "$OUTPUT_DIR/picocrypt-mobile.aar" \
        | sed -n 's#^jni/\([^/]*\)/libgojni\.so$#\1#p' \
        | LC_ALL=C sort
)"
if [ "$actual_abis" != "$expected_abis" ]; then
    echo "Error: unexpected gomobile AAR ABIs" >&2
    echo "Expected:" >&2
    printf '%s\n' "$expected_abis" >&2
    echo "Actual:" >&2
    printf '%s\n' "$actual_abis" >&2
    exit 1
fi

if ! unzip -qq "$OUTPUT_DIR/picocrypt-mobile.aar" -d "$VERIFY_DIR"; then
    echo "Error: AAR reproducibility policy failed during extraction." >&2
    exit 1
fi

ensure_absent_from_aar() {
    local prohibited_value="$1"
    local policy_name="$2"
    local scan_status

    set +e
    LC_ALL=C grep -a -r -F -q -- "$prohibited_value" "$VERIFY_DIR"
    scan_status=$?
    set -e
    case "$scan_status" in
        0)
            echo "Error: AAR reproducibility policy failed: $policy_name." >&2
            exit 1
            ;;
        1)
            ;;
        *)
            echo "Error: AAR reproducibility policy could not scan: $policy_name." >&2
            exit 1
            ;;
    esac
}

verify_native_so() {
    local abi="$1"
    local native_so="$VERIFY_DIR/jni/$abi/libgojni.so"
    local metadata
    local build_id
    local section_headers
    local program_headers
    local segment first second
    local load_count=0
    local relro_count=0

    if ! metadata="$($REAL_GO version -m "$native_so" 2>/dev/null)"; then
        echo "Error: AAR reproducibility policy failed for ABI $abi: go-build-metadata." >&2
        exit 1
    fi
    if ! printf '%s\n' "$metadata" | awk -F '\t' '$2 == "build" && $3 == "-trimpath=true" { found = 1 } END { exit(found ? 0 : 1) }'; then
        echo "Error: AAR reproducibility policy failed for ABI $abi: trimpath." >&2
        exit 1
    fi
    if ! printf '%s\n' "$metadata" | awk -F '\t' '
        $2 == "dep" && $3 == "Picocrypt-NG" { awaiting_replacement = 1; seen = 1; next }
        awaiting_replacement && $2 == "=>" { if ($3 == "./localmod") exact_replacement = 1; awaiting_replacement = 0; next }
        awaiting_replacement && $2 != "" { awaiting_replacement = 0 }
        END { exit(seen && exact_replacement ? 0 : 1) }
    '; then
        echo "Error: AAR reproducibility policy failed for ABI $abi: project-replacement." >&2
        exit 1
    fi
    if ! printf '%s\n' "$metadata" | awk -F '\t' '
        $2 == "=>" {
            replacement_path = $3
            if (replacement_path ~ /^\// || replacement_path ~ /^[[:alpha:]]:[\\\\/]/ || replacement_path ~ /^\\\\\\\\/) bad = 1
        }
        END { exit(bad ? 1 : 0) }
    '; then
        echo "Error: AAR reproducibility policy failed for ABI $abi: absolute-replacement." >&2
        exit 1
    fi
    if ! build_id="$($REAL_GO tool buildid "$native_so" 2>/dev/null)" || [ -n "$build_id" ]; then
        echo "Error: AAR reproducibility policy failed for ABI $abi: go-buildid." >&2
        exit 1
    fi
    if ! section_headers="$($LLVM_READELF -S "$native_so" 2>/dev/null)"; then
        echo "Error: AAR reproducibility policy failed for ABI $abi: llvm-readelf." >&2
        exit 1
    fi
    if printf '%s\n' "$section_headers" | grep -F -q '.note.gnu.build-id'; then
        echo "Error: AAR reproducibility policy failed for ABI $abi: elf-buildid." >&2
        exit 1
    fi
    if ! program_headers="$($LLVM_READELF -lW "$native_so" 2>/dev/null)"; then
        echo "Error: AAR page alignment validation failed for ABI $abi: llvm-readelf." >&2
        exit 1
    fi
    # Android requires LOAD alignment >= 16 KB and a 16 KB aligned RELRO end.
    # https://developer.android.com/guide/practices/page-sizes
    while read -r segment first second; do
        case "$segment" in
            LOAD)
                load_count=$((load_count + 1))
                if (( first < 16384 )); then
                    echo "Error: AAR 16 KB page alignment failed for ABI $abi: LOAD." >&2
                    exit 1
                fi
                ;;
            GNU_RELRO)
                relro_count=$((relro_count + 1))
                if (( (first + second) % 16384 != 0 )); then
                    echo "Error: AAR 16 KB page alignment failed for ABI $abi: RELRO." >&2
                    exit 1
                fi
                ;;
        esac
    done <<< "$(printf '%s\n' "$program_headers" | awk '$1 == "LOAD" { print $1, $NF } $1 == "GNU_RELRO" { print $1, $3, $6 }')"
    if (( load_count == 0 || relro_count == 0 )); then
        echo "Error: AAR page alignment validation failed for ABI $abi: missing LOAD or RELRO." >&2
        exit 1
    fi
}

for abi in $expected_abis; do
    verify_native_so "$abi"
done

# Trailing slash: only a real path prefix (always followed by content) matches;
# a bare substring like "PCV3/outer/root" in a root-user build must not trip the policy.
ensure_absent_from_aar "$GO_SRC_DIR/" "checkout-path"
ensure_absent_from_aar "$USER_HOME/" "user-home"

echo "✓ Build successful!"
echo "  AAR location: $OUTPUT_DIR/picocrypt-mobile.aar"
