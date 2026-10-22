#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
if command -v sha256sum > /dev/null 2>&1; then
    hash_command=(sha256sum)
elif command -v shasum > /dev/null 2>&1; then
    hash_command=(shasum -a 256)
else
    echo 'Android gomobile policy requires sha256sum or shasum' >&2
    exit 1
fi

# Exercise the emitted build wrapper; these checks do not run Android or a KDF.
# shellcheck disable=SC2016
sed -n '/^cat > "\$WRAPPER_DIR\/go" <<'"'"'EOF'"'"'$/,/^EOF$/p' "$root/android/build-gomobile.sh" \
    | sed '1d;$d' > "$work/go-wrapper"
test -s "$work/go-wrapper"
cat > "$work/go" <<'GO'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
    list)
        if [[ $2 == -m ]]; then printf 'gobind\n'; else printf '%s\n' "${TEST_DEFAULT_GODEBUG:-}"; fi
        ;;
    build) printf '%s\0' "$@" > "${TEST_ARGUMENTS:?}" ;;
    *) exit 99 ;;
esac
GO
chmod +x "$work/go"
export PICOCRYPT_REAL_GO="$work/go" PICOCRYPT_GO_SRC_DIR="$root/src" PICOCRYPT_JQ=jq PICOCRYPT_RUNTIME_DEFAULTS_DIR="$work"
export GOOS=android GOARCH=arm GOFLAGS=-buildvcs=false TEST_ARGUMENTS="$work/arguments"
caller_flags="-s -w -buildid= -X example.label=kept '-extldflags=-Wl,--as-needed -Wl,-z,relro'"
export TEST_DEFAULT_GODEBUG=containermaxprocs=0,panicnil=1
bash "$work/go-wrapper" build -ldflags "$caller_flags" -buildmode=c-shared -o=libgojni.so ./gobind
mapfile -d '' -t arguments < "$TEST_ARGUMENTS"
expected="$caller_flags -X=runtime.godebugDefault=$TEST_DEFAULT_GODEBUG,madvdontneed=1"
[[ ${arguments[2]} == "$expected" ]] || { echo 'Android runtime defaults or caller linker flags were lost' >&2; exit 1; }
[[ ${arguments[3]} == -buildmode=c-shared && ${arguments[5]} == ./gobind ]]
[[ $(cat "$work/runtime-defaults-arm") == "$TEST_DEFAULT_GODEBUG,madvdontneed=1" ]]

export TEST_DEFAULT_GODEBUG=
bash "$work/go-wrapper" build "-ldflags=$caller_flags" -buildmode=c-shared ./gobind
mapfile -d '' -t arguments < "$TEST_ARGUMENTS"
[[ ${arguments[1]} == "-ldflags=$caller_flags -X=runtime.godebugDefault=madvdontneed=1" ]]

reject() {
    rm -f -- "$TEST_ARGUMENTS"
    if bash "$work/go-wrapper" "$@" > "$work/rejection" 2>&1; then
        echo "Android build policy unexpectedly accepted: $*" >&2
        exit 1
    fi
    test ! -e "$TEST_ARGUMENTS"
    grep -Eq 'runtime defaults|runtime[.]godebugDefault|linker flags|gobind' "$work/rejection"
}
reject build -ldflags '-X=runtime.godebugDefault=madvdontneed=0' -buildmode=c-shared ./gobind
reject build -ldflags '-X runtime.godebugDefault=madvdontneed=1' -buildmode=c-shared ./gobind
GOFLAGS='-ldflags=-X=runtime.godebugDefault=madvdontneed=0' reject build -ldflags "$caller_flags" ./gobind
TEST_DEFAULT_GODEBUG=madvdontneed=0 reject build -ldflags "$caller_flags" ./gobind
TEST_DEFAULT_GODEBUG=madvdontneed=1,madvdontneed=0 reject build -ldflags "$caller_flags" ./gobind
reject build -buildmode=c-shared ./gobind
reject build -ldflags "$caller_flags" -ldflags "$caller_flags" ./gobind
reject build -ldflags "$caller_flags" ./unexpected
if GOMOBILE_LDFLAGS='-s -w -X=runtime.godebugDefault=madvdontneed=0' \
    bash "$root/android/build-gomobile.sh" > "$work/rejection" 2>&1; then
    echo 'Caller runtime override reached the Android build' >&2
    exit 1
fi
grep -Fq 'runtime.godebugDefault is reserved' "$work/rejection"

unset GOOS GOARCH GOFLAGS
[[ $(go env GOHOSTOS) == linux ]] || { echo 'The c-shared ELF policy control requires a Linux host' >&2; exit 1; }
host_arch=$(go env GOHOSTARCH)
ndk=${ANDROID_NDK_HOME:-${ANDROID_HOME:-$HOME/Android/Sdk}/ndk/$(cat "$root/android/ndk-version.txt")}
LLVM_READELF="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
test -x "$LLVM_READELF"
sed -n '/^verify_runtime_defaults() {$/,/^}$/p' "$root/android/build-gomobile.sh" > "$work/artifact-policy"
test -s "$work/artifact-policy"
# shellcheck source=/dev/null
source "$work/artifact-policy"
mkdir "$work/control"
printf 'module android-runtime-policy-control\n\ngo 1.27.2\n' > "$work/control/go.mod"
printf 'package main\nimport "C"\nfunc main() {}\n' > "$work/control/main.go"
for flag in 0 1; do
    GOOS=linux GOARCH="$host_arch" GOMAXPROCS=1 CGO_ENABLED=1 \
        go -C "$work/control" build -p 1 -trimpath -buildmode=c-shared \
        -ldflags="-s -w -buildid= -X=runtime.godebugDefault=panicnil=1,madvdontneed=$flag" \
        -o "$work/control-$flag.so" .
    metadata=$(go version -m "$work/control-$flag.so")
    grep -Fq -- '-trimpath=true' <<< "$metadata"
    if grep -F -- '-ldflags=' <<< "$metadata"; then
        echo 'Review Go trimpath build-metadata behavior' >&2
        exit 1
    fi
done
verify_runtime_defaults "$work/control-1.so" 'panicnil=1,madvdontneed=1'
if verify_runtime_defaults "$work/control-0.so" 'panicnil=1,madvdontneed=1' || \
    verify_runtime_defaults "$work/control-1.so" 'madvdontneed=1'; then
    echo 'ELF runtime-default tripwire accepted missing or partial defaults' >&2
    exit 1
fi

# The linker target is internal to this exact Go toolchain. Re-review on updates.
[[ $(go env GOVERSION) == go1.27.2 ]]
goroot=$(go env GOROOT)
while read -r expected path; do
    actual=$("${hash_command[@]}" "$goroot/$path" | cut -d' ' -f1)
    [[ $actual == "$expected" ]] || { echo "Review Android reclamation hook after Go source change: $path" >&2; exit 1; }
done <<'HASHES'
fe478d164989b5cd5783c9820d99879623780ba353f836f499238e76efb24fd8 src/runtime/runtime.go
3eee37fa8927b469e4f746598d79a6df3efc58f85e0ccd2ecddc88075ad75dd1 src/runtime/runtime1.go
08cc392d6b540338b966c9593691a700d8ac99ce4081f444f792b994e37b52c7 src/runtime/mem_linux.go
a4bc6dc3acd35967397788da7333a8ddb2636a45c7714655c521405ad98f0f09 src/runtime/rt0_android_arm.s
683f194afd2b24ab16bfb09863207df2c38a3b3c319ffd5678682b57998d44b9 src/runtime/rt0_android_arm64.s
1f52f25a10577cc79be49d997a867025b49626e0a749c0c46fdc4601c681870e src/runtime/rt0_android_386.s
61cf51ba582f3b88e25c7539a1d48897ba6498260e4eb71e44a40e058458f152 src/runtime/rt0_android_amd64.s
13359b8707e78300e8e0ec880b9a8d1af4bafdf32140b56df5f041a52fbc1325 src/cmd/go/internal/work/gc.go
d6e1adb610ec55f2e8bc0afd361eedd6e38689684bca122b02873da1d0ed1584 src/cmd/go/internal/load/pkg.go
2f51cea9197f1fc3dc4ccb62738f807400817a9759b960c5fbcf4403d7f5f08d src/cmd/link/internal/ld/data.go
HASHES
echo 'Android gomobile build policy passed (tooling checks only)'
