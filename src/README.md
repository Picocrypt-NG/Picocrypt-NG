# Building from Source

## Prerequisites

**Linux:**
```bash
apt install -y gcc xorg-dev libgtk-3-dev libgl1-mesa-dev libglu1-mesa
```

**macOS:**
```bash
xcode-select --install
brew install glfw glew
```

**Windows:** TDM-GCC or MinGW-w64

## Install Go

Download from [go.dev/dl](https://go.dev/dl/) or use your package manager. Use exactly Go 1.27.3 for development and release builds.

## Build

```bash
git clone https://github.com/Picocrypt-NG/Picocrypt-NG.git
cd Picocrypt-NG/src

# Linux/macOS
CGO_ENABLED=1 go build -tags migrated_fynedo -ldflags="-s -w" -o Picocrypt-NG ./cmd/picocrypt

# Windows
CGO_ENABLED=1 go build -tags migrated_fynedo -ldflags="-s -w -H=windowsgui -extldflags=-static" -o Picocrypt-NG.exe ./cmd/picocrypt
```

## Run

```bash
./Picocrypt-NG
```

## Android

The Android build path now lives in the repository root `android/` project and uses gomobile bindings from `src/mobile/`. See `../android/README.md` for the native Android app build instructions.

## WebAssembly

The in-memory single-file bridge creates PCV3 and reads supported PCV1/PCV2/PCV3 volumes. PCV3 accepts a password, keyfiles, or both; D1 requires explicit selection. It supports comments, Paranoid mode, Reed-Solomon and visibly unverified Force output. `picocryptCapabilities()` advertises the size limits; admission preserves the fixed 1 GiB KDF but cannot observe physical browser headroom. Folder, split and streaming workflows remain native features. Owned Go buffers are wiped best-effort, without a guarantee for JavaScript/runtime copies. See `../API.md` for the bridge contract. The separately deployed website requires its own runtime checks.

## Test

```bash
# Default local suite; serialize packages that run the fixed 1 GiB KDF
go test -p 1 -tags migrated_fynedo ./...

# Complete Linux native production-KDF operation and CLI lane (run separately)
bash ../.github/scripts/test-production-kdf.sh

# Golden compatibility checks with production KDF
go test -count=1 -run '^TestGolden' ./internal/volume

# Actual JavaScript/WASM bridge and independent memory-codec fixtures.
# Includes serial production KDFs; run separately from other heavy suites.
../.github/scripts/test-wasm.sh

# CLI package tests, including default binary-regression coverage
go test ./internal/cli

# Opt-in stdin/stdout CLI integration tests
PICOCRYPT_RUN_CLI_INTEGRATION=1 go test ./internal/cli

# Race-sensitive Go work; serialize KDF-heavy packages
CGO_ENABLED=1 go test -tags migrated_fynedo -race -p 1 -timeout 15m ./...
```

The complete Linux native production-KDF lane also runs from the repository root with
`mise run test:production-kdf` or `jouet test --cmd -- mise run test:production-kdf`.
It includes all compiled production-tagged operation and CLI tests, enables CLI
integration, and rejects selectors, inherited test overrides and unexpected skips.
Run it separately from other heavy suites. It retains execution JSON, tool/source
identity and timing/memory reports in a fresh temporary directory printed at start;
`PICOCRYPT_PRODUCTION_KDF_REPORT_DIR` can name a new directory under an existing
parent. Linux and GNU `timeout` are required. Bootstrap allows 30 seconds for
`go env` and 5 minutes to compile the runner, each with a 2-second forced-kill
grace period (less than 6 minutes total). The runner then has a separate 60-minute
execution budget, with 30 minutes per test package; the Linux job allows 75 minutes.
These limits remain provisional until hosted CI measurement:
one local run completed in about 15 minutes with two CPUs, a 4 GiB memory cap and
no swap. CI uses `GOMEMLIMIT=2GiB` and `GOMAXPROCS=2`; these settings do not reduce
the fixed KDF profile.

## Notes

### Local quality checks

Run these commands from the repository root after `mise install`:

```sh
mise run hk:check                # formatting, vet, lint and workflow checks
jouet diag check --changed       # diagnostics for current changed files
mise run workflows:lint          # all repository workflows, offline
mise run tooling:fmt             # Go production-KDF helper formatting
mise run tooling:lint            # helper Go static analysis, SARIF
jouet test                      # separate default Go suite
```

hk runs checks without fixes, staging or stashing. Go vet and lint keep the
project's module and build tags and analyze the whole module. The commit and
push hooks run all quality checks, including for deleted files; targeted
diagnostics alone are not a commit gate. Production-KDF, golden, race,
WASM and Android test commands remain separate.

Before a GitButler CLI commit, run `mise run hk:check`, inspect `but diff`,
and select the intended files or hunks. Do not rely on `but commit` invoking
pre-commit. Checks read working-tree files, including changes from other applied
branches; they do not verify an isolated branch or selected hunk. CI checks the
actual published branch tree.

For the GitButler GUI, enable **Run Git hooks** in the project's **Git stuff**
settings. Preserve an existing GitButler guard hook: when it supports
`pre-commit-user`, connect hk there rather than overwriting the guard. Linked
worktrees require explicit checks because their GUI commit path skips hooks.
Local hook scripts are machine-specific and are not part of a clone.

The workflow gate checks workflows and local composite actions using pinned
jactionlint, ShellCheck and Ruff with the default
profile, no baseline and no online lookups. Missing analyzers fail the check.
Tooling integration tests can be run with
`jouet test --cmd -- mise run tooling:test`; they cover real hk analyzer diagnostics
on every host. On Linux they also execute the production-KDF runner helper in
normal and race modes. Other hosts compile the Linux helper tests without running
them and explicitly report that Linux unit/race execution remains required.
Helper static analysis always targets Linux with CGO disabled. These are tooling
checks, separate from production-KDF product tests.

The separate [formal checks](../verification/README.md) provide reproducible
EasyCrypt model and Go source-contract commands with explicit scope limits.
They are distinct from the Go tests above and do not establish whole-application
refinement.

- On Linux without hardware OpenGL: `LIBGL_ALWAYS_SOFTWARE=1 ./Picocrypt-NG`
- If accessibility bus causes issues: `NO_AT_BRIDGE=1 ./Picocrypt-NG`
