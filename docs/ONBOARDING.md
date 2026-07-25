# Picocrypt-NG — Onboarding Guide

> Generated from the project knowledge graph (commit `caae7a5`, 2026-06-10).
> Regenerate with `/understand` + `/understand-onboard` after major changes.

## Project Overview

**Picocrypt-NG** is a very small, simple, yet paranoid-grade file-encryption tool written in Go — a community-developed continuation of the archived Picocrypt project. It encrypts files into authenticated `.pcv` volumes using the XChaCha20 cipher (with an optional cascaded Serpent-CTR layer in paranoid mode), the Argon2id KDF, and a separate keyed MAC applied encrypt-then-MAC. One audited crypto core ships behind four frontends: a Fyne desktop GUI, a headless Cobra CLI, a browser WASM build, and a native Android app.

- **Languages:** Go (core, ~164 files), Kotlin (Android host), plus YAML/TOML/XML/Markdown/Shell
- **Frameworks:** Fyne (GUI), Cobra (CLI), Jetpack Compose (Android), Gradle, GitHub Actions
- **Core value:** confidentiality + integrity, and byte-for-byte `.pcv` interop with versions 2.08/2.09 — security and backward compatibility beat every other concern

## Architecture Layers

The codebase follows a strict one-directional layer hierarchy (`cmd → ui/cli/wasm/mobile → app → volume → crypto/header/keyfile → encoding/fileops/util`). There are no circular imports.

| Layer | Files | What lives there |
|---|---|---|
| **Entry points** | 7 | Thin entry points in `src/cmd`: build-tag dispatch (`!cli`, `cli`, `js && wasm`) hands off to the interface layer immediately |
| **Interface** | 67 | Fyne GUI (`internal/ui`), Cobra CLI (`internal/cli`), WASM bindings (`internal/wasm`), gomobile bridge (`src/mobile`), and thread-safe app state (`internal/app`) |
| **Volume orchestration** ⚠️ | 26 | AUDIT-CRITICAL: the 8-phase encrypt and 7-phase decrypt pipelines, `OperationContext`, `EncryptRequest`/`DecryptRequest` (`internal/volume`) |
| **Crypto core** ⚠️ | 19 | AUDIT-CRITICAL primitives: XChaCha20 + Serpent-CTR, Argon2id KDF, keyed MAC, volume-header format & auth, keyfile processing (`internal/crypto`, `header`, `keyfile`) |
| **Foundation** | 40 | No crypto/UI deps: Reed-Solomon codecs (`encoding`), file ops (zip/split/recombine, `fileops`), typed errors, structured logging, constants |
| **Android app** | 88 | Kotlin/Jetpack Compose host, `GoBridge` over the gomobile AAR, Gradle build, unit + instrumented tests (`android/`) |
| **CI/CD** | 34 | 12 GitHub Actions workflows: release builds for Linux/macOS/Windows/Android/Snap + PR test builds (`.github/`) |
| **Test data & policies** | 28 | Golden 2.08/2.09 compatibility vectors (`src/testdata`), test-only packages validating dist metadata, CI policy, docs freshness |
| **Docs & config** | 15 | README, ARCHITECTURE, API, CLI, Internals, Changelog, `VERSION`, `go.mod`, `FyneApp.toml`, lint configs |

## Key Concepts

- **Encrypt-then-MAC, not AEAD.** The keystream is unauthenticated XChaCha20; integrity comes from a separate keyed MAC (keyed BLAKE2b-512 normally, HMAC-SHA3-512 in paranoid mode). The Serpent-CTR → XChaCha20 → MAC ordering is **frozen** — never reorder it.
- **One core, four frontends.** The `volume.ProgressReporter` interface (5 methods) and `OperationContext` decouple the pipeline from any UI. GUI, CLI, WASM, and Android all drive the same `volume.Encrypt()`/`Decrypt()`.
- **Build tags, not runtime switches.** GUI vs CLI vs WASM are selected at compile time (`//go:build !cli` / `cli` / `js && wasm`); per-OS variants use file-name conventions (`diskspace_windows.go`, `macos_open_darwin.go`).
- **Golden vectors gate compatibility.** Any change to crypto/header/volume must keep `golden_test.go` green — it decrypts reference 2.08/2.09 volumes from `src/testdata/golden/` and guards byte-level format stability.
- **Secrets are zeroed.** `crypto.SecureZero` + RAII-style `Close()` on `CipherSuite`/`OperationContext`; all key material is wiped on every exit path (verified by `zeroing_exit_test.go`).
- **Resilience extras.** Reed-Solomon header (and optional payload) encoding, plausible deniability (an extra headerless XChaCha20 wrap), keyfiles (ordered = sequential hash, unordered = XOR), and volume splitting.
- **Owned output.** Volume writes use exclusively created random sibling stages
  with retained handles, then sync and publish to the requested path. ZIP, split,
  recombine, and extraction paths use exclusive creation or operation-owned
  intermediates and remove only identities created by that operation. Publication
  differs by pipeline and platform, so do not claim universal rename or crash
  atomicity.

## Guided Tour (13 steps)

1. **Project overview** — `README.md`: what Picocrypt NG is, features, downloads.
2. **Entry points & build tags** — `src/cmd/picocrypt/main.go`, `main_gui.go` (`!cli`), `main_cli.go` (`cli`), `src/go.mod`: `main()` just calls `run()`; build tags pick the implementation.
3. **Frontends: Fyne GUI & Cobra CLI** — `internal/ui/app.go`, `internal/cli/root.go` (note the `detectCLIMode` heuristic), `internal/app/state.go` (RWMutex-guarded single source of truth).
4. **The pipeline contract** — `internal/volume/context.go` + `internal/app/reporter.go`: `ProgressReporter` and `OperationContext` are how every frontend reuses one core.
5. **8-phase encryption** — `internal/volume/encrypt.go`, `internal/fileops/zip.go`: preprocessing (zip), randomness, header write, KDF, keyfiles, auth values, stream encryption, finalization.
6. **7-phase decryption & plausible deniability** — `internal/volume/decrypt.go`, `deniability.go`: recombine, deniability removal, RS header read, key derivation, v1/v2 auth, optional verify-first pass.
7. **Crypto core** — `internal/crypto/{cipher,kdf,mac,rekey,zeroing}.go`: `CipherSuite`, Argon2id, MAC selection, the rekey counter, secure zeroing.
8. **Volume header, Reed-Solomon, keyfiles** — `internal/header/{format,auth}.go`, `internal/encoding/rs.go`, `internal/keyfile/processor.go`: every header field independently RS-encoded; v1 vs v2 header auth.
9. **Specifications** — `Internals.md` (byte-level format spec), `ARCHITECTURE.md` (layer map): read these after seeing the code.
10. **Golden vectors** — `internal/volume/golden_test.go` + `src/testdata/golden/*.pcv`: the 2.08/2.09 byte-for-byte interop gate. Run these before and after touching anything AUDIT-CRITICAL.
11. **WASM frontend** — `src/cmd/wasm/main.go`, `internal/wasm/{encrypt,decrypt}.go`: registers `picocryptEncrypt`/`picocryptDecrypt` JS globals; password-only (no keyfiles/paranoid).
12. **Android frontend** — `src/mobile/android.go` (gomobile exports) → `GoBridge.kt` (JSON-serialized calls) → `MainActivity.kt` (Compose UI).
13. **CI/CD release matrix** — `VERSION` file change triggers the release workflows (`build-linux/windows/macos/android.yml`); its content becomes the release tag.

## File Map (key files by layer)

**Entry points**
- `src/cmd/picocrypt/main.go` — `func main() { run() }`; the build tag decides which `run()` compiles in
- `src/cmd/picocrypt/main_gui.go` / `main_cli.go` — GUI (falls through to `ui.NewApp` if no CLI subcommand) / headless CLI
- `src/cmd/wasm/main.go` — WASM entry, JS global registration

**Interface**
- `src/internal/ui/app.go` — Fyne GUI skeleton; assembles all sections, schedules startup-path handling
- `src/internal/ui/drop.go` — drag-and-drop & startup-argument classification (volume/keyfile/file set)
- `src/internal/ui/open_readiness.go` — iCloud/ubiquitous-file readiness gate (45 s polling, cancelable)
- `src/internal/ui/operations.go` — wires the Start button to the pipeline in a worker goroutine
- `src/internal/cli/root.go` — Cobra root; `Execute(version)`, CLI-vs-GUI detection, SIGINT handling
- `src/internal/cli/encrypt.go` / `decrypt.go` — subcommands incl. stdin/stdout streaming and split/deniability detection
- `src/internal/app/state.go` — thread-safe GUI state (`State` + typed accessors)
- `src/internal/wasm/encrypt.go` / `decrypt.go` — simplified in-memory pipeline for the browser
- `src/mobile/android.go` — gomobile bridge: `StartEncrypt`/`StartDecrypt`/`GetProgress`/`CancelOperation`

**Volume orchestration (AUDIT-CRITICAL)**
- `src/internal/volume/context.go` — `ProgressReporter`, request structs, `OperationContext` with `Close()` zeroing
- `src/internal/volume/encrypt.go` / `decrypt.go` — the 8-phase / 7-phase pipelines
- `src/internal/volume/deniability.go` — add/remove the deniability layer
- `src/internal/volume/validate.go` — request validation

**Crypto core (AUDIT-CRITICAL)**
- `src/internal/crypto/cipher.go` — `CipherSuite`; frozen Serpent→XChaCha20→MAC ordering
- `src/internal/crypto/kdf.go` — Argon2id `DeriveKey`, `RandomBytes`, `SubkeyReader` (HKDF stream order matters)
- `src/internal/crypto/mac.go` — BLAKE2b vs HMAC-SHA3-512 selection
- `src/internal/header/format.go` / `reader.go` / `writer.go` / `auth.go` — typed `VolumeHeader`, RS-encoded fields, v1/v2 auth
- `src/internal/keyfile/processor.go` — ordered/unordered keyfile hashing, key XOR

**Foundation**
- `src/internal/encoding/rs.go` — Reed-Solomon codecs (RS128/RS5/RS1)
- `src/internal/fileops/zip.go` / `unpack.go` / `split.go` / `recombine.go` — archive + chunk lifecycle; `unpack.go` carries the path-traversal/symlink defenses
- `src/internal/errors/errors.go` — sentinel errors + typed error structs
- `src/internal/log/log.go` — structured leveled logging, no-op default

**Android**
- `GoBridge.kt` — Kotlin wrapper over the gomobile AAR
- `OperationManager.kt` — validates `FormData`, starts/polls/cancels operations
- `MainActivity.kt` — Compose screen assembled from cards (file, password, keyfiles, progress)
- `FileCopyService.kt` — SAF → internal-storage copying

**CI/CD & tests**
- `.github/workflows/build-*.yml` — release matrix, triggered by `VERSION` changes
- `src/internal/volume/golden_test.go` + `src/testdata/golden/` — 2.08/2.09 compatibility gate
- `src/internal/volume/roundtrip_test.go` — encrypt→decrypt across all option combinations

## Complexity Hotspots

Approach these with extra care (run `go test ./...` in `src/`, plus `go vet` and `govulncheck`, before and after):

1. **`src/internal/volume/encrypt.go` / `decrypt.go` / `context.go` / `deniability.go`** — AUDIT-CRITICAL pipeline orchestration. Any change here must keep golden + roundtrip tests green. Never reorder cipher/MAC phases or the HKDF subkey read order.
2. **`src/internal/crypto/kdf.go`** — the `SubkeyReader` stream order is a format invariant (v1 vs v2 HKDF layout).
3. **`src/internal/header/reader.go`** — the only validated header parser; comment-length guard and RS retry behavior have regression tests (`rs_corruption_test.go`).
4. **`src/internal/fileops/unpack.go`** — security-hardened zip extraction (path traversal, symlink swaps, Windows name-truncation tricks). Its test file documents the attack catalog.
5. **`src/internal/ui/drop.go` + `open_readiness.go`** — the most intricate UI logic: startup paths, late macOS/iCloud file deliveries, readiness cancellation, races. `drop_test.go` is the largest UI test suite — keep it deterministic.
6. **`src/internal/cli/root.go`** — `detectCLIMode` heuristic distinguishes CLI invocation from GUI-with-file-args; subtle cross-platform behavior.
7. **`src/mobile/android.go` + `OperationManager.kt`** — the cross-language bridge: JSON-serialized options, single-operation lifecycle, cancellation-state protection on both sides.

## Working Conventions (short version)

- Write the failing test first, then fix; small focused commits.
- `go test ./...` + `go vet` + `govulncheck` must be green before closing any phase of work.
- AUDIT-CRITICAL packages (`crypto/`, `header/`, `keyfile/`, `volume/`) — never modify without running golden vectors.
- Match existing style: doc comments on exported symbols, `CRITICAL:`/`SECURITY:` callouts for invariants, build tags over `runtime.GOOS`.
