# Picocrypt-NG v2.19 Android localization and release preparation design

## Status and decision

- Status: draft for written-spec review.
- Date: 2026-07-20.
- Target branch: `prepare-2.19`.
- Base commit: `65325e1` (merge of dependency PR #239 into `main`).
- Decision: ship complete native Android catalogs for every complete desktop
  locale that Android does not yet have, remove raw backend English from the
  Android display boundary, apply only evidenced safe-stable tooling updates,
  and keep cryptographic and volume-format behavior unchanged.

This design is governed by [AGENTS.md](../../../AGENTS.md), the
[translation guide](../../localization/TRANSLATION_GUIDE.md),
[Weblate setup](../../localization/WEBLATE_SETUP.md),
[Android architecture and build notes](../../../android/README.md),
[ARCHITECTURE.md](../../../ARCHITECTURE.md), [API.md](../../../API.md),
[SIGNING.md](../../../SIGNING.md), [Changelog.md](../../../Changelog.md), and
the root [VERSION](../../../VERSION). Executable configuration and tests take
precedence when those documents disagree.

## Context

The desktop and Android applications have separate platform-native string
catalogs. Desktop strings are keyed JSON under
`src/internal/ui/translation/`; Android strings are resources under
`android/app/src/main/res/`. Desktop translation PRs therefore do not
automatically localize the native Android application.

At the base commit, desktop has complete catalogs for English, Russian,
German, French, Spanish, Simplified Chinese, and Hindi. Android has only base
English and Russian. The missing Android catalogs are therefore exactly:

- German (`de`);
- French (`fr`);
- Spanish (`es`);
- Simplified Chinese (`zh-Hans`);
- Hindi (`hi`).

Italian is registered as possible desktop language metadata, but
`src/internal/ui/translation/it.json` does not exist. It is not a shipped,
complete desktop translation and is not included in this work. The Italian
references in the translation and Weblate documentation are documentation
drift that must not be converted into an unsupported release claim.

The Android base catalog currently contains 112 translatable strings and three
plural resources. Only a small subset of its English copy is literally shared
with desktop. Desktop catalogs are therefore terminology and tone references,
not mechanically reusable Android catalogs. Android-only screens, lifecycle
messages, Storage Access Framework errors, foreground notifications, and
security warnings need independent translation and review.

There is a second localization boundary problem. `volume.ProgressReporter`
emits English text for desktop and CLI consumers. The current gomobile bridge
stores that text in `ProgressResult`, and both Compose and the Android
foreground-service notification render it directly. Unknown errors can also
surface raw Go or JVM exception messages. Adding XML catalogs without fixing
that boundary would still leave important Android operation flows in English.

## Goals and success criteria

The work is successful only when all of the following are true:

1. Android has complete, buildable `de`, `fr`, `es`, `zh-Hans`, and `hi`
   catalogs with exact base-resource parity.
2. Every catalog has the required plural categories and preserves the exact
   positional placeholder contract.
3. Security-critical copy retains Picocrypt-NG's implemented meaning and has
   language-specific human review evidence.
4. Android 13 and newer expose every shipped locale in system per-app language
   settings through a generated `LocaleConfig`.
5. Compose and foreground notifications render semantic status codes and typed
   arguments through one Android resource-backed renderer.
6. Raw Go/JVM status, progress-info, and error strings remain diagnostic data
   only and never become a normal user-facing fallback.
7. Authentication, corruption, force-decrypt, cancellation, and retry behavior
   remain exactly as constrained below.
8. No production code in `src/internal/crypto`, `src/internal/header`,
   `src/internal/keyfile`, `src/internal/volume`, or `src/internal/fileops` is
   changed for localization.
9. Only demonstrated safe-stable dependency or release-tool changes are made;
   speculative indirect Go overrides and prerelease dependencies are excluded.
10. Go, Android, golden compatibility, race, policy, build, scanner, and
    release checks pass with every skip or external blocker reported.

## Scope

### Included

- Five complete Android locale catalogs and their resource-contract tests.
- Generated Android per-app language configuration.
- A typed status and progress-info classification layer in `src/mobile`.
- A shared Kotlin status renderer used by Compose and the foreground service.
- Resource-backed Android error presentation with raw technical diagnostics
  kept separate.
- The mobile reporter concurrency fix required by the new structured state.
- Documentation of the updated gomobile bridge contract.
- Safe-stable release-tool updates and bounded Windows download retries.
- Release-facing metadata needed to describe the actual v2.19 result.
- Full verification and a new draft PR from `prepare-2.19` after local gates
  pass.

### Not included

- Any cryptographic algorithm, KDF, header, keyfile, deniability, Reed-Solomon,
  encrypted-volume format, or compatibility change.
- A redesign of `volume.ProgressReporter` or typed status changes for desktop
  and CLI consumers.
- CLI localization, web/WASM localization, or translation of user-authored
  volume comments.
- An Android in-app language selector. Android 13+ system settings are the
  supported selector in this scope; the app continues following the system
  locale on older Android versions.
- Italian localization without a complete reviewed desktop catalog and a
  separate admission decision.
- Prerelease AGP, Kotlin, Gradle, AndroidX, Go, or GitHub Action versions.
- Forced indirect Go dependency versions merely because `go list -m -u all`
  reports a newer module in the build list.
- Closing or rewriting the old release PR #229 before its replacement is fully
  verified and published.

## Sources of truth and invariants

The following invariants are release-blocking:

- Base Android English in `values/strings.xml` owns Android resource IDs and
  placeholder meaning.
- A shipped locale must be complete. Android's English resource fallback is a
  safety net, not an acceptable way to ship a partially translated locale.
- UI state stores semantic codes and arguments when text may be resolved under
  a different locale later.
- Raw backend text must not be translated as source copy and must not be the
  user-visible fallback.
- Positional placeholders such as `%1$s`, `%1$d`, and `%1$.2f` are mandatory;
  translators may reorder them but may not add, remove, or change their types.
- Technical extensions and protocol tokens remain arguments or
  `translatable="false"` values; translators do not rewrite them.
- Authentication failure never enables force-decrypt. Recoverable data
  corruption may enable force-decrypt. Header corruption does not.
- New gomobile fields require a newly built AAR and must never rely on a stale
  checked-in or locally cached binding.
- Any unmapped production status template must fail closed to localized
  “Working…” and fail an executable contract test.
- Release signing readiness is established by live signing-service state, not
  by the presence of workflow YAML.

## Current-state inventory

| Surface | Complete locales at base | Relevant gap |
|---|---|---|
| Desktop Fyne | `en`, `ru`, `de`, `fr`, `es`, `zh-Hans`, `hi` | None in this scope |
| Native Android | `en`, `ru` | Missing `de`, `fr`, `es`, `zh-Hans`, `hi` |
| CLI | English-only contract | Localization is out of scope |
| Web/WASM bridge | No hosted UI catalog in this repository | Localization is out of scope |

Clean baseline evidence before implementation:

- `go test -tags migrated_fynedo ./...` passes. Its two documented conditional
  skips are the opt-in CLI integration test and a symlink-prefix test that is
  inapplicable to the current temporary directory.
- The golden v1/v2 compatibility command passes with no skips.
- `mise run android:test` builds the gomobile AAR and passes 175 JVM tests with
  no failures or skips.
- The generated baseline AAR contains only the documented `arm64-v8a` and
  `x86_64` ABIs.

## Android localization design

### Catalog layout

Add these files:

```text
android/app/src/main/res/values-de/strings.xml
android/app/src/main/res/values-fr/strings.xml
android/app/src/main/res/values-es/strings.xml
android/app/src/main/res/values-b+zh+Hans/strings.xml
android/app/src/main/res/values-hi/strings.xml
```

`values-b+zh+Hans` is the correct Android BCP-47 resource qualifier for
Simplified Chinese and is supported at Picocrypt-NG's API 24 minimum. It also
preserves the desktop locale's explicit script distinction instead of reducing
it to ambiguous `zh`.

Each file contains every translatable base string and every base plural
resource, in base-file order. It does not duplicate the non-translatable
`app_name`. The locale matrix becomes `en`, `ru`, `de`, `fr`, `es`, `zh-Hans`,
and `hi`.

### Resource contract

Generalize `LocalizationResourcesTest.kt` from Russian-specific parity checks
to a data-driven locale matrix. For every locale the tests enforce:

- exact ordered equality of translatable string names with the base catalog;
- exact equality of plural resource names with the base catalog;
- no duplicate string or plural name;
- no missing, empty, or English-identical P0/P1 translation unless the value
  is an intentionally invariant technical term;
- an identical multiset of positional format specifiers for every string;
- an identical format-specifier contract for every plural form;
- no raw `.pcv`, `.zip`, `.bin`, or `.incomplete` translator-owned extension
  where the base contract requires an argument;
- the existing `file(s)` prohibition and non-translatable `app_name` rule.

Required plural categories are:

| Locale | Required Android quantities |
|---|---|
| `en`, `de`, `hi` | `one`, `other` |
| `fr`, `es` | `one`, `many`, `other` |
| `ru` | `one`, `few`, `many`, `other` |
| `zh-Hans` | `other` |

The executable locale matrix, not this prose table alone, is authoritative.
Every required form contains the correct count placeholder even when two forms
have identical visible wording.

### Translation and review method

The base Android English catalog is translated for Android context. Desktop
catalogs and the terminology guide seed terms and voice, but strings are not
copied by key or position because the catalog schemas and UI contexts differ.

Each locale receives two review layers:

1. A deterministic structural review covering resource parity, XML validity,
   placeholders, plurals, prohibited wording, and technical-token handling.
2. A human native or near-native linguistic review covering Android context,
   truncation, tone, grammar, and the P0/P1 security set.

The P0/P1 set includes at minimum password/keyfile authentication, corrupted
data, corrupt header, force-decrypt, verify-first, plaintext comment metadata,
deniability, deletion, storage errors, cancellation, and retry guidance.
Existing desktop review evidence for Simplified Chinese or Hindi does not
approve Android-only adaptations. The release PR remains draft until review
evidence for all five Android catalogs is attached or linked.

Real-device or emulator review covers:

- German, French, and Spanish expansion without clipped controls;
- Simplified Chinese glyph choice and line breaking;
- Hindi shaping, conjuncts, matras, dotted-circle absence, and vertical
  clipping;
- long notifications and progress cards;
- system font scale and the existing debug pseudolocales.

### Per-app language discovery

Enable AGP's generated locale configuration and restrict packaged languages to
the intended application set in the application module:

```kotlin
androidResources {
    generateLocaleConfig = true
    localeFilters += listOf(
        "en",
        "ru",
        "de",
        "fr",
        "es",
        "b+zh+Hans",
        "hi",
    )
}
```

Add `android/app/src/main/res/resources.properties` with:

```properties
unqualifiedResLocale=en
```

AGP derives the locale configuration from the resulting `values-*` resources
and injects the generated manifest reference. No manual
`res/xml/locale_config.xml` or `android:localeConfig` entry is added. A policy
test verifies that the release variant contains exactly the seven intended
locales and that no dependency-only locale leaks into the user-visible list.
Debug-only `en-XA` and `ar-XB` pseudolocales remain test resources and are
not release locales.

This follows Android's current
[automatic per-app language support](https://developer.android.com/guide/topics/resources/app-languages#automatic-support)
guidance: generated configuration requires `generateLocaleConfig`, a declared
unqualified default locale, and an explicit resource filter when dependency
translations must not expand the supported-language list.

The app does not add an in-app picker or AndroidX locale-storage behavior in
this scope. Android 13+ exposes the system selector; Android 12 and older keep
following the system locale.

## Typed mobile status boundary

### Data flow

The approved flow is:

```text
volume/fileops English reporter templates
    -> src/mobile androidProgressReporter classifier
    -> ProgressState / ProgressResult stable codes and typed arguments
    -> GoBridge Kotlin data classes
    -> one resource-backed OperationStatus renderer
    -> Compose ProgressCard and foreground notification
```

The classifier is deliberately at the mobile boundary. Moving it into
`src/internal/volume` would broaden the change into audit-critical production
code and alter desktop/CLI contracts. Mapping raw strings only in Kotlin would
leave English as durable mobile state and duplicate parsing across UI and
service consumers.

### Go bridge fields

Add a focused `src/mobile/status.go` classifier. Extend both `ProgressState`
and exported `ProgressResult` with:

```go
StatusCode              string
StatusSpeedMiBPerSecond float64
StatusETA               string
InfoCode                string
InfoCurrent             int64
InfoTotal               int64
```

Existing `Status`, `Info`, `Error`, and error `Code` fields remain available
for diagnostics and compatibility with current bridge tests. Android must not
render those raw fields. `Progress` remains the canonical numeric fraction.

`StatusETA` is accepted only when it matches the backend's validated
`HH:MM:SS` shape. Speed is parsed into a finite, non-negative numeric value.
Malformed arguments classify as `UNKNOWN`; Android never interpolates the raw
template as fallback.

### Status code contract

Terminal codes:

```text
STARTING
COMPLETED
CANCELLED
ERROR
```

Static phase codes:

```text
COMPRESSING_FILES
GENERATING_VALUES
DERIVING_KEY
READING_KEYFILES
CALCULATING_VALUES
WRITING_VALUES
SPLITTING
RECOMBINING_CHUNKS
READING_VALUES
DUPLICATE_KEYFILES_WARNING
VERIFYING_INTEGRITY
MAC_VERIFICATION_FAILED_CONTINUING
REPAIRING_VERIFYING
INTEGRITY_VERIFIED_DECRYPTING
COMPARING_VALUES
UNZIPPING
ADDING_PLAUSIBLE_DENIABILITY
REMOVING_DENIABILITY_PROTECTION
```

Rate codes:

```text
COMPRESSING_RATE
ENCRYPTING_RATE
SPLITTING_RATE
RECOMBINING_RATE
VERIFYING_RATE
DECRYPTING_RATE
REPAIRING_RATE
UNPACKING_RATE
ADDING_DENIABILITY_RATE
REMOVING_DENIABILITY_RATE
```

Fallback code:

```text
UNKNOWN
```

Static messages use exact equality. Rate messages use anchored full-string
patterns for the existing `%.2f MiB/s (ETA: HH:MM:SS)` templates. Substring
matching is prohibited. The classifier normalizes no arbitrary prose.

### Progress-info code contract

`InfoCode` is one of:

```text
NONE
PERCENT
ITEM_COUNT
UNKNOWN
```

- `PERCENT` is rendered from numeric `Progress` with locale-aware Android
  number formatting. The raw backend text, including `"(verifying)"`, is not
  shown.
- `ITEM_COUNT` carries `InfoCurrent` and `InfoTotal`; Android chooses the
  localized plural resource.
- `NONE` renders no secondary line.
- `UNKNOWN` hides the secondary line while preserving raw `Info` for
  diagnostics.

The verify-first phase is conveyed by `StatusCode`; it is not encoded in an
English suffix attached to percentage text.

### Atomicity and lifecycle

The current reporter reads a state copy and then writes the full status and
progress tuple. Concurrent `SetStatus` and `SetProgress` calls can therefore
overwrite a newer field with a stale copy. The structured bridge fixes this at
the same boundary:

- `SetStatus` acquires the progress-map lock once and changes only raw status,
  status code, speed, and ETA.
- `SetProgress` acquires the lock once and changes only numeric progress, raw
  info, info code, and item arguments.
- terminal transitions set their raw diagnostic value and semantic code in the
  same critical section.
- `getProgress` copies every raw and structured field under the read lock.

Race tests must exercise concurrent status and progress updates and run under
`go test -race`. No new goroutine, queue, or general event abstraction is
introduced.

### Kotlin state and renderer

`GoBridge.ProgressState` carries status code/arguments, progress info
code/arguments, completion state, and error code/text separately. It does not
overload `info` with an error.

Introduce small immutable Kotlin display models in `OperationStatus.kt`, for
example:

```kotlin
data class OperationStatusData(
    val code: String,
    val speedMiBPerSecond: Double = 0.0,
    val eta: String = "",
)

data class OperationProgressDetail(
    val code: String,
    val current: Long = 0,
    val total: Long = 0,
)
```

`OperationUiState.Running` stores these semantic values and the numeric
fraction. One renderer resolves them with an Android `Context` or resources.
Both `ProgressCard` and `OperationForegroundService` call this renderer.
Direct `.setContentText(rawStatus)` and direct rendering of raw Go fields are
guarded against by tests.

Unknown status renders localized “Working…”. Unknown info renders nothing.
This is a fail-safe degradation: a newly introduced backend phase remains
usable without exposing English, while the source-contract test still fails
and forces maintainers to add the intended localized mapping.

## Error presentation

The existing stable Go error `Code` remains distinct from status codes. Android
maps it as follows:

| Go error code | User-facing result | Security action |
|---|---|---|
| `AUTH_FAILED` | localized password/keyfile authentication failure | password retry only; never force-decrypt |
| `DATA_CORRUPTED` | localized damaged-data warning | force-decrypt may be offered |
| `CORRUPT_HEADER` | localized corrupt-header failure | no force-decrypt |
| `FILE_NOT_FOUND` | localized missing-file failure | no force-decrypt |
| `CANCELLED` | localized cancellation | normal cancelled terminal state |
| `GENERIC`, empty, unknown | localized operation-failed fallback | no special recovery action |

Authentication continues to take precedence when an error chain could also be
classified as corruption. Raw Go/JVM text is stored only in
`technicalMessage`; it does not populate visible `userMessage` fallback text.
`AppError.fromException` likewise returns a resource-backed generic or
recognized local error while retaining exception detail diagnostically.

Existing resources `error_read_folder_failed`, `error_copy_files_failed`, and
`keyfile_create_failed` intentionally contain a positional reason placeholder.
That contract is preserved. The value supplied to the placeholder becomes a
small localized reason classification such as permission denied, missing file,
insufficient storage, I/O failure, or unknown cause. It is never the raw
exception message. This keeps useful user context without weakening the
existing placeholder tests or leaking English diagnostics.

## Dependency and tooling policy

### Safe-stable version decision

The dependency audit is evaluated as of 2026-07-20. Current executable pins
already use the latest applicable stable releases for:

- Go 1.26.5;
- Gradle 9.6.1;
- Android Gradle Plugin 9.3.0;
- Kotlin 2.4.10;
- AndroidX Core 1.19.0, Test JUnit 1.3.0, Espresso 3.7.0, Lifecycle
  2.11.0, and Activity 1.13.0;
- Compose BOM 2026.06.01 and material icons 1.7.8;
- coroutines 1.11.0, MockK 1.14.11, Architecture Components testing
  2.2.0, DocumentFile 1.1.0, and org.json 20260719;
- all externally referenced GitHub Actions, including setup-go 7.0.0 and
  setup-java 5.6.0 merged through PRs #236 and #237.

AGP 9.4.0 alpha builds and Kotlin 2.4.20 Beta are prerelease and are excluded.
Gradle 9.6.1 exceeds AGP 9.3.0's documented Gradle 9.5.0 minimum. No Android
library version is changed merely to produce churn.

Primary release evidence is the official
[AGP 9.3.0 compatibility table](https://developer.android.com/build/releases/agp-9-3-0-release-notes),
[Gradle 9.6.1 release notes](https://docs.gradle.org/9.6.1/release-notes.html),
and [Kotlin release history](https://kotlinlang.org/docs/releases.html).

### Go module decision

`go mod tidy -diff` is clean. `govulncheck` finds no reachable symbol- or
package-level vulnerability in Picocrypt-NG. It reports one module-level
advisory, GO-2026-5932, for the unused `x/crypto/openpgp` package and offers no
applicable fix. GitHub Dependabot has no open alerts at the audit point.

The eleven newer indirect modules reported by `go list -m -u all` are not an
approved update set. Ten are upstream test/build-list nodes that are not
compiled into Picocrypt-NG. The only compiled candidate, `bild`, remains pinned
by Fyne 2.8.0 and its newer release has no applicable fix for the code paths
Picocrypt-NG uses. Adding any of these versions to the main module would be a
forced Minimal Version Selection override without demonstrated security or
runtime benefit.

Therefore `src/go.mod` and `src/go.sum` remain unchanged in this release work.
An indirect override becomes admissible only for a reachable vulnerability or
bug with focused regression proof, or when its direct parent updates the pin.

### Approved release-tool changes

Apply these narrow changes:

1. Update `cosign-release` in
   `.github/actions/sign-and-attest/action.yml` from `v3.1.1` to stable
   [`v3.1.2`](https://github.com/sigstore/cosign/releases/tag/v3.1.2). Keep the
   verified `sigstore/cosign-installer` v4.1.2 commit SHA.
2. Replace the nonofficial Resource Hacker GitHub user attachment with the
   [vendor's direct installer](https://www.angusj.com/resourcehacker/)
   `https://www.angusj.com/resourcehacker/reshacker_setup.exe` for version
   5.2.8 and pin SHA-256
   `b611be2f35cb44efd1c29df03e7ebe62bd556a500585680e1afa5e073eaf1756`.
3. Use bounded `curl.exe` downloads in all four Windows build/test workflows
   for Resource Hacker, UPX, and legacy Go where applicable. Require:
   `--fail`, `--location`, `--silent`, `--show-error`, `--retry 3`,
   `--retry-all-errors`, `--retry-delay 2`, `--connect-timeout 30`,
   `--max-time 300`, `--retry-max-time 600`, `--remove-on-error`, explicit
   `$LASTEXITCODE` failure, and the existing SHA-256 verification.

The affected workflows are:

```text
.github/workflows/build-windows.yml
.github/workflows/pr-test-build-windows.yml
.github/workflows/build-windows-legacy.yml
.github/workflows/pr-test-build-windows-legacy.yml
```

Resource Hacker 5.2.8 is not Authenticode-signed and the vendor does not
publish a checksum. Its pinned digest is therefore a documented trust-on-first-
use value captured from the current official HTTPS installer. Any silent
vendor-side replacement fails the build and requires deliberate re-verification.
Downloading directly from the vendor also avoids redistributing the binary
under ambiguous web licensing terms.

The retry change addresses the observed PR #229 UPX transport reset. Retries
are bounded and remain protected by checksums; a persistent network or integrity
failure stays loud.

## Release preparation

The implementation is prepared as a fresh `prepare-2.19` branch based on
current `main`. It does not reuse the old release PR #229 commits blindly and
does not absorb unrelated local release-WIP changes.

After functional work passes its gates, update release-facing sources of truth
together:

- `VERSION` and every lockstep runtime/package version location required by
  [AGENTS.md](../../../AGENTS.md);
- `Changelog.md` with the actual five new Android locales, the mobile status
  localization boundary, and the two release-tool fixes;
- Android/Fastlane changelog copy without claims stronger than the verified
  implementation;
- `android/README.md`, `ARCHITECTURE.md`, and `API.md` for the structured mobile
  progress contract and generated locale configuration;
- localization/Weblate documentation to remove Italian drift and list
  `zh-Hans` and `hi` correctly.

The old draft PR #229 remains untouched until the new branch passes local and
GitHub checks and a replacement draft PR exists. It can then be closed as
superseded with a direct link to the new PR.

Production Windows signing is an external release blocker. The live SignPath
production certificate “Release certificate 2026” is still `CSR PENDING`, has
no validity dates, and leaves the release signing policy invalid. The branch
may be prepared and reviewed, but v2.19 must not be described as production-
signing-ready until the certificate is issued/imported and a real signed
artifact verifies successfully.

## Version-control workflow

GitButler is the primary write interface for branch, selective commit, push,
and PR operations. Changes are committed by GitButler file or hunk IDs so the
pre-existing release-WIP files remain uncommitted and unassigned to
`prepare-2.19` unless explicitly reconciled during the release-metadata step.

The separate clean linked worktree is a validation sandbox because the current
GitButler CLI does not register it as a project without switching it to
`gitbutler/workspace`. Direct Git is permitted only for a documented operation
that GitButler cannot safely perform, such as lifecycle management of that
linked worktree. It is not used as a routine substitute for GitButler commits,
pushes, rebases, or PR creation.

Planned atomic commits are:

1. this design specification;
2. Android localization contract and five catalogs;
3. typed mobile status/error boundary and documentation;
4. release-tool policy tests and workflow updates;
5. reconciled v2.19 release metadata.

The exact split may combine inseparable test and implementation files, but it
must not mix unrelated changes or the user's pre-existing WIP.

## Testing and verification

### Localization tests

- Locale-matrix key, plural, duplicate, and placeholder parity.
- Language-specific plural category contracts.
- Security-wording gates for every locale's P0/P1 strings.
- Technical extension and invariant-token guards.
- Generated `LocaleConfig` contains exactly `en`, `ru`, `de`, `fr`, `es`,
  `zh-Hans`, and `hi`.
- Debug pseudolocale compilation and screenshot/render review.
- Human review evidence for all five new catalogs.

### Go mobile tests

- Table tests for every static, terminal, rate, malformed, and unknown status.
- Typed speed/ETA and item-count argument parsing.
- A source/AST contract test that enumerates production reporter templates in
  `volume` and `fileops` and fails when one lacks a mobile classification.
- Terminal start/success/cancel/error code tests.
- Atomic update tests proving status updates do not overwrite progress and
  progress updates do not overwrite status.
- `go test -race` for the mobile package and the full race-sensitive suite.

### Kotlin tests

- `GoBridgeTest` for every structured JNI field and separate error transport.
- `OperationStatusTest` for static/rate rendering, locale formatting, and
  unknown fallback.
- `OperationManagerTest` proving terminal and recovery behavior uses stable
  codes, not raw English.
- `OperationUiStateTest` for semantic state projection.
- Foreground-service guard proving it uses the shared renderer.
- `AppError` tests for error-code security behavior, localized generic/header
  fallback, localized reason placeholders, and diagnostic-only raw text.
- Resource tests proving every renderer/error key exists in every locale with
  matching placeholders.

### Workflow policy tests

Write failing policy tests before editing workflows. They require:

- exact Cosign v3.1.2 plus the existing installer SHA;
- the official Resource Hacker URL, exact 5.2.8 checksum, direct installer
  path, and absence of GitHub user-attachment URLs;
- bounded curl flags, explicit exit-code handling, and subsequent checksum
  verification in all four Windows workflows;
- existing Resource Hacker process-exit and non-empty-output checks.

### Full release gates

Run and report at minimum:

```text
go mod tidy -diff
go test -tags migrated_fynedo ./...
go test -run 'TestGoldenDecryption|TestGoldenCompressedDecryption|TestGoldenWrongPassword|TestGoldenV1WrongPassword' ./internal/volume
go test -tags migrated_fynedo -race ./...
golangci-lint run --output.text.path /dev/null --output.json.path stdout
govulncheck -test -tags=migrated_fynedo ./...
desktop GUI build
CLI-only build
WASM build
mise run android:test
Android lint and release assembly with the rebuilt AAR
actionlint
gitleaks
opengrep
trivy
```

The opt-in CLI integration suite is run with
`PICOCRYPT_RUN_CLI_INTEGRATION=1`. Android instrumentation and visual checks
run on an emulator/device matrix rather than being silently counted as part of
JVM tests. GitHub Windows jobs must exercise Resource Hacker and UPX on hosted
Windows because local policy tests cannot prove those executables work.

No gate is reported as passing if it was skipped. Any environment-limited gate
is named explicitly with its blocker.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Android translation sounds fluent but changes a security promise | P0/P1 glossary checks plus independent native/near-native review |
| A new backend reporter string appears | source-contract test fails; runtime falls back to localized “Working…” |
| Regex accepts unexpected status prose | anchored exact patterns and typed argument validation |
| Compose and notification diverge | one renderer with a test forbidding raw notification status |
| Concurrent reporter calls lose fields | field-specific updates under one lock plus race tests |
| A stale AAR hides bridge changes | gomobile rebuild is part of Android test/build entry points and release gates |
| Android locale list advertises unfinished translations | complete-catalog tests, generated-config inspection, and human review gate |
| Indirect dependency churn creates untested runtime combinations | no main-module override without reachable defect evidence |
| Vendor installer changes silently | pinned SHA-256, bounded download, loud mismatch, documented TOFU origin |
| Release is claimed ready while SignPath is pending | live certificate state and signed-artifact verification remain release blockers |

## Documentation updates

Implementation must synchronize:

- `android/README.md` with status codes, diagnostic raw fields, AAR rebuild,
  locale directories, and generated locale configuration;
- `ARCHITECTURE.md` with the mobile-boundary classifier and single renderer;
- `API.md` with exported `ProgressResult` fields and compatibility behavior;
- `docs/localization/TRANSLATION_GUIDE.md` and `WEBLATE_SETUP.md` with the
  actual shipped Android and desktop locale sets;
- release notes and Fastlane metadata with literal verified claims.

## Release gates and deferred work

The branch can reach implementation-complete state while two release gates
remain external or human:

1. native/near-native review and visual evidence for all five Android
   catalogs;
2. production SignPath certificate issuance/import and real artifact signing
   verification.

Those gates keep the PR draft or the release blocked; they do not justify
weakening tests, dropping locales silently, exposing raw English, or bypassing
signing policy.

A future design may replace English reporter templates at the source with a
typed cross-platform event API. That is intentionally deferred because it
touches audit-critical volume/file-operation callers and requires independent
desktop/CLI compatibility design.

## Acceptance criteria

The `prepare-2.19` work is ready for final merge review when:

- all five Android catalogs are structurally complete and human-reviewed;
- Android system language settings list the intended seven total locales;
- neither Compose nor notifications display raw backend status/info/errors;
- error recovery actions satisfy the authentication/corruption matrix;
- no audit-critical production package or encrypted format changed;
- the approved Cosign, Resource Hacker, and download-retry changes are covered
  by policy tests;
- `go.mod` and `go.sum` remain unchanged unless new evidence reopens the audit;
- all local and GitHub gates pass with skips and limitations explicitly listed;
- release metadata matches the implementation exactly;
- SignPath is either verified ready or is still stated plainly as the release
  blocker;
- the old PR #229 is closed only after the replacement draft PR exists and is
  linked.
