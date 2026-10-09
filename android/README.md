# Android App - Picocrypt-NG

This directory contains the Android app that integrates with the Go encryption backend.

## Building

### Prerequisites

1. **Go Mobile**: Use exactly Go 1.27.2 and install Go mobile bindings
   ```bash
   go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20260908204917-8b95e45f8d3e
   go install golang.org/x/mobile/cmd/gobind@v0.0.0-20260908204917-8b95e45f8d3e
   mkdir -p "$(go env GOPATH | cut -d: -f1)/pkg/gomobile"
   ```

2. **Android SDK**: Ensure Android SDK is installed and `ANDROID_HOME` is set.
   - Requires the stable NDK `30.0.16248370` pin from `ndk-version.txt` (minimum API level 26,
     matching app's minSdk)
   - CI and recommended local builds use JDK 21
   - Android app and gomobile outputs are 64-bit only: `arm64-v8a` and `x86_64`

3. **Application ID**: The native Android app uses:
   ```text
   io.github.picocrypt_ng.picocrypt_ng
   ```

### Build Steps

1. **Build Go Mobile Bindings** (required before building Android app). From the repository root,
   the recommended command is:
   ```bash
   mise run android:gomobile
   ```
   To run the script directly instead:
   ```bash
   ./android/build-gomobile.sh
   ```
   The script requires exactly Go 1.27.2 and the exact NDK revision in `ndk-version.txt`. It verifies
   that `gomobile` and `gobind` match the `golang.org/x/mobile` version in `src/go.mod` and were built
   with Go 1.27.2 before generating `app/libs/picocrypt-mobile.aar`.
   The mise task selects these versions independently of the desktop development tools.

2. **Build Android App**:
   ```bash
   ./android/build-app
   ```
   Or use Android Studio/Gradle directly.

## Architecture

### Go Mobile Package (`src/mobile/`)

The Go mobile package exports (see `src/mobile/android.go`):
- `StartOperation()` - Reserves a new operation and returns its ID
- `DetectOperation(filePath)` - Determines whether a file should be encrypted or decrypted
- `StartPCV3(requestJSON, password)` - Starts PCV3 creation or reading in the background;
  creation accepts a single file, multiple files, or a folder, with optional compression
- `StartEncrypt(requestJSON, password)` - Retired compatibility entry point; clears the
  supplied password and returns `PCV3_UNSUPPORTED` without starting encryption
- `StartDecrypt(requestJSON, password)` - Starts decryption in the background
- `GetProgress(operationID)` - Returns `ProgressResult` with `Status`, `StatusCode`,
  `StatusSpeedMiBPerSecond`, `StatusETA`, `Progress`, `Info`, `InfoCode`, `InfoCurrent`,
  `InfoTotal`, `Done`, `Error`, and `Code`. `Status`, `Info`, and `Error` are retained as
  compatibility/diagnostic fields; Android display logic uses the stable codes and typed values.
- `GetDecryptionInfo(filePath)` - Reads a volume's header to report whether a password/keyfiles are
  required before the user commits to decrypting
- `CancelOperation(operationID)` - Cancels a running operation and returns its canonical terminal
  `ProgressResult`; an already-recorded success or failure wins over a late cancellation request

Passwords cross the bridge as `[]byte` so the Kotlin side can zero its transfer buffer after
use. `StartPCV3` clears the caller buffer and transfers an owned copy into the shared
credential lifecycle, which clears its owned byte buffers. Legacy decryption can still
create Go password strings that cannot be explicitly wiped; UI strings and runtime copies
are outside the owned-byte cleanup guarantee.

### Android Components (`app/src/main/.../picocrypt_ng/`)

Staging & bridge:
- **StagingService**: Copies the user's SAF selection (single file, multiple files, or a whole
  folder tree) into app-internal staging and produces a `StagedSelection`
  (`inputFiles`/`onlyFolders`/`onlyFiles`/`suggestedOutputName`) for the Go side
- **FileCopyService**: Legacy single-file copy into internal storage (used for the simple file case)
- **GoBridge**: Kotlin wrapper over the Go mobile bindings; serialises the selection to the request JSON
- **OperationManager**: Owns operation lifecycle, progress polling, and staging cleanup
- **OperationStatus**: Shared resource-backed renderer used by both Compose progress UI and the
  foreground notification; unknown status falls back to localized **Working**, and unknown or
  malformed detail is hidden
- **AppError** / **AppErrorText**: Stable-code error model and configuration-aware localized display
  boundary; raw Go/JVM details remain diagnostic rather than user-facing copy
- **SecureBytes**: Holds the password as a zeroable byte buffer

State & lifecycle:
- **MainViewModel** / **OperationViewModel**: UI state, form data, and progress exposed to Compose
- **FormData**: The selection model (kind + file lists) and form fields
- **OperationForegroundService** (`dataSync`): Hosts a running operation with a progress
  notification so it survives backgrounding; self-stops when the operation finishes
- **SettingsRepository**: SharedPreferences-backed setting holder for screenshot protection
  (`FLAG_SECURE`), exposed as a `StateFlow`

UI (`ui/components/`):
- **FileCard** / **PasswordCard** / **KeyfileCard** / **AdvancedCard** / **CommentsCard**: input cards
- **DecryptOptionsCard** / **DecryptionInfoCard**: decrypt-side options and header info
- **WorkButton**: starts the encrypt/decrypt operation
- **ProgressCard** / **ErrorDialog**: progress and error surfaces
- **PrivacyCard**: always-visible card with the screenshot-protection toggle

## Integration Flow

1. User picks a single file, multiple files, or a folder (SAF) → `StagingService` copies the
   selection into internal staging and builds a `StagedSelection`
2. `DetectOperation()` / `GetDecryptionInfo()` run → Determine encrypt/decrypt mode and whether
   a password/keyfiles are required
3. UI updates → Shows the appropriate fields (encrypt vs. decrypt) for the detected operation
4. User fills the form and taps **WorkButton** → `OperationForegroundService` starts and the
   operation runs in the background (Go goroutine), with the password passed as zeroable `[]byte`
5. Progress is polled → stable status/detail codes and typed arguments pass through `GoBridge` to
   the shared `OperationStatus` renderer, so the UI and foreground notification show the same
   localized status and progress
6. Operation completes → Success/error is shown, staging is wiped, and the service self-stops

## Localization

Release builds package exactly eight application locales: base English (`values`), Russian
(`values-ru`), German (`values-de`), French (`values-fr`), Spanish (`values-es`), Simplified Chinese
(`values-b+zh+Hans`), Hindi (`values-hi`), and Korean (`values-ko`). Korean uses the generic `ko`
language tag with contemporary neutral South Korean wording. AGP generates the locale configuration
from these resources with `androidResources.generateLocaleConfig = true` and
`androidResources.localeFilters`; `resources.properties` declares `unqualifiedResLocale=en`.

The generated release list is `en`, `ru`, `de`, `fr`, `es`, `zh-Hans`, `hi`, and `ko`. Debug-only
`en-XA`/`ar-XB` pseudolocales are excluded. There is no manual `locale_config.xml` and no in-app
locale picker: Android 13 and newer expose the system per-app selector, while older Android versions
follow the system locale. Packaging proves resource completeness, not linguistic or device review;
the six new catalogs still require native or near-native review and real-device rendering checks
before release admission.

## Notes

- Selections are staged under app-internal storage
  (`/data/data/io.github.picocrypt_ng.picocrypt_ng/files/picocrypt_files/`, folder/multi-file under
  `picocrypt_files/staging/`); staging is wiped when the operation clears
- Selection is **single-file XOR multi-file XOR folder**. Android's Storage Access Framework has no
  picker that selects files *and* folders together in one dialog (`OpenMultipleDocuments` = files
  only; `OpenDocumentTree` = exactly one folder), so a mixed "files + folder" selection is not
  offered. Workaround: put the items in one folder and choose **Folder**. The Go core already accepts
  a combined `inputFiles`/`onlyFolders`/`onlyFiles` list, so this is a SAF/UI limitation, not a core
  one — additive mixed selection would be a UI/staging feature, not a core change
- Progress is polled every 500ms by the UI ViewModel while visible, and every 1s by the foreground
  service when the app is backgrounded
- Operations run in background threads (Go goroutines + Kotlin coroutines)
- The Go mobile AAR must be rebuilt whenever Go code changes, especially after an exported
  `src/mobile` method, type, or field changes; stale gomobile bindings will not contain the generated
  getters expected by Kotlin
- `build-gomobile.sh` builds the AAR with `-trimpath` (via `GOFLAGS`) and `-buildid=` (via
  `GOMOBILE_LDFLAGS`) so the native `.so` files don't embed local build paths or unstable Go build
  IDs — needed for reproducible / source-built F-Droid verification
- Permissions requested: `POST_NOTIFICATIONS`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`
  (for the progress notification / long-running operations). No Google Play Services, Firebase, ads,
  or tracking — relevant for F-Droid/IzzyOnDroid inclusion (#155)
- Release artifacts disable Google's dependency-metadata blob via `dependenciesInfo { includeInApk =
  false; includeInBundle = false }` (transparency requirement for F-Droid/IzzyOnDroid)
- GitHub Actions builds and verifies unsigned release APKs without signing credentials.
  A separate job with a read-only GitHub token validates the exact source-bound artifact,
  then signs it offline with Android SDK tools using `ANDROID_KEYSTORE_BASE64`,
  `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS` and `ANDROID_KEY_PASSWORD`.
  Gradle never receives these secrets; signed APKs must match the pinned certificate
  before publication.
- F-Droid builds run release Gradle tasks without maintainer signing properties.
  Reproducible builds must match the official signed APKs after signature copying;
  an F-Droid 3.0 update requires those checks.
- Release builds produce **64-bit per-ABI APKs** for `arm64-v8a` and `x86_64`
  plus a **64-bit universal** fallback APK. Android 8.0/API 26 remains the OS
  floor, but the device must support one of those 64-bit ABIs. Stable split
  versionCode offsets remain `arm64-v8a=2` and `x86_64=4`; the universal APK
  keeps `base`. The next fdroiddata release must mirror this as
  `VercodeOperation: [10*%c+2, 10*%c+4]`. Published v2.18 metadata remains a
  historical four-ABI release.
- The release workflow publishes three signed release APKs; PR workflow artifacts remain debug/testing-only

### PCV3 publication and document providers

Android 8.0/API 26 and a supported 64-bit ABI are the installation minimum.
The OS version does not establish filesystem publication support: creation probes
atomic no-replace behavior in the actual app-private output directory before the
KDF. Unsupported kernels, filesystems, or SELinux policies fail closed; an
ordinary rename after an existence check is never substituted.

Saving retained PCV3 output requires a provider that exposes a seekable regular
file descriptor in `rwt` mode. Pipes and other unsupported descriptors are refused
with `PCV3_OUTPUT_PROVIDER_UNSUPPORTED`; select another destination. A failed
ciphertext save retains the same encrypted result for retry without repeating the
KDF. Decrypted temporary plaintext remains subject to its one-shot cleanup policy.
Successful descriptor transfer confirms only the local transfer; it does not prove
that a remote provider durably stored or synchronized the document. Archive SAF
publication likewise reports durability uncertainty rather than durable storage.

### PCV3 request and retained-output limits

Android uses a bounded 4 MiB UTF-8 JSON request, including JSON escaping and all path
lists. This aggregate transport limit is separate from the 99,999-byte UTF-8 comment,
4,096-byte path, 64-keyfile and 4,096-path-per-selection-list limits. Creation checks
these limits before transferring form ownership; a refusal keeps the selection and
credentials available for correction. JSON size is admitted before aggregate allocation.

An ordinary retained ciphertext or plaintext result offers Save and explicit, confirmed
Discard. A rejected destination keeps the result available and displays the save error.
Native plaintext transfer remains one-shot; only confirmed ciphertext save failure
allows retry. Foreground timeout stops the service promptly while process-owned
cancellation retains native and SAF cleanup custody until settlement.

ZIP preparation and SAF export share a 192 MiB accounting budget across Go and
Kotlin, with a separate check of fresh platform memory observations. The budget
covers retained metadata, paths and provider identities; it is not a process PSS
limit. Archive preparation owns its cancellation context after decryption ends,
and the active export continues supplying fresh memory observations. Resource
refusal preserves cleanup custody and does not offer a password retry.
