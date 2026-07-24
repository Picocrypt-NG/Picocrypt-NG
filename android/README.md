# Android App - Picocrypt-NG

This directory contains the Android app that integrates with the Go encryption backend.

## Building

### Prerequisites

1. **Go Mobile**: Use exactly Go 1.26.5 and install Go mobile bindings
   ```bash
   go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20260709172247-6129f5bee9d5
   go install golang.org/x/mobile/cmd/gobind@v0.0.0-20260709172247-6129f5bee9d5
   mkdir -p "$(go env GOPATH | cut -d: -f1)/pkg/gomobile"
   ```

2. **Android SDK**: Ensure Android SDK is installed and `ANDROID_HOME` is set.
   - Requires the stable NDK `29.0.14206865` pin from `ndk-version.txt` (minimum API level 24,
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
   The script requires exactly Go 1.26.5 and the exact NDK revision in `ndk-version.txt`. It verifies
   that `gomobile` and `gobind` match the `golang.org/x/mobile` version in `src/go.mod` and were built
   with Go 1.26.5 before generating `app/libs/picocrypt-mobile.aar`.

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
- `StartEncrypt(requestJSON, password)` - Starts encryption in the background; the request JSON
  carries the staged selection (single file, multiple files, or a folder) so the Go side can
  encrypt a single output or a recursive archive
- `StartDecrypt(requestJSON, password)` - Starts decryption in the background
- `GetProgress(operationID)` - Returns `ProgressResult` with `Status`, `StatusCode`,
  `StatusSpeedMiBPerSecond`, `StatusETA`, `Progress`, `Info`, `InfoCode`, `InfoCurrent`,
  `InfoTotal`, `Done`, `Error`, and `Code`. `Status`, `Info`, and `Error` are retained as
  compatibility/diagnostic fields; Android display logic uses the stable codes and typed values.
- `GetDecryptionInfo(filePath)` - Reads a volume's header to report whether a password/keyfiles are
  required before the user commits to decrypting
- `CancelOperation(operationID)` - Cancels a running operation and returns its canonical terminal
  `ProgressResult`; an already-recorded success or failure wins over a late cancellation request

Passwords cross the bridge as `[]byte` (not `String`) so the Kotlin side can zero its buffer after
use. On the Go side the password becomes a normal `string` for the operation's duration (released
when it ends), so it is not separately wiped.

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

Release builds package exactly seven application locales: base English (`values`), Russian
(`values-ru`), German (`values-de`), French (`values-fr`), Spanish (`values-es`), Simplified Chinese
(`values-b+zh+Hans`), and Hindi (`values-hi`). AGP generates the locale configuration from these
resources with `androidResources.generateLocaleConfig = true` and
`androidResources.localeFilters`; `resources.properties` declares `unqualifiedResLocale=en`.

The generated release list is `en`, `ru`, `de`, `fr`, `es`, `zh-Hans`, and `hi`. Debug-only
`en-XA`/`ar-XB` pseudolocales are excluded. There is no manual `locale_config.xml` and no in-app
locale picker: Android 13 and newer expose the system per-app selector, while older Android versions
follow the system locale. Packaging proves resource completeness, not linguistic or device review;
the five new catalogs still require native or near-native review and real-device rendering checks
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
- Release signing in GitHub Actions expects these repository secrets: `ANDROID_KEYSTORE_BASE64`,
  `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`. The workflow decodes the
  keystore and maps them to the Gradle properties the build reads
  (`ORG_GRADLE_PROJECT_PICOCRYPT_KEYSTORE_PATH`, `…_KEYSTORE_PASSWORD`, `…_KEY_ALIAS`, `…_KEY_PASSWORD`)
- F-Droid builds should run release Gradle tasks without maintainer signing properties; AGP then
  emits unsigned release APKs for F-Droid to sign. GitHub release CI sets
  `PICOCRYPT_REQUIRE_RELEASE_SIGNING=true` so official GitHub release builds still fail if signing
  secrets are missing.
- Release builds produce **64-bit per-ABI APKs** for `arm64-v8a` and `x86_64`
  plus a **64-bit universal** fallback APK. Android 7.0/API 24 remains the OS
  floor, but the device must support one of those 64-bit ABIs. Stable split
  versionCode offsets remain `arm64-v8a=2` and `x86_64=4`; the universal APK
  keeps `base`. The next fdroiddata release must mirror this as
  `VercodeOperation: [10*%c+2, 10*%c+4]`. Published v2.18 metadata remains a
  historical four-ABI release.
- The release workflow publishes three signed release APKs; PR workflow artifacts remain debug/testing-only
