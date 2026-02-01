# Android App - Picocrypt-NG

This directory contains the Android app that integrates with the Go encryption backend.

## Building

### Prerequisites

1. **Go Mobile**: Install Go mobile bindings
   ```bash
   go install golang.org/x/mobile/cmd/gomobile@latest
   gomobile init
   go get golang.org/x/mobile/bind
   ```

2. **Android SDK**: Ensure Android SDK is installed and `ANDROID_HOME` is set.
   - Requires NDK 29.0+ (minimum API level 24, matching app's minSdk)

### Build Steps

1. **Build Go Mobile Bindings** (required before building Android app):
   ```bash
   ./build-gomobile.sh
   ```
   This will generate `app/libs/picocrypt-mobile.aar` containing the Go mobile bindings.

2. **Build Android App**:
   ```bash
   ./build-app
   ```
   Or use Android Studio/Gradle directly.

## Architecture

### Go Mobile Package (`src/mobile/`)

The Go mobile package provides:
- `DetectOperation()` - Determines if a file should be encrypted or decrypted
- `StartOperation()` - Creates a new operation and returns its ID
- `StartEncrypt()` - Starts encryption in background
- `StartDecrypt()` - Starts decryption in background
- `GetProgress()` - Retrieves current progress
- `GetError()` - Retrieves error message if operation failed
- `CancelOperation()` - Cancels a running operation

### Android Components

- **FileCopyService**: Copies selected files to internal app storage
- **GoBridge**: Kotlin wrapper for Go mobile bindings
- **OperationManager**: Manages operation lifecycle and progress tracking
- **FileCard**: UI component for file selection
- **WorkButton**: UI component to start encrypt/decrypt operations
- **ProgressCard**: UI component to display operation progress

## Integration Flow

1. User selects file → File is copied to internal storage
2. `DetectOperation()` is called → Determines encrypt/decrypt mode
3. UI updates → Shows appropriate fields based on operation type
4. User fills form and clicks button → Operation starts in background
5. Progress is polled → UI updates with status and progress
6. Operation completes → Success/error message is shown

## Notes

- Files are copied to internal app storage (`/data/data/io.github.picocrypt_ng/files/picocrypt_files/`)
- Progress is polled every 500ms during operations
- Operations run in background threads (Go goroutines + Kotlin coroutines)
- The Go mobile AAR must be rebuilt whenever Go code changes

