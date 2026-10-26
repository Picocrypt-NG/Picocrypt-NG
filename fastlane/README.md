# Fastlane metadata (F-Droid / IzzyOnDroid)

Store metadata for the Android app, in the Fastlane/Supply layout that F-Droid and
IzzyOnDroid read. Tracks issue #155.

## Layout

```
fastlane/metadata/android/<locale>/
  title.txt                 # max 30 chars
  short_description.txt      # max 80 chars
  full_description.txt       # max 4000 chars (plain text / Markdown / single-line HTML)
  changelogs/default.txt    # max 500 bytes, plain ASCII, fallback changelog (any versionCode)
  images/
    icon.png                 # 48x48 .. 512x512, PNG/JPG
    featureGraphic.png       # 512x250 or 1024x500 (optional)
    phoneScreenshots/        # 1.png, 2.png, ... ; max 2:1 side ratio, PNG/JPG
```

`en-US` is required as the fallback locale. Only `en-US` is populated so far.

The fastlane tree lives at the repository root. The Android app lives in
`android/` and desktop sources in `src/`.

## versionCode

`versionCode` is derived from the repo-root `VERSION` file by the release workflow:
`major*10000 + minor*100 + patch`. The current development target is `3.0`,
with base versionCode `30000`. This version is not yet released.

Current source builds produce per-ABI APKs for `armeabi-v7a`, `arm64-v8a`,
`x86` and `x86_64`, plus a universal APK. Gradle applies `10*base+offset`
to every release output:

| Output | Offset | 3.0 versionCode |
| --- | --- | --- |
| Universal | 0 | 300000 |
| `armeabi-v7a` | 1 | 300001 |
| `arm64-v8a` | 2 | 300002 |
| `x86` | 3 | 300003 |
| `x86_64` | 4 | 300004 |

An fdroiddata entry for these splits must match with
`VercodeOperation: [10*%c+1, 10*%c+2, 10*%c+3, 10*%c+4]`.
APK support does not guarantee enough available memory for PCV3's fixed
1 GiB KDF, particularly in a fragmented 32-bit address space.

fastlane changelogs are keyed by versionCode, with `changelogs/default.txt` served as the
fallback for any versionCode that has no specific file. This repo ships only
`default.txt`, with at most 500 bytes of ASCII text. There are no per-versionCode
or per-ABI changelog files.

## Status

- [x] `images/icon.png`: 140×140 key logo (within F-Droid's 48 to 512 px range)
- [x] `images/phoneScreenshots/1.png`, `2.png`: encrypt and decrypt screens,
      sized 1220×2420 and 715×1318 (both within the 2:1 side-ratio limit)
- [x] Four per-ABI APK splits and stable versionCodes (`android/app/build.gradle.kts`)
- [x] AI-assistance disclosure in `README.md` and `CONTRIBUTING.md`
- [ ] More locales (only `en-US` is populated)

The metadata and build configuration do not establish store acceptance or
publication. Store review remains separate.
