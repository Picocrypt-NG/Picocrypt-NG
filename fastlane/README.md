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

The fastlane tree lives at the repository root, where F-Droid and IzzyOnDroid expect it by
default (this repo is a monorepo — the Android app lives in `android/`, desktop sources in
`src/`).

## versionCode

`versionCode` is derived from the repo-root `VERSION` file by the release workflow:
`major*10000 + minor*100 + patch`. The current release target is **2.19** → base
versionCode `21900` (`VERSION` is `2.19`).

Current source builds ship **64-bit per-ABI APKs** for `arm64-v8a` and `x86_64`
plus a 64-bit universal APK. Their stable versionCode offsets remain
`arm64-v8a=2` and `x86_64=4`; the universal APK keeps `base`. The next fdroiddata
release entry must mirror this with `VercodeOperation: [10*%c+2, 10*%c+4]`.
Published v2.18 metadata remains a historical four-ABI release.

fastlane changelogs are keyed by versionCode, with `changelogs/default.txt` served as the
fallback for any versionCode that has no specific file. This repo ships only `default.txt`
(the current release notes, ≤ 500 bytes, ASCII): the IzzyOnDroid submission was withdrawn, so
the per-versionCode / per-ABI changelog files (one `<versionCode>.txt` per ABI split code) are
no longer maintained. F-Droid-family clients fall back to `default.txt` for every build;
per-code files can be reintroduced later if a store that needs them is targeted again.

## Status

- [x] `images/icon.png` — 140×140 key logo (within F-Droid's 48–512 px range)
- [x] `images/phoneScreenshots/1.png`, `2.png` — main/encrypt screen (showing the Privacy &
      Security screenshot-protection toggle) + decrypt screen (both ≤ 2:1; `1.png` is
      1220×2420 ≈ 1.98:1, `2.png` ≈ 1.84:1)
- [x] 64-bit per-ABI APK splits + stable per-ABI versionCodes (`app/build.gradle.kts`)
- [x] AI-assistance disclosure — addressed upstream on the GitHub/IzzyOnDroid thread
- [ ] Review `title.txt` / `short_description.txt` / `full_description.txt` — drafts, tune
      wording before submitting
- [ ] More locales (only `en-US` is populated)
