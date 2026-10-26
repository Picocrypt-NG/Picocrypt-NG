<a href="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-windows.yml"><img src="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-windows.yml/badge.svg"></a>
<a href="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-windows-legacy.yml"><img src="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-windows-legacy.yml/badge.svg"></a>
<a href="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-macos.yml"><img src="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-macos.yml/badge.svg"></a>
<a href="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-linux.yml"><img src="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-linux.yml/badge.svg"></a>

<p align="center"><img align="center" src="/images/logo.png" width="512" alt="Picocrypt NG"></p> 

Picocrypt NG encrypts files and folders locally using XChaCha20 and Argon2id. It provides desktop, command-line, Android and browser interfaces.

This README describes the **3.0 development source**. The latest published release is [2.18](https://github.com/Picocrypt-NG/Picocrypt-NG/releases/tag/2.18). PCV3 is new in 3.0; released 2.x builds cannot open PCV3 volumes.

<br>
<p align="center"><img align="center" src="/images/screenshot.png" width="318" alt="Picocrypt NG"></p>

<!--  DO NOT REMOVE (but you can add more lines)  -->
# History

Picocrypt NG is a community-developed continuation of the archived [Picocrypt](https://github.com/Picocrypt) project.

*The original Picocrypt author does not endorse, develop, nor support Picocrypt NG.*

When referencing Picocrypt NG, please always include the "NG" suffix to ensure distinction.
<!--/ DO NOT REMOVE  -->

# Downloads

Read the [features and limitations](#features) before using Picocrypt NG.

Download official builds from this repository and follow the [release verification guide](SIGNING.md). When sharing Picocrypt NG, link to this repository.

## Windows
**Windows 10/11:** Download the latest <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG-Setup.exe">installer</a> or <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG-portable.exe">portable executable</a>. A CLI-only Windows build is available <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG-cli.exe">here</a>.

**Windows 7/8 (Legacy Systems):** Download the <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG-cli-Legacy.exe">legacy CLI build</a>. The current build configuration uses official Go source with pinned [go-legacy-win7 compatibility patches](.github/toolchains/legacy-go/manifest.json). The CLI has no GUI or OpenGL dependencies.

The legacy build is for command-line use only. Use the standard installer or portable executable on Windows 10/11.

If your antivirus flags a download, check its origin and signatures using the [verification guide](SIGNING.md).

**Code signing:** The current Windows release workflows require Authenticode signing through the [SignPath Foundation](https://signpath.org/) and verification against the pinned production certificate. This configuration does not apply retroactively to the published 2.18 downloads. See the [verification guide](SIGNING.md#windows-authenticode).

## macOS
Download Picocrypt NG <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG.dmg">here</a>, open the container, and drag Picocrypt NG to your Applications.

Picocrypt NG is also available through the third-party MacPorts port:
```
sudo port install picocrypt-ng
```
This port is maintained outside this repository and is not published by the Picocrypt NG maintainers, so release timing, build flags, and packaging behavior are controlled by MacPorts and its maintainers.

**Apple Silicon vs Intel:** The released macOS app is built for Apple Silicon and targets macOS 15.0+. Intel Mac users and users on older macOS releases need to <a href="src/README.md">build from source</a> or use the CLI-only version where appropriate.

**Gatekeeper Warning:** The release is ad-hoc signed but not notarized (notarization needs a paid Apple Developer ID), so macOS shows a Gatekeeper warning the first time you open it. This is a Gatekeeper prompt, not a Picocrypt NG runtime error.

To open it, use one of these methods:
- **Right-click → Open** (instead of double-clicking), then confirm
- **System Settings → Privacy & Security** → scroll down → "Open Anyway"
- **Terminal:** `xattr -cr /Applications/Picocrypt-NG.app` removes quarantine attributes if macOS reports "app is damaged and can't be opened"

The CLI-only build avoids the `.app` bundle path and is useful for terminal-only use.

## Linux
Download the raw binary for <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG">amd64</a> or <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG-arm64">arm64</a> (you may need the packages below). CLI-only builds are also available for <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG-cli">amd64</a> and <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG-cli-arm64">arm64</a>. Alternatively, try the <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG.deb">.deb</a> or <a href="https://flathub.org/en/apps/io.github.picocrypt_ng.Picocrypt-NG">Flatpak</a>.
```
sudo apt install -y libc6 libgcc-s1 libgl1 libgtk-3-0 libstdc++6 libx11-6
```

## Android
The native Android app requires Android 8.0 or newer and supports <code>armeabi-v7a</code>, <code>arm64-v8a</code>, <code>x86</code>, and <code>x86_64</code>. Download the signed universal APK <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG-android-universal.apk">here</a>, or choose the smaller matching per-ABI APK from the latest GitHub release. PCV3 operations require sufficient available memory for the fixed 1 GiB KDF, including on 32-bit devices. PR artifacts remain debug/testing-only.

**APK verification:**

- Application ID: `io.github.picocrypt_ng.picocrypt_ng`
- SHA-256 signing certificate fingerprint:

```text
E2:F2:A9:71:23:1A:A0:B8:68:82:C6:3B:87:B6:89:C7:16:32:C6:D5:51:68:B1:CE:85:69:52:D0:7F:61:72:B7
```

Verify the APK signature and certificate with `apksigner verify --print-certs Picocrypt-NG-android-universal.apk`.
For the APK file checksum, compare `sha256sum` with the digest next to that release asset on GitHub.

For local Android builds and architecture details, see <a href="android/README.md">android/README.md</a>.

## CLI
Picocrypt NG includes a command-line interface in this repository; see <a href="CLI.md">CLI.md</a> for usage. It encrypts literal file and folder operands; use quoted explicit glob patterns when pattern matching is intended. It also supports paranoid mode and Reed-Solomon encoding. You can use it on systems that don't have a GUI or can't run the GUI app.

## Web
Picocrypt NG provides a browser app <a href="https://picocrypt-ng.github.io/">here</a> for in-memory single-file operations. This repository's WASM bridge creates PCV3 with a password, keyfiles, or both, and reads supported PCV1/PCV2/PCV3 volumes. It supports Paranoid mode, Reed-Solomon payload protection, comments and explicit D1 selection. Force output is marked unverified. Browser size limits are exposed by `picocryptCapabilities()`; sufficient browser memory is also required. Folder workflows, split volumes and large streaming jobs remain desktop/CLI/native-app features. Owned buffers are wiped best-effort; JavaScript and runtime copies cannot be guaranteed wiped. The hosted page is deployed separately and may use an older core.

## Translations
Community translations for Picocrypt NG are hosted in the
[Picocrypt-NG Weblate project](https://hosted.weblate.org/projects/picocrypt-ng/).
When the project is operationally unlocked, the desktop and native Android
components accept target-language corrections and proposals for new languages.
Component configuration disables editing the base English catalogs and
managing source string IDs. Every Weblate repository change is proposed from a
fork through a GitHub pull request; human approval and the required CI checks
remain mandatory before merge. The complete operational contract is recorded in
[WEBLATE_SETUP.md](docs/localization/WEBLATE_SETUP.md).

Security-sensitive wording must preserve the meaning documented in the
[translation guide](docs/localization/TRANSLATION_GUIDE.md). Community
linguistic review is continuous, so the bundled catalogs are not presented as
certified native-language reviews.

Current desktop and native Android builds bundle application UI catalogs for
English, Russian, German, French, Spanish, Simplified Chinese, Hindi, and Korean
(`ko`, with contemporary neutral South Korean wording). The desktop app has an
in-app language selector for Picocrypt-NG-owned UI; Fyne-owned dialogs and raw
backend status text may remain English. Android 13 and newer expose the system
per-app language selector; older Android versions follow the system locale. The
CLI remains English-only. Catalog structure, placeholders, plurals, and locale
registration are enforced in repository tests; translation and rendering
corrections continue through the same reviewed pull-request workflow.

## File Associations
Double-click `.pcv` files to open Picocrypt NG in decrypt mode on Windows, macOS, and Linux. Installer/`.deb`/`.app` packages register the association automatically.

# Scope

Picocrypt NG encrypts selected files and folders. It does not provide full-disk encryption. New encryption uses PCV3; supported legacy v1/v2 volumes remain readable.

# Features

To encrypt on desktop, select or drop your files, provide a password, keyfiles, or both, and choose Encrypt. To decrypt, select the encrypted volume and provide the same factors. Select D1 explicitly when opening a D1 volume.

Available options depend on the interface:
<ul>
	<li><strong>Password generator</strong>: Generate passwords with a chosen length and character set using cryptographically secure randomness.</li>
	<li><strong>Comments</strong>: Normal PCV3 and legacy comments are plaintext metadata; never put secrets in them. The desktop can preview a Normal PCV3 comment before decryption, but marks it unverified. A confirmed comment comes from the authenticated reader result. D1 encrypts its metadata, including comments, and has no pre-decryption comment preview. The desktop and native Android apps disable comment entry for D1.</li>
	<li><strong>Keyfiles</strong>: Native desktop, CLI and Android encryption uses PCV3 by default, with a password, keyfiles, or both. Normal PCV3 and D1 apply the selected factors together. Use non-empty, secret, unpredictable keyfiles and keep them available for decryption. Supported legacy v1/v2 volumes remain readable; see <a href="Internals.md#keyfile-design">format-specific keyfile details</a>.</li>
	<li><strong>Paranoid mode</strong>: Add a Serpent-CTR layer plus HMAC-SHA3 authentication. This also increases the Argon2id work factor for Normal PCV3 and legacy volumes. D1 uses its fixed 1 GiB, eight-pass, eight-lane profile with either cipher suite. Paranoid mode adds processing cost and still requires strong credentials and a trusted endpoint.</li>
	<li><strong>Reed-Solomon</strong>: Reed-Solomon adds error-correction redundancy so Picocrypt NG can detect and repair limited corruption. It cannot prevent corruption and cannot recover data after corruption exceeds the redundancy budget.</li>
	<li><strong>Recovery and Force</strong>: Ordinary PCV3 decryption publishes plaintext only after authentication. Native PCV3 recovery stores partial or unverified results as separate forensic artifacts with range and final-record verification details. It keeps the source and does not automatically extract these artifacts. Unverified recovery requires separate consent. Legacy Force decrypt and browser Force can retain unverified bytes; do not treat them as authentic. Reed-Solomon can help recover limited corruption when present.</li>
	<li><strong>Split into chunks</strong>: Large legacy and PCV3 outputs can be split into custom-sized chunks and recombined during decryption. PCV3 removes the complete container only after every chunk is durably published.</li>
	<li><strong>Compress files</strong>: Picocrypt NG combines multiple files in a ZIP archive without compression by default. Select compression to use Deflate.</li>
	<li><strong>Deniability</strong>: PCV3 D1 creates a random-looking container with optional Paranoid mode. Its Argon2id profile always uses 1 GiB, eight passes and eight lanes. It supports files, folders, multiple inputs, compression, and raw CLI stdin/stdout. D1 archive payloads can be saved as ZIP files or extracted with the desktop Auto unzip option. Deniability concerns the container's appearance; filenames, file sizes and other storage metadata remain visible.</li>
	<li><strong>Recursively</strong>: Picocrypt NG processes files in the selected folders and subfolders individually. A batch can decrypt standalone Normal PCV3 files alongside supported legacy volumes using the selected password and keyfiles. For a batch of D1 volumes, enable <strong>All selected files are PCV3 D1</strong>: every file is then opened as D1, without trying other formats. A failed file is kept and the batch continues; cancellation stops processing further files. PCV3 outputs never replace existing files, and PCV3 encrypted originals are retained. Recovery and PCV3 split volumes remain single-file operations.</li>
	<li><strong>File associations</strong>: Double-click <code>.pcv</code> files to open Picocrypt NG in decrypt mode. Setup.exe (Windows), <code>.deb</code> (Linux), and <code>.app</code> (macOS) register the association automatically.</li>
</ul>

# Security

For more information on how Picocrypt NG handles cryptography, see <a href="Internals.md">Internals</a> for the technical details.

Picocrypt NG protects stored volumes and assumes a trusted host while credentials and plaintext are in use. It does not protect against a compromised endpoint or attempt to prevent side-channel analysis.

PCV3 authenticates its header, records and final record before publishing ordinary plaintext. Legacy v1 lacks the v2 full-header HMAC. In legacy v2 keyfile volumes, the authentication, Serpent and rekey subkeys are password-derived without the keyfile; recover these volumes and re-encrypt them as PCV3. Force recovery has the separate trust limits described above.

PCV3 passwords use a fixed, bounded Unicode 18.0.0 NFC profile that preserves case and spaces. Input outside that profile is rejected before key derivation. Legacy readers retain their separate normalization and retry behavior. See the [password profile](Internals.md#pcv3-password-profile) for the exact bounds.

# AI Usage

AI tools (LLMs) assist development in this project. Picocrypt NG builds on upstream Picocrypt commit `7e403a2`, [audited by Radically Open Security in 2024](https://github.com/Picocrypt/storage/blob/main/Picocrypt.Audit.Report.pdf), with subsequent v2 changes and the new PCV3 format. The historical audit applies to that upstream revision, not to later changes or PCV3. Development practices and format-specific verification are described in [CONTRIBUTING.md](CONTRIBUTING.md#ai-assistance) and the [PCV3 security contract](docs/SECURITY_CONTRACT.md).

# FAQ

**Does the "Delete files" feature shred files?**

No. Picocrypt NG deletes files without securely erasing their contents. Copies may remain in SSD storage, snapshots and backups. See the [source-deletion limits](docs/SECURITY_CONTRACT.md#publication-and-source-retention).

**Is Picocrypt NG quantum-secure?**

Picocrypt NG uses symmetric cryptography with large security margins, which is generally less affected by known quantum speedups than public-key cryptography. This is not a guarantee against all future cryptanalytic developments; password strength and endpoint security still matter.

# Acknowledgements
Thank you to the significant contributors on [Open Collective](https://opencollective.com/picocrypt) who helped secure the original Picocrypt project's audit:
<ul>
	<li><strong>Mikołaj ($1674)</strong></li>
	<li><strong>Guest ($842)</strong></li>
	<li><strong>YellowNight ($818)</strong></li>
	<li>Incognito ($135)</li>
	<li>akp ($98)</li>
	<li>JC ($90)</li>
	<li>evelian ($50)</li>
	<li>jp26 ($50)</li>
	<li>guest-116103ad ($50)</li>
	<li>Guest ($27)</li>
	<li>Gittan Pade ($25)</li>
	<li>Pokabu ($20)</li>
	<li>oli ($20)</li>
	<li>Bright ($20)</li>
	<li>Incognito ($20)</li>
	<li>Guest ($20)</li>
	<li>JokiBlue ($20)</li>
	<li>Guest ($20)</li>
	<li>Markus ($15)</li>
	<li>EN ($15)</li>
	<li>Guest ($13)</li>
	<li>Tybbs ($10)</li>
	<li>N. Chin ($10)</li>
	<li>Manjot ($10)</li>
	<li>Phil P. ($10)</li>
	<li>Raymond ($10)</li>
	<li>Cohen ($10)</li>
	<li>EuA ($10)</li>
	<li>geevade ($10)</li>
	<li>Guest ($10)</li>
	<li>Hilebrinest ($10)</li>
	<li>gabu.gu ($10)</li>
	<li>Boat ($10)</li>
	<li>Guest ($10)</li>
</ul>
<!-- Last updated July 12, 2024 -->
