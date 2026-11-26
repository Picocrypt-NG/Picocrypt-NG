# Verifying Picocrypt-NG releases

## Build inputs checked before signing

The direct and coordinated Linux, macOS and Snap release workflows verify the raw
artifact ID, archive digest, producing attempt, source SHA, version and payload
hashes before signing. Their payload manifests also carry the build-material
digests, which the verifier compares against its own checkout of the release
source. The Android verifier checks the unsigned APK carrier's build materials
before loading signing credentials.

- Linux AMD64 and ARM64 use architecture-specific Ubuntu 24.04 image digests
  and package locks in `.github/toolchains/linux-release/`. The package
  records come from Ubuntu's signed `noble`, `noble-updates` and
  `noble-security` snapshot at `20261105T000000Z`. Preparation verifies each
  downloaded package's hash, name, architecture and version. Installation
  resolves against a generated local index with networking disabled. The
  native test, GUI and CLI build, UPX compression and DEB steps then use the
  resulting local image with networking disabled.
- The Linux, macOS, Android and Snap preparation steps verify the matching Go
  archive against `.github/toolchains/release-go.json`, download modules into
  a fresh cache and run `go mod verify`. The build uses the local toolchain,
  disables the module proxy and sets `-mod=readonly`. The producer checks
  `go.mod` and `go.sum` against the release checkout.
- The macOS lane selects the Xcode and SDK versions in
  `.github/toolchains/macos-release.json`, records the hosted OS and image
  builds, and checks that the GUI and CLI are ARM64, target macOS 15.0 or
  earlier, and link only Apple system libraries. The PR lane uses the same
  pinned SDK and binary checks without a Homebrew install step. The official
  release lane still provisions Homebrew dependencies pending native validation.
- Android prepares a fresh SDK and NDK from the hashes in
  `.github/toolchains/android-release.json` and uses the same checked Temurin
  archive as the offline signer. Gomobile seeds its generated module from the
  application's pinned Go requirements and checksums. The Gradle wrapper
  verifies its distribution in a fresh Gradle home. The release build checks
  dependency artifacts and metadata in strict mode against the committed
  verification file. The payload
  records digests for the SDK, JDK, Go, Gradle wrapper and verification file.
- The Snap producer provisions its QEMU host tools and Jammy build guest
  from the locks in `.github/toolchains/snap-host/` and
  `.github/toolchains/snap-release/`. It builds the strict AMD64 Snap and
  checks the installed command inside the guest with egress disabled. The
  locks cover the cloud image, build and stage packages, Snapcraft and the
  base and GNOME snaps. The raw artifact records the host and guest locks,
  host container recipe, Go archive and Go module digests.

The macOS hosted image and Homebrew dependencies remain outside the verified
material set. The public signatures and source attestations retain their
existing format.

## Linux AppImage

The Linux AppImage is GPG-signed in CI and carries AppImageUpdate delta-update
information, so an installed build can update itself in place (downloading only the
changed blocks via a `.zsync` published alongside each release).

### AppImage build inputs

The unsigned producer builds and packages AppImage inside the locked Ubuntu
22.04 environment. The lock covers the base image, Debian packages, Go and
the packaging tools. The signer checks the material record expected for the
reviewed source and its binding to the exact AppDir archive before importing
the signing key.

The AppImage dependency review checks current signed Jammy indexes weekly and
reports the same comparison in validation and staging summaries. Review any
updates and refresh the lock in a dedicated pull request with an unsigned
AppImage build. The review job reads package metadata and leaves the release
build inputs pinned. See the [lock refresh procedure](.github/toolchains/appimage-release/README.md).

### Release signing key

```
Picocrypt-NG Release Signing
ed25519 fingerprint: 40D5 5274 9B0E B548 C79D  79F2 2DD9 3FE7 5B45 D97F
```

To import it, save the block below to a file and run `gpg --import <file>`:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEai6HJBYJKwYBBAHaRw8BAQdA7A56uqCha9ICfgYAlPw49V/Vr/S6CEUnyUZM
lFDFKnW0S1BpY29jcnlwdC1ORyBSZWxlYXNlIFNpZ25pbmcgPDExOTA4MjIwOStS
ZXRlbmdhcnRAdXNlcnMubm9yZXBseS5naXRodWIuY29tPoiQBBMWCgA4FiEEQNVS
dJsOtUjHnXnyLdk/51tF2X8FAmouhyQCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgEC
F4AACgkQLdk/51tF2X+PIgEA1sMIfiJRqIlTYbxtPaXIPTJyGpoz6PUKxJpc7sDQ
vpQBAN2uP29K6q9toerA6Oh2i0TOmDRZWJB1VONAbdKfiWUA
=2583
-----END PGP PUBLIC KEY BLOCK-----
```

### How to verify a download

1. **SHA-256.** GitHub displays a `sha256:` digest next to each release asset.
   Compare it against your download:

   ```
   sha256sum Picocrypt-NG-<version>-x86_64.AppImage
   ```

2. **Embedded GPG signature and trusted signer.** From a trusted checkout of this
   repository, run:

   ```bash
   bash .github/scripts/verify-appimage.sh ./Picocrypt-NG-<version>-x86_64.AppImage
   ```

   This requires Linux x86_64, Docker and the host commands checked by the script.
   It checks the source, package and patch hashes recorded under
   `.github/toolchains/appimage-verifier/`, then builds upstream AppImageUpdate
   `validate` with one NUL-termination fix. Compilation runs without networking
   from the pinned Ubuntu 22.04 image and package closure. The resulting scratch
   runtime contains the verifier, GPG tools and their runtime libraries, with no
   shell, compiler or package manager. Docker and its build cache are trusted.

   The AppImage is copied into a private directory and mounted read-only into a
   non-root container with no network, a read-only root filesystem, dropped
   capabilities and resource limits. Its payload is never executed. Success
   requires a valid signature and the exact full fingerprint above. Cached source
   and package bytes are rehashed; an arbitrary cached executable or image tag is
   not accepted. These controls do not establish bit-for-bit reproducibility or
   an independent audit of the verifier and its dependencies.
   The key embedded in `.sig_key` alone does not establish trust, and a nonempty
   `.sha256_sig` section alone does not prove the signature is valid. The AppImage
   digest excludes format-defined sections; verifying a detached signature over
   the entire file with `gpg --verify` is not equivalent.

   Exit `1` means an ordinary signature, format or signer-policy refusal. Exit `2`
   means setup, Docker, timeout, OOM, abnormal termination or another tool fault.
   Both block release. Public negative controls require the expected refusal and
   a working unchanged positive fixture; infrastructure failures do not count as
   cryptographic rejections. A crash on a malformed ELF is reported as a tool
   fault, not as a normal cryptographic result.

### CI validation and production signing

The default `build-appimage` dispatch (`publish_release=false`) builds and smoke
tests unsigned packaging, then uploads a `validate-appimage-amd64` workflow
artifact. This path has no release environment, production GPG key, keyless
signing, or release publication. Public, independently signed fixtures exercise
the verifier without private signing keys.

With `publish_release=true` on `main`, the build hands its AppDir to a separate
job through an immutable same-run artifact ID and checked archive SHA-256.
The archive is safely extracted before the release GPG key is imported. A
separate job prepares the signing dependencies without credentials. The
signing job checks their repository-pinned hashes and imports the key only
inside a network-disabled container with a temporary in-memory GPG home.
Production signing selects the full expected fingerprint from the verifier
manifest, rather than the first key in the keyring. The signing key is removed
before signature verification and payload smoke testing. External cryptographic
verification must pass before uploading the signed build artifact and before
the separate Sigstore/provenance and release staging gates run.

The producer versions, source commits, asset IDs and SHA-256 digests are recorded
in `.github/toolchains/appimage-build.json`. `linuxdeploy` creates AppDir;
`appimagetool` receives the pinned runtime explicitly, avoiding implicit producer
or runtime downloads. Updating the signing key requires one reviewed change to
the public fingerprint, verifier manifest and release secret. A failed verifier
blocks release; structural section checks are not a fallback.

### Self-updating

Installed AppImages embed update information pointing at this repository's GitHub
releases. To pull the latest signed build (delta download):

```
appimageupdatetool ./Picocrypt-NG-<version>-x86_64.AppImage
```

## Windows Authenticode

The current release workflows require SignPath signing for the Windows GUI,
current and legacy CLIs, installer and embedded uninstaller. They verify the
SignPath Foundation production certificate against this SHA-256 fingerprint:

```
E4ED1CAE2D8E8F94C13BD7805E2F8BB54D690BEA7133CECC1979CC6A60207D5B
```

This describes the configured production pipeline. The latest published release,
[2.18](https://github.com/Picocrypt-NG/Picocrypt-NG/releases/tag/2.18), predates
this Authenticode requirement. Neither 2.19 nor the current 3.0 development
version has been published.

For an executable produced by this pipeline, verify it in PowerShell:

```powershell
$signature = Get-AuthenticodeSignature .\Picocrypt-NG-portable.exe
$signature.Status
$signature.SignerCertificate.GetCertHashString(
  [System.Security.Cryptography.HashAlgorithmName]::SHA256
)
$signature.TimeStamperCertificate
```

`Status` must be `Valid`, the fingerprint must match the value above, and
`TimeStamperCertificate` must not be empty.

Production release workflows submit three sequential requests from
`.github/workflows/build-windows.yml` and one from
`.github/workflows/build-windows-legacy.yml`. Approve each request only when
SignPath reports this repository, the `main` branch, the expected workflow, and
the expected artifact configuration. Each request may wait up to one hour for
approval and completion. The `signpath_release_dry_run` workflow input exercises
the same production signing and verification path without uploading signed
output or publishing a GitHub release.

## Sigstore verification (keyless)

The production release workflows generate keyless Sigstore signatures using
GitHub Actions OIDC, Fulcio and the Rekor transparency log for the artifacts
listed below. They publish a `<artifact>.sigstore.json` bundle beside each
artifact and a build-provenance attestation to GitHub. The published 2.18 release
also includes these bundles.

GitHub's `sha256:` asset digest checks your download against the bytes stored by
GitHub. Signature verification also checks the producing CI identity against the
workflow you select below.

Install [cosign](https://docs.sigstore.dev/cosign/installation/) **3.1.3 or newer** and the
[GitHub CLI](https://cli.github.com/).

### 1. Authenticity (cosign, pinned producing workflow)

```bash
cosign verify-blob <artifact> \
  --bundle <artifact>.sigstore.json \
  --certificate-identity 'https://github.com/Picocrypt-NG/Picocrypt-NG/.github/workflows/<workflow>.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

### 2. Provenance (GitHub CLI)

```bash
gh attestation verify <artifact> \
  --repo Picocrypt-NG/Picocrypt-NG \
  --signer-workflow Picocrypt-NG/Picocrypt-NG/.github/workflows/<workflow>.yml
```

### `<workflow>` per artifact

| Artifact(s) | `<workflow>` |
|---|---|
| `*.AppImage`, `*.AppImage.zsync` | `build-appimage` |
| `Picocrypt-NG`, `Picocrypt-NG-cli`, `Picocrypt-NG.deb`, `Picocrypt-NG-arm64`, `Picocrypt-NG-cli-arm64` | `build-linux` |
| `Picocrypt-NG-portable.exe`, `Picocrypt-NG-cli.exe`, `Picocrypt-NG-Setup.exe` | `build-windows` |
| `Picocrypt-NG-cli-Legacy.exe` | `build-windows-legacy` |
| `Picocrypt-NG.dmg`, `Picocrypt-NG-cli-macos` | `build-macos` |
| `*.snap` | `build-snapcraft` |
| `*.apk` | `build-android` |

Use the exact producing workflow from the table, including `@refs/heads/main`.
The release gate also binds the source commit and repository.

The `.sigstore.json` bundle embeds the Rekor inclusion proof, so `cosign verify-blob`
can run fully offline given a `--trusted-root`.

## Release coordinator for operators

Assign a named maintainer to each responsibility in the release record:

| Stage | Responsible role | Trust anchor |
|---|---|---|
| AppImage GPG signing | GPG key custodian and release operator | Fingerprint above and `.github/toolchains/appimage-verifier/manifest.json` |
| Android APK signing | Android keystore custodian and release operator | `android/release-signing-cert-sha256.txt` |
| Windows Authenticode | SignPath approver | Production certificate fingerprint above and reviewed artifact configurations |
| macOS bundle sealing | macOS packager | Current ad-hoc seal; Developer ID/notarization is a separate decision |
| Sigstore, provenance and publication | Release operator | Exact workflow owner, repository, ref and source SHA |

Record the reviewed `main` commit, root `VERSION` and required-check results.
The `release-coordinator` workflow (`.github/workflows/release.yml`) checks out the
dispatch commit. In validation and staging it builds that commit and binds root
`VERSION` and the canonical ownership manifest to every owner call.

- `validation` (default) builds and verifies all 19 canonical primary assets
  without production signing, staging or publication.
- `stage` runs full validation, then the seven owners sign and stage their
  complete sets. Existing verified draft pairs are preserved. After all seven
  owners report `staged=true`, the coordinator reads back the 19 primary assets and
  19 Sigstore bundles and verifies their digests, signatures, provenance and
  source-bound release notes. The successful stage run uploads an immutable
  receipt with the verified draft ID, source commit and candidate digest. The
  summary displays all three values and the receipt artifact ID.
- `publish` requires only the `stage_receipt_id` from the approved stage
  summary. Before protected publication, the coordinator authenticates the
  artifact and its successful stage run and attempt on `main`. The resolver
  summary shows the authenticated values for the approver to check. On Ubuntu,
  the publisher verifies the receipt's full draft again and publishes those
  same assets with `published=true`. This mode skips all native builds and
  signing jobs. A failed publication can be retried with the same receipt ID.

The seven direct build workflows remain a fallback for platform validation and
staging. Their existing `publish_release=true` input signs and stages only.
Use `publish_release=false` for unsigned validation. On Windows also set
`signpath_test=false` and `signpath_release_dry_run=false`. Check the actual source
SHA and version of each direct run against the reviewed commit. A single
coordinator stage run reports when the entire candidate is ready for approval.

`stage` and `publish` require a manual dispatch from `main` in this repository,
with matching workflow and checkout SHAs. The publish workflow can promote an
earlier approved source commit that is still on `main` and matches the current
release version and policy. Keep workflow-file changes out of `main` between staging and
publication when possible. GitHub can deny tag creation or release publication
if the target commit differs from the default branch in workflow files. A changed
draft or different source requires a new verified receipt and approval before
publication.

Both modes require separate explicit authorization, including a signed staging
rehearsal. Inspect the actual `release` environment branch policy, required
reviewers and self-review settings before execution. Record the named approver
and decision. The final stage verification uses the protected environment's
`contents: write` token permission for draft visibility in the GitHub Releases
API. The verification script only reads the draft. Review SignPath requests as
described above. `signpath_release_dry_run` still performs production signing.
macOS retains its existing ad-hoc bundle seal; these modes do not add Developer ID
signing or notarization.

Retain the source SHA, stage run ID and attempt, receipt artifact ID, draft
release ID, candidate digest, immutable raw/signing-input/signed-generation
artifact IDs, official ZIP SHA-256 digests and each artifact's producing attempt.
Keep the receipt available through the publication and retry window.
Keep tool versions, verification reports and approval records through the
signing/retry window. Keep credentials, private keys, memory dumps and personal
filesystem paths out of this evidence. The release gate verifies remote bytes,
provenance, exact asset ownership and the source-bound tag before publication.

Read back the final release ID, tag, target SHA, `draft=false`, `prerelease=false`
and complete 38-asset set. A successful leaf job can leave an incomplete draft;
it does not establish that publication occurred.
Keep the approved draft untouched during publication. The shared queue serializes
workflow writes, and the finalizer checks the approved inventory before and after
publication. GitHub's editor is outside that queue. If publication fails after
updating the release, inspect its actual state before taking any recovery action.

For staging recovery, first verify the original staged artifact/bundle pairs by
ID, digest, source and provenance, then rerun only failed jobs in the same run.
Successful signing jobs' retained full-owner generations let staging retry
restore and verify the original bytes without signing or attesting again.
The producing attempt can precede the
retry attempt. A partial staged set must retain its original artifact/bundle
pairs. If a required retained artifact expired, or a partial set cannot be
completed with its original bytes, stop for an explicit recovery decision.
Rebuilding or generating replacement signatures is not a recovery fallback;
the same source SHA can produce different bytes, timestamps or signatures.
Existing release assets must not be overwritten.

For a publication retry, use the original approved stage receipt ID. A later
workflow attempt cannot replace that artifact ID. If the receipt expires or is
deleted, stop for a separately approved recovery of the same verified
candidate.
If GitHub rejects creation of the release tag after `main` advances, verify the
candidate and obtain operator approval to create the exact tag at that candidate
SHA before retrying. Do not point the tag at the newer head.
If GitHub still denies publication, leave the draft intact and review the
permission failure with the release operator.

Rotate a signing identity through one reviewed change to its public trust
anchors, verification fixtures and service policy before using replacement
credentials. Retain historical public verification material. AppImage rotation
must keep this file and its verifier manifest consistent; Android rotation must
update the pinned certificate digest; SignPath rotation must update every
production certificate check.

For each legacy Go update, review the source/bootstrap hashes, immutable vendor
commit and local patches together with `build-legacy-go.ps1` and its manifest.
Retain filesystem, randomness, PE and import regressions. A legacy release
candidate also needs execution in isolated Windows 7 and Windows 8 VMs;
`windows-2022` checks alone do not establish that compatibility.

Review CodeQL languages and extraction diagnostics for the selected SHA,
including excluded platform/build-tag files and native dependency failures.
Keep this evidence separate from the bounded models and source contracts in
[`verification/README.md`](verification/README.md); stable PCV3 releases require
human review of audit-critical product changes. Paid Apple Developer ID and
notarization require a separate budget/credential decision and a
quarantined-download smoke test on a clean supported macOS system.

Hosted validation of the promotion path requires a separately authorized
rehearsal. Local policy and runtime fixtures cover the routing and verification
logic. Signing, publication, failed-job retry and retention recovery also
require evidence from hosted jobs.
