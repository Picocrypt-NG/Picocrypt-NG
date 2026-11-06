# Verifying Picocrypt-NG releases

## Linux AppImage

The Linux AppImage is GPG-signed in CI and carries AppImageUpdate delta-update
information, so an installed build can update itself in place (downloading only the
changed blocks via a `.zsync` published alongside each release).

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
The archive is safely extracted before the release GPG key is imported.
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

The `release-coordinator` workflow (`.github/workflows/release.yml`) uses the
dispatch event's `github.sha` for every checkout and reusable owner call. It binds
root `VERSION` and the full canonical manifest to that commit. Its `mode` input
has three choices:

- `validation` (default) builds and verifies all 19 canonical primary assets
  without production signing, staging or publication.
- `stage` runs full validation, then the seven owners sign and stage their
  complete sets, or reuse already verified complete remote sets. Success requires
  every owner to report `staged=true`; `published` remains `false`.
- `publish` additionally runs strict finalization after all seven owners succeed
  with `staged=true`. It requires the complete 19 primary assets and their 19
  Sigstore bundles, verifies their source and trust bindings, and confirms actual
  publication with `published=true`.

`stage` and `publish` require a manual dispatch from `main` in this repository,
with matching workflow, source and checkout SHAs. Both require separate explicit
authorization, including a signed staging rehearsal. Check the live `release`
environment protections before execution: `environment: release` in YAML alone
does not establish a required human approval. macOS retains its existing ad-hoc
bundle seal; these modes do not add Developer ID signing or notarization.

Retain the source SHA, run ID, immutable raw/signing-input/signed-generation
artifact IDs, official ZIP SHA-256 digests and each artifact's producing attempt.
For recovery, rerun only failed jobs in the same run. Successful signing jobs'
retained full-owner generations let staging retry restore and verify the original
bytes without signing or attesting again. The producing attempt can precede the
retry attempt. A partial staged set must retain its original artifact/bundle
pairs. If a required retained artifact expired, or a partial set cannot be
completed with its original bytes, stop for an explicit recovery decision.
Rebuilding or generating replacement signatures is not a recovery fallback;
existing release assets must not be overwritten.

The new coordinator graph has not yet executed end to end in hosted GitHub
Actions. Local policy/runtime fixtures and lint do not establish hosted signing,
failed-job retry or retention recovery acceptance.
