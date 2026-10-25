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

2. **Embedded GPG signature.** The AppImage embeds a detached signature (ELF section
   `.sha256_sig`) produced by the key above, together with its public key (`.sig_key`).
   AppImage-aware tooling (e.g. AppImageUpdate / `appimaged`) uses these to confirm the
   release was signed by the key whose fingerprint is shown above.

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

A check that accepts any main-branch workflow in this repository replaces
`--certificate-identity` with
`--certificate-identity-regexp '^https://github.com/Picocrypt-NG/Picocrypt-NG/\.github/workflows/.+@refs/heads/main$'`.

The `.sigstore.json` bundle embeds the Rekor inclusion proof, so `cosign verify-blob`
can run fully offline given a `--trusted-root`.
