#!/usr/bin/env bash
# Generate the GitHub release body for a Picocrypt-NG release.
#
#   gen-release-body.sh <version> [changelog] [output]
#
# The body is fully deterministic from <version> and the changelog, so every
# platform lane supplies identical text to the shared staged-publication gate.
#
#   - Downloads table: a static artifact matrix; only the URL base and the two
#     version-bearing filenames (AppImage, snap) depend on <version>.
#   - "What's new": the "# v<version>" section of the changelog, with its simple
#     HTML (<li>✓ <strong>..</strong>: ..</li>) converted to Markdown bullets.
#   - Verification: how to check the keyless cosign bundle + build provenance
#     that sign-and-attest publishes (this replaces the old SHA-256 block).
set -euo pipefail

VERSION="${1:?usage: gen-release-body.sh <version> [changelog] [output]}"
CHANGELOG="${2:-Changelog.md}"
OUTPUT="${3:--}"

REPO="Picocrypt-NG/Picocrypt-NG"
BASE="https://github.com/$REPO/releases/download/$VERSION"
ANCHOR="v${VERSION//./}"  # GitHub header anchor for "# v2.16" is "#v216"

# --- "What's new": extract the section and convert its HTML to Markdown -------
# Recent (2.x) entries are uniformly "<li>✓ <strong>X</strong>: Y</li>" lines
# wrapped in <ul>/</ul>, so after dropping the wrappers every line is one bullet.
whatsnew="$(
  tr -d '\r' < "$CHANGELOG" \
  | awk -v hdr="# v$VERSION" '
      $0 == hdr || index($0, hdr " ") == 1 { grab = 1; next }
      grab && /^# v/ { grab = 0 }
      grab { print }
    ' \
  | sed -e 's/^[[:space:]]*//' \
        -e '/^<ul>$/d' -e '/^<\/ul>$/d' \
        -e 's/^<li>✓[[:space:]]*//' -e 's/<\/li>$//' \
        -e 's/<strong>/**/g' -e 's#</strong>#**#g' \
        -e 's/<code>/`/g' -e 's#</code>#`#g' \
        -e 's/<em>/*/g' -e 's#</em>#*#g' -e 's/<i>/*/g' -e 's#</i>#*#g' \
        -e 's#<a href="\([^"]*\)">\([^<]*\)</a>#[\2](\1)#g' \
        -e 's/&amp;/\&/g' -e 's/&lt;/</g' -e 's/&gt;/>/g' \
  | sed -e 's/^\(..*\)$/- \1/'
)"
[ -n "$whatsnew" ] || { echo "release-body: no '# v$VERSION' section in $CHANGELOG" >&2; exit 1; }

# --- Assemble the body --------------------------------------------------------
body="$(cat <<EOF
## Downloads

| Architecture | Windows | macOS | Linux | Android | Web |
|---|---|---|---|---|---|
| **x86-64** (64-bit) | [Installer]($BASE/Picocrypt-NG-Setup.exe) · [Portable]($BASE/Picocrypt-NG-portable.exe) · [CLI]($BASE/Picocrypt-NG-cli.exe) | — | [AppImage]($BASE/Picocrypt-NG-$VERSION-x86_64.AppImage) · [.deb]($BASE/Picocrypt-NG.deb) · [Binary]($BASE/Picocrypt-NG) · [CLI]($BASE/Picocrypt-NG-cli) · [Snap]($BASE/picocrypt-ng_${VERSION}_amd64.snap) | [APK]($BASE/Picocrypt-NG-android-x86_64.apk) | [Open](https://picocrypt-ng.github.io/) |
| **ARM64** (AArch64) | — | [DMG]($BASE/Picocrypt-NG.dmg) · [CLI]($BASE/Picocrypt-NG-cli-macos) | [Binary]($BASE/Picocrypt-NG-arm64) · [CLI]($BASE/Picocrypt-NG-cli-arm64) | [APK]($BASE/Picocrypt-NG-android-arm64-v8a.apk) | |

- 🌐 **Web version** — runs in any modern browser, nothing to install: <https://picocrypt-ng.github.io/>
- **Android 7.0+ on 64-bit ARM or x86-64 devices** — [universal APK]($BASE/Picocrypt-NG-android-universal.apk)
- **Windows 7/8 (legacy) CLI** (x86-64): [Download]($BASE/Picocrypt-NG-cli-Legacy.exe)
- macOS builds are **Apple Silicon (ARM64)** only.

---

## What's new in $VERSION

$whatsnew

Full changelog: https://github.com/$REPO/blob/main/Changelog.md#$ANCHOR

---

## Verifying your download

Every artifact is signed with keyless [cosign](https://github.com/sigstore/cosign) (a \`<file>.sigstore.json\` bundle ships next to it) and carries a GitHub build-provenance attestation. No keys to trust — the signature is bound to the exact GitHub Actions run that built the file.

Build provenance (easiest, needs the [\`gh\`](https://cli.github.com/) CLI):

\`\`\`sh
gh attestation verify <file> --repo $REPO
\`\`\`

Cosign bundle (download the matching \`<file>.sigstore.json\` too):

\`\`\`sh
cosign verify-blob <file> \\
  --bundle <file>.sigstore.json \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
  --certificate-identity-regexp '^https://github.com/$REPO/\.github/workflows/'
\`\`\`
EOF
)"

if [ "$OUTPUT" = "-" ]; then
  printf '%s\n' "$body"
else
  printf '%s\n' "$body" > "$OUTPUT"
fi
