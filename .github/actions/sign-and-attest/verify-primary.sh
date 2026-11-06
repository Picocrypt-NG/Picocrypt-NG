#!/usr/bin/env bash
set -euo pipefail

[[ $# == 3 ]] || exit 2
artifact=$1 workflow=$2 source_sha=$3
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
case "$workflow" in
  build-linux.yml|build-macos.yml|build-windows.yml|build-windows-legacy.yml|build-android.yml|build-appimage.yml|build-snapcraft.yml) ;;
  *) echo "release gate: unknown canonical workflow owner" >&2; exit 1 ;;
esac
identity="https://github.com/$repo/.github/workflows/$workflow@refs/heads/main"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
verified="$work/verified-provenance.json"
cosign verify-blob "$artifact" \
  --bundle "$artifact.sigstore.json" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-github-workflow-sha "$source_sha" \
  --certificate-github-workflow-ref "refs/heads/main" \
  --certificate-github-workflow-repository "$repo" || exit 1
gh attestation verify "$artifact" \
  --repo "$repo" \
  --cert-identity "$identity" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signer-digest "$source_sha" \
  --source-ref "refs/heads/main" \
  --source-digest "$source_sha" \
  --predicate-type "https://slsa.dev/provenance/v1" \
  --deny-self-hosted-runners --format json > "$verified" || exit 1
bash "$(dirname -- "${BASH_SOURCE[0]}")/verify-certificate.sh" online "$verified" "$workflow" "$source_sha"
