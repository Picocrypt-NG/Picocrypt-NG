#!/usr/bin/env bash
# Policy only: input must come from successful gh attestation verify --format json.
set -euo pipefail

fail() { echo 'release identity: verified provenance certificate policy mismatch' >&2; exit 1; }
[[ $# == 4 || $# == 5 ]] || fail
mode=$1
verified=$2
owner=$3
sha=$4
repo=Picocrypt-NG/Picocrypt-NG
case "$owner" in
    build-linux.yml|build-macos.yml|build-windows.yml|build-windows-legacy.yml|build-android.yml|build-appimage.yml|build-snapcraft.yml) ;;
    *) fail ;;
esac
[[ $sha =~ ^[0-9a-f]{40}$ && -f $verified && ! -L $verified && -s $verified ]] || fail
owner_uri="https://github.com/$repo/.github/workflows/$owner@refs/heads/main"
coordinator_uri="https://github.com/$repo/.github/workflows/release.yml@refs/heads/main"
caller_uri=
case "$mode" in
    exact)
        [[ $# == 5 ]] || fail
        case "$5" in
            "$repo/.github/workflows/$owner@refs/heads/main"|"$repo/.github/workflows/release.yml@refs/heads/main") caller_uri="https://github.com/$5" ;;
            *) fail ;;
        esac
        ;;
    online) [[ $# == 4 ]] || fail ;;
    *) fail ;;
esac

jq -e --arg mode "$mode" --arg owner "$owner_uri" --arg coordinator "$coordinator_uri" \
    --arg caller "$caller_uri" --arg sha "$sha" '
    type == "array" and length > 0 and ($mode == "online" or length == 1) and
    all(.[]; .verificationResult.signature.certificate |
      .issuer == "https://token.actions.githubusercontent.com" and
      .subjectAlternativeName == $owner and
      .buildSignerURI == $owner and .buildSignerDigest == $sha and
      (.buildConfigURI == $owner or .buildConfigURI == $coordinator) and
      ($mode == "online" or .buildConfigURI == $caller) and .buildConfigDigest == $sha and
      .sourceRepositoryURI == "https://github.com/Picocrypt-NG/Picocrypt-NG" and
      .sourceRepositoryDigest == $sha and .sourceRepositoryRef == "refs/heads/main" and
      .runnerEnvironment == "github-hosted")
' "$verified" >/dev/null || fail
