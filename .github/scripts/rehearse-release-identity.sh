#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

fail() { printf 'Identity rehearsal: %s\n' "$*" >&2; exit 1; }

check_certificate() {
  [[ $# == 5 ]] || fail 'check-verified-certificate requires verified JSON, caller, callee, SHA and ref'
  # Input is accepted only after gh verification by the hosted path below. This
  # separate entry point lets policy tests exercise field matching without OIDC.
  jq -e --arg caller "$2" --arg callee "$3" --arg sha "$4" --arg ref "$5" '
    type == "array" and length == 1 and
    (.[0].verificationResult.signature.certificate |
      .issuer == "https://token.actions.githubusercontent.com" and
      .subjectAlternativeName == $callee and
      .buildSignerURI == $callee and .buildSignerDigest == $sha and
      .buildConfigURI == $caller and .buildConfigDigest == $sha and
      .sourceRepositoryURI == "https://github.com/Picocrypt-NG/Picocrypt-NG" and
      .sourceRepositoryDigest == $sha and .sourceRepositoryRef == $ref and
      .runnerEnvironment == "github-hosted")
  ' "$1" >/dev/null || {
    printf 'Identity rehearsal: verified certificate policy mismatch\n' >&2
    return 1
  }
}

check_offline_gh_rejection() {
  [[ $# == 1 && -f $1 && ! -L $1 ]] || fail 'check-offline-gh-rejection requires a regular diagnostic file'
  local diagnostic
  diagnostic=$(< "$1")
  diagnostic=${diagnostic#$'\n'}
  # gh 2.102.1 hides the underlying Sigstore error; setup and transport errors differ.
  case "$diagnostic" in
    'Error: verifying with issuer "sigstore.dev"'|'Error: verifying with issuer "GitHub, Inc."') ;;
    *) fail 'unexpected offline gh verification failure' ;;
  esac
}

[[ $# -ge 1 ]] || fail 'expected a rehearsal operation'
mode=$1
shift
if [[ $mode == check-verified-certificate ]]; then
  check_certificate "$@"
  exit
fi
if [[ $mode == check-offline-gh-rejection ]]; then
  check_offline_gh_rejection "$@"
  exit
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $mode == install-gh ]]; then
  [[ $# == 0 && $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'install-gh requires Linux x86_64 and no arguments'
  manifest="$script_dir/../toolchains/release-identity-rehearsal.json"
  jq -e '.schema_version == 1 and .gh.version == "2.102.1" and
    .gh.url == "https://github.com/cli/cli/releases/download/v2.102.1/gh_2.102.1_linux_amd64.tar.gz" and
    (.gh.sha256 | test("^[0-9a-f]{64}$"))' "$manifest" >/dev/null || fail 'invalid gh pin manifest'
  tools=$(mktemp -d "${RUNNER_TEMP:?RUNNER_TEMP is required}/identity-gh.XXXXXXXX")
  archive="$tools/gh.tar.gz"
  curl --fail --location --proto '=https' --proto-redir '=https' --silent --show-error \
    --connect-timeout 20 --max-time 180 --retry 2 --retry-max-time 180 \
    --output "$archive" "$(jq -er '.gh.url' "$manifest")"
  actual=$(sha256sum < "$archive")
  [[ ${actual%% *} == "$(jq -er '.gh.sha256' "$manifest")" ]] || fail 'gh archive checksum mismatch'
  tar -xzf "$archive" --directory "$tools" --strip-components=2 gh_2.102.1_linux_amd64/bin/gh
  rm -- "$archive"
  "$tools/gh" --version | head -n 1
  printf '%s\n' "$tools" >> "${GITHUB_PATH:?GITHUB_PATH is required}"
  exit
fi

[[ $# == 1 && ( $1 == direct || $1 == reusable ) ]] || fail 'expected exactly one fixed probe kind: direct or reusable'
kind=$1
repo=Picocrypt-NG/Picocrypt-NG
ref=refs/heads/ci/rehearse-release-identity
[[ ${GITHUB_REPOSITORY:-} == "$repo" && ${GITHUB_REF:-} == "$ref" && ${GITHUB_EVENT_NAME:-} == push ]] || fail 'only the explicit same-repository rehearsal branch push is allowed'
[[ ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || fail 'a GitHub-hosted runner is required'
sha=${GITHUB_SHA:?GITHUB_SHA is required}
[[ $sha =~ ^[0-9a-f]{40}$ && ${GITHUB_WORKFLOW_SHA:-} == "$sha" && $(git rev-parse HEAD) == "$sha" ]] || fail 'source and caller workflow commits must match the checkout'
[[ ${GITHUB_RUN_ID:-} =~ ^[0-9]+$ && ${GITHUB_RUN_ATTEMPT:-} =~ ^[0-9]+$ ]] || fail 'run identity is required'
caller="https://github.com/${GITHUB_WORKFLOW_REF:?GITHUB_WORKFLOW_REF is required}"
primary="https://github.com/$repo/.github/workflows/rehearse-release-identity.yml@$ref"
alternate="https://github.com/$repo/.github/workflows/rehearse-release-identity-alternate.yml@$ref"
[[ $caller == "$primary" || ( $kind == reusable && $caller == "$alternate" ) ]] || fail 'unexpected caller workflow'
callee=$caller
if [[ $kind == reusable ]]; then
  callee="https://github.com/$repo/.github/workflows/rehearse-release-identity-leaf.yml@$ref"
fi
directory="rehearsal-release-identity/$kind"

update_report() {
  jq "$1" "$directory/report.json" > "$directory/report.next.json"
  mv -- "$directory/report.next.json" "$directory/report.json"
}

case "$mode" in
  prepare)
    [[ ! -e $directory && ! -L $directory ]] || fail 'probe output already exists'
    mkdir -p -- "$directory"
    jq -n --arg repo "$repo" --arg caller "$caller" --arg callee "$callee" \
      --arg sha "$sha" --arg ref "$ref" --arg kind "$kind" \
      --arg run "$GITHUB_RUN_ID" --arg attempt "$GITHUB_RUN_ATTEMPT" \
      '{schema_version:1, repository:$repo, caller:$caller, callee:$callee, source_sha:$sha,
        source_ref:$ref, kind:$kind, run_id:$run, run_attempt:$attempt,
        built:true, signed:false, verified:false, published:false, signing:"public-ephemeral-oidc"}' \
      > "$directory/report.json"
    cp -- "$directory/report.json" "$directory/probe.txt"
    gh --version | head -n 1 > "$directory/gh-version.txt"
    grep -Eq '^gh version 2[.]102[.]1([[:space:]]|$)' "$directory/gh-version.txt" || fail 'unexpected gh version'
    cosign version --json > "$directory/cosign-version.json"
    jq -e '.gitVersion == "v3.1.3"' "$directory/cosign-version.json" >/dev/null || fail 'unexpected cosign version'
    ;;
  observe-oidc)
    export REHEARSAL_DIRECTORY="$directory"
    node --input-type=module <<'NODE'
import {writeFileSync} from 'node:fs';
try {
const url = new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);
url.searchParams.set('audience', 'sigstore');
const response = await fetch(url, {
  headers: {Authorization: `bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`},
  signal: AbortSignal.timeout(30000),
});
if (!response.ok) throw new Error('OIDC request failed');
const token = (await response.json()).value;
if (typeof token !== 'string' || token.split('.').length !== 3) throw new Error('Invalid OIDC response');
const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
const fields = ['iss', 'aud', 'repository', 'repository_id', 'ref', 'sha', 'workflow_ref',
  'workflow_sha', 'job_workflow_ref', 'job_workflow_sha', 'runner_environment',
  'run_id', 'run_attempt', 'event_name'];
const selected = {unverified_token_claim_observation: true};
for (const field of fields) selected[field] = claims[field] ?? null;
writeFileSync(`${process.env.REHEARSAL_DIRECTORY}/oidc-claims.json`, `${JSON.stringify(selected, null, 2)}\n`, {mode: 0o600});
} catch {
  console.error('OIDC observation failed');
  process.exitCode = 1;
}
NODE
    ;;
  sign)
    cosign sign-blob "$directory/probe.txt" --bundle "$directory/probe.sigstore.json" --yes
    test -s "$directory/probe.sigstore.json"
    update_report '.signed = true'
    ;;
  verify)
    bundle=${PROVENANCE_BUNDLE:?the exact attest action bundle is required}
    [[ -f $bundle && ! -L $bundle && -s $bundle ]] || fail 'provenance bundle must be a nonempty regular file'
    cp -- "$bundle" "$directory/probe.provenance.json"
    signer_workflow=${callee#https://github.com/}
    signer_workflow=${signer_workflow%@*}
    verification_gh() {
      env -u GH_DEBUG -u GH_FORCE_TTY GH_HOST=github.com GH_TOKEN=offline-rehearsal-verification \
        GITHUB_TOKEN= GH_CONFIG_DIR="$directory/gh-no-credentials" gh "$@"
    }
    verification_gh attestation trusted-root --hostname github.com > "$directory/trusted-root.jsonl"
    test -s "$directory/trusted-root.jsonl"
    verify_cosign() {
      cosign verify-blob "$1" --bundle "$directory/probe.sigstore.json" \
        --certificate-identity "$2" --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate-github-workflow-sha "$sha" --certificate-github-workflow-ref "$ref" \
        --certificate-github-workflow-repository "$repo"
    }
    verify_provenance() {
      verification_gh attestation verify "$1" --bundle "$2" --custom-trusted-root "$directory/trusted-root.jsonl" --repo "$repo" \
        --signer-workflow "$signer_workflow" --signer-digest "$4" \
        --source-ref "$ref" --source-digest "$3" --predicate-type https://slsa.dev/provenance/v1 \
        --deny-self-hosted-runners --format json
    }
    verify_cosign "$directory/probe.txt" "$callee"
    verify_provenance "$directory/probe.txt" "$directory/probe.provenance.json" "$sha" "$sha" > "$directory/verified.json"
    check_certificate "$directory/verified.json" "$caller" "$callee" "$sha" "$ref"

    rejected() {
      local name=$1 diagnostic=$2
      shift 2
      if "$@" > "$directory/rejected-$name.log" 2>&1; then
        fail "negative control accepted: $name"
      fi
      grep -Eq "$diagnostic" "$directory/rejected-$name.log" || fail "negative control had an unexpected failure: $name"
      printf '%s\n' "$name" >> "$directory/rejected-controls.txt"
    }
    rejected_integrity() {
      local name=$1 artifact=$2 provenance=$3
      # Bracket each local failure: gh exposes only the issuer, not its underlying error.
      verify_provenance "$directory/probe.txt" "$directory/probe.provenance.json" "$sha" "$sha" > "$directory/verified-before-$name.json"
      check_certificate "$directory/verified-before-$name.json" "$caller" "$callee" "$sha" "$ref"
      if verify_provenance "$artifact" "$provenance" "$sha" "$sha" > "$directory/rejected-$name.log" 2>&1; then
        fail "negative control accepted: $name"
      fi
      check_offline_gh_rejection "$directory/rejected-$name.log"
      verify_provenance "$directory/probe.txt" "$directory/probe.provenance.json" "$sha" "$sha" > "$directory/verified-after-$name.json"
      check_certificate "$directory/verified-after-$name.json" "$caller" "$callee" "$sha" "$ref"
      printf '%s\n' "$name" >> "$directory/rejected-controls.txt"
    }
    other_caller=$alternate
    [[ $caller != "$alternate" ]] || other_caller=$primary
    other_callee=$primary
    [[ $callee != "$primary" ]] || other_callee="https://github.com/$repo/.github/workflows/rehearse-release-identity-leaf.yml@$ref"
    wrong_sha=0000000000000000000000000000000000000000
    [[ $sha != "$wrong_sha" ]] || wrong_sha=1111111111111111111111111111111111111111
    rejected caller 'verified certificate policy mismatch' check_certificate "$directory/verified.json" "$other_caller" "$callee" "$sha" "$ref"
    rejected callee 'verified certificate policy mismatch' check_certificate "$directory/verified.json" "$caller" "$other_callee" "$sha" "$ref"
    rejected source-ref 'verified certificate policy mismatch' check_certificate "$directory/verified.json" "$caller" "$callee" "$sha" refs/heads/main
    rejected source-sha 'expected SourceRepositoryDigest' verify_provenance "$directory/probe.txt" "$directory/probe.provenance.json" "$wrong_sha" "$sha"
    rejected signer-sha 'expected BuildSignerDigest' verify_provenance "$directory/probe.txt" "$directory/probe.provenance.json" "$sha" "$wrong_sha"
    rejected certificate-commit-sha 'verified certificate policy mismatch' check_certificate "$directory/verified.json" "$caller" "$callee" "$wrong_sha" "$ref"
    rejected cosign-callee 'expected SAN value' verify_cosign "$directory/probe.txt" "$other_callee"
    cp -- "$directory/probe.txt" "$directory/altered-probe.txt"
    printf 'altered\n' >> "$directory/altered-probe.txt"
    rejected_integrity altered-payload "$directory/altered-probe.txt" "$directory/probe.provenance.json"
    jq -e 'if (.dsseEnvelope.signatures | length) == 1 then
      .dsseEnvelope.signatures[0].sig |= (if startswith("A") then "B" + .[1:] else "A" + .[1:] end)
      else error("expected one DSSE signature") end' "$directory/probe.provenance.json" > "$directory/altered-provenance.json"
    rejected_integrity altered-signature "$directory/probe.txt" "$directory/altered-provenance.json"
    update_report '.verified = true'
    jq -r '"Identity rehearsal (" + .kind + "): built=" + (.built|tostring) + ", signed=" + (.signed|tostring) + ", verified=" + (.verified|tostring) + ", published=false"' "$directory/report.json" >> "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"
    ;;
  *) fail 'unsupported operation' ;;
esac
