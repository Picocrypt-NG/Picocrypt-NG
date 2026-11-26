#!/usr/bin/env bash

set -euo pipefail

fail() {
  echo "stage receipt: $1" >&2
  exit 1
}

[[ $# == 2 ]] || fail 'expected an artifact ID and release version'
artifact_id=$1
version=$2
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
repository_id="${GITHUB_REPOSITORY_ID:?GITHUB_REPOSITORY_ID is required}"
output="${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
[[ $repo == Picocrypt-NG/Picocrypt-NG && $repository_id =~ ^[1-9][0-9]*$ ]] ||
  fail 'unexpected repository'
[[ $artifact_id =~ ^[1-9][0-9]*$ && $version =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] ||
  fail 'invalid receipt ID or release version'

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
artifact_api="repos/$repo/actions/artifacts/$artifact_id"
archive_limit=65536

gh api "$artifact_api" > "$work/artifact.json" || fail 'could not read artifact metadata'
artifact_fields=$(
  jq -ser --arg artifact "$artifact_id" --arg repository "$repository_id" \
    --argjson limit "$archive_limit" '
    select(length == 1) | .[0] |
    .workflow_run as $run |
    select((.id | tostring) == $artifact and .expired == false and
      (.size_in_bytes | type == "number" and . > 0 and . <= $limit) and
      (.digest | test("\\Asha256:[0-9a-f]{64}\\z")) and
      (.name | test("\\Arelease-stage-receipt-attempt-[1-9][0-9]*\\z")) and
      ($run.id | tostring | test("\\A[1-9][0-9]*\\z")) and
      ($run.repository_id | tostring) == $repository and
      ($run.head_repository_id | tostring) == $repository and
      $run.head_branch == "main" and ($run.head_sha | test("\\A[0-9a-f]{40}\\z"))) |
    [$run.id, (.name | sub("^release-stage-receipt-attempt-"; "")), $run.head_sha, .digest] | @tsv
  ' "$work/artifact.json"
) || fail 'invalid, expired or foreign stage receipt artifact'
IFS=$'\t' read -r run_id attempt source_sha archive_digest <<< "$artifact_fields"

attempt_api="repos/$repo/actions/runs/$run_id/attempts/$attempt"
gh api "$attempt_api" > "$work/attempt.json" || fail 'could not read producing workflow attempt'
jq -se --arg run "$run_id" --arg attempt "$attempt" --arg source "$source_sha" \
  --arg repository "$repository_id" '
  length == 1 and (.[0] |
    (.id | tostring) == $run and (.run_attempt | tostring) == $attempt and
    .path == ".github/workflows/release.yml" and .event == "workflow_dispatch" and
    .status == "completed" and .conclusion == "success" and
    .head_branch == "main" and .head_sha == $source and
    (.repository.id | tostring) == $repository and
    (.head_repository.id | tostring) == $repository)
' "$work/attempt.json" >/dev/null || fail 'receipt did not come from a successful main coordinator attempt'

if ! gh api --paginate "$attempt_api/jobs?per_page=100" |
  jq -se --arg run "$run_id" --arg source "$source_sha" '
    [.[].jobs[] | select(.name == "result")] |
    length == 1 and (.[0] |
      .status == "completed" and .conclusion == "success" and
      (.run_id | tostring) == $run and .head_sha == $source and
      ([.steps[] | select(.name == "Upload staged candidate receipt")] |
        length == 1 and (.[0] | .status == "completed" and .conclusion == "success")))
  ' >/dev/null; then
  fail 'the producing attempt did not upload a verified stage receipt'
fi

archive="$work/receipt.zip"
gh api --allow-escape-sequences "$artifact_api/zip" |
  head -c "$((archive_limit + 1))" > "$archive" || fail 'could not download receipt archive'
(( $(wc -c < "$archive") <= archive_limit )) || fail 'receipt archive exceeds the size limit'
download_digest=$(sha256sum "$archive")
[[ sha256:${download_digest%% *} == "$archive_digest" ]] || fail 'receipt archive digest mismatch'

# Read the single payload without extracting an archive member onto the filesystem.
python3 -I - "$archive" > "$work/receipt.json" <<'PY' || fail 'invalid receipt archive or JSON'
import json
import stat
import sys
import zipfile


def unique_object(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError
        fields[key] = value
    return fields


try:
    limit = 4096
    with zipfile.ZipFile(sys.argv[1]) as archive:
        members = archive.infolist()
        if len(members) != 1:
            raise ValueError
        member = members[0]
        file_type = stat.S_IFMT(member.external_attr >> 16)
        if (member.orig_filename != "receipt.json"
                or file_type not in (0, stat.S_IFREG)
                or not 0 < member.file_size <= limit):
            raise ValueError
        with archive.open(member) as source:
            payload = source.read(limit + 1)
        if not 0 < len(payload) <= limit:
            raise ValueError
    receipt = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_object)
    print(json.dumps(receipt, allow_nan=False))
except (OSError, ValueError, EOFError, RuntimeError, zipfile.BadZipFile):
    sys.exit(1)
PY

receipt_fields=$(
  jq -er --arg repo "$repo" --arg version "$version" --arg source "$source_sha" \
    --arg run "$run_id" --arg attempt "$attempt" '
    select(keys == ["candidate_digest","mode","release_id","repository","run_attempt",
                    "run_id","schema","source_sha","version"] and
      .schema == 1 and .mode == "stage" and .repository == $repo and
      .version == $version and .source_sha == $source and
      .run_id == $run and .run_attempt == $attempt and
      (.release_id | test("\\A[1-9][0-9]*\\z")) and (.candidate_digest | test("\\A[0-9a-f]{64}\\z"))) |
    [.release_id, .candidate_digest] | @tsv
  ' "$work/receipt.json"
) || fail 'receipt does not match the approved workflow source or release version'
IFS=$'\t' read -r release_id candidate_digest <<< "$receipt_fields"
printf 'source-sha=%s\ncandidate-digest=%s\nrelease-id=%s\nstage-run-id=%s\nstage-run-attempt=%s\n' \
  "$source_sha" "$candidate_digest" "$release_id" "$run_id" "$attempt" >> "$output"
