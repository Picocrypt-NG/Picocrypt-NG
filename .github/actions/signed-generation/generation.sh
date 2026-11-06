#!/usr/bin/env bash
set -euo pipefail

fail() { echo "signed generation: $*" >&2; exit 1; }
mode=${1:-}
case "$mode" in record|metadata|restore) ;; *) fail 'expected record|metadata|restore' ;; esac
repo=${GITHUB_REPOSITORY:?}
owner=${GENERATION_OWNER:?}
directory=${GENERATION_DIR:?}
[[ $repo == Picocrypt-NG/Picocrypt-NG && $SOURCE_SHA == "$GITHUB_SHA" && $SOURCE_SHA =~ ^[0-9a-f]{40}$ ]] || fail 'wrong repository/source'
[[ $(git rev-parse HEAD) == "$SOURCE_SHA" && $(tr -d '\r\n' < VERSION) == "$SOURCE_VERSION" ]] || fail 'wrong checkout/version'
[[ $GITHUB_RUN_ID =~ ^[1-9][0-9]*$ && $GITHUB_RUN_ATTEMPT =~ ^[1-9][0-9]*$ ]] || fail 'wrong run/attempt'
case "$owner" in
  build-linux.yml|build-macos.yml|build-windows.yml|build-windows-legacy.yml|build-android.yml|build-appimage.yml|build-snapcraft.yml) ;;
  *) fail 'unknown owner' ;;
esac
helper=$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
workspace=$(pwd -P)
canonical=$(bash "$helper/../stage-release/release-manifest.sh" "$SOURCE_VERSION")
digest=$(printf '%s\n' "$canonical" | sha256sum)
[[ ${digest%% *} == "$CANONICAL_MANIFEST_SHA256" ]] || fail 'wrong canonical digest'
expected=$(awk -v owner="$owner" '$2 == owner {print $1 "\t" $3; print $1 ".sigstore.json\t" $3 ".sigstore.json"}' <<< "$canonical" | LC_ALL=C sort)
[[ -n $expected ]] || fail 'empty owner'
expected_json=$(jq -Rn '[inputs|split("\t")|{name:.[0],path:.[1]}]' <<< "$expected")
primaries=$(awk -v owner="$owner" '$2 == owner {print $1}' <<< "$canonical")
attempt=$GITHUB_RUN_ATTEMPT
if [[ $mode != record ]]; then
  [[ $GENERATION_ARTIFACT_ID =~ ^[1-9][0-9]*$ && $GENERATION_ARTIFACT_DIGEST =~ ^[0-9a-f]{64}$ && $GENERATION_ARTIFACT_ATTEMPT =~ ^[1-9][0-9]*$ ]] || fail 'invalid artifact binding'
  attempt=$GENERATION_ARTIFACT_ATTEMPT
  (( attempt <= GITHUB_RUN_ATTEMPT )) || fail 'future generation'
fi
name="signed-${owner%.yml}-attempt-$attempt"
if [[ $mode == metadata ]]; then
  metadata=$(gh api --method GET "repos/$repo/actions/artifacts/$GENERATION_ARTIFACT_ID") || fail 'artifact metadata unavailable'
  jq -e --arg id "$GENERATION_ARTIFACT_ID" --arg name "$name" --arg digest "sha256:$GENERATION_ARTIFACT_DIGEST" \
    --arg run "$GITHUB_RUN_ID" --arg source "$SOURCE_SHA" \
    '(.id|tostring) == $id and .name == $name and .digest == $digest and .expired == false
      and (.workflow_run.id|tostring) == $run and .workflow_run.head_sha == $source' <<< "$metadata" >/dev/null || fail 'artifact metadata mismatch/expired'
  exit 0
fi

check_parents() {
  local parent
  parent=$(dirname -- "$1")
  while [[ $parent != . ]]; do
    [[ ! -L $parent ]] || return 1
    if [[ -e $parent && ! -d $parent ]]; then return 1; fi
    parent=$(dirname -- "$parent")
  done
}

if [[ $mode == record ]]; then
  [[ ! -e $directory && ! -L $directory ]] || fail 'generation destination already exists'
  parent=$(dirname -- "$directory")
  [[ -d $parent ]] || fail 'generation parent missing'
  work=$(mktemp -d "$parent/.signed-generation.XXXXXX")
else
  [[ -d $directory && ! -L $directory ]] || fail 'generation directory missing/link'
  work=$(mktemp -d)
fi
trap 'rm -rf -- "$work"' EXIT
mkdir -m 0700 "$work/archive"
if [[ $mode == restore ]]; then
  manifest="$directory/generation-manifest.json"
  [[ -f $manifest && ! -L $manifest && -s $manifest ]] || fail 'invalid generation manifest'
  jq -e --arg repository "$repo" --arg source "$SOURCE_SHA" --arg version "$SOURCE_VERSION" \
    --arg canonical "$CANONICAL_MANIFEST_SHA256" --arg owner "$owner" --arg run "$GITHUB_RUN_ID" --arg attempt "$attempt" --argjson expected "$expected_json" '
    type == "object" and keys == ["canonical_manifest_sha256","files","owner_workflow","repository","run_attempt","run_id","schema_version","source_sha","version"]
      and .schema_version == 1 and .repository == $repository and .source_sha == $source and .version == $version
      and .canonical_manifest_sha256 == $canonical and .owner_workflow == $owner and .run_id == $run and .run_attempt == $attempt
      and (.files|type == "array") and ([.files[]|{name,path}]|sort_by(.name)) == $expected
      and all(.files[]; type == "object" and keys == ["name","path","sha256"] and (.sha256|type == "string" and test("^[0-9a-f]{64}$")))
    ' "$manifest" >/dev/null || fail 'generation manifest mismatch'
  actual=$(find "$directory" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
  names=$(printf '%s\n' "$expected" | cut -f1)
  [[ $actual == "$(printf '%s\ngeneration-manifest.json\n' "$names" | LC_ALL=C sort)" ]] || fail 'generation file set mismatch'
  cp -- "$manifest" "$work/archive/generation-manifest.json"
fi
while IFS=$'\t' read -r file path; do
  if [[ $mode == record ]]; then
    check_parents "$path" || fail 'canonical parent is a link/non-directory'
    source=$path
    resolved=$(realpath -- "$source")
    [[ $resolved == "$workspace/"* ]] || fail 'canonical input outside workspace'
  else source="$directory/$file"
  fi
  [[ -f $source && ! -L $source && -s $source ]] || fail "missing/invalid full-owner file $file"
  cp -- "$source" "$work/archive/$file"
done <<< "$expected"
if [[ $mode == restore ]]; then
  (cd "$work/archive"; jq -r '.files[]|"\(.sha256)  \(.name)"' generation-manifest.json | sha256sum --check --strict --status) || fail 'generation bytes differ'
fi
while IFS= read -r file; do
  bash "$helper/../sign-and-attest/verify-primary.sh" "$work/archive/$file" "$owner" "$SOURCE_SHA" >&2 || fail 'signed pair verification failed'
done <<< "$primaries"
if [[ $mode == record ]]; then
  files=$(while IFS=$'\t' read -r file path; do
    hash=$(sha256sum "$work/archive/$file") || exit 1
    jq -cn --arg name "$file" --arg path "$path" --arg sha256 "${hash%% *}" '{name:$name,path:$path,sha256:$sha256}' || exit 1
  done <<< "$expected" | jq -sc 'sort_by(.name)')
  jq -nS --arg repository "$repo" --arg source_sha "$SOURCE_SHA" --arg version "$SOURCE_VERSION" \
    --arg canonical_manifest_sha256 "$CANONICAL_MANIFEST_SHA256" --arg owner_workflow "$owner" --arg run_id "$GITHUB_RUN_ID" --arg run_attempt "$attempt" --argjson files "$files" \
    '{schema_version:1,repository:$repository,source_sha:$source_sha,version:$version,canonical_manifest_sha256:$canonical_manifest_sha256,
      owner_workflow:$owner_workflow,run_id:$run_id,run_attempt:$run_attempt,files:$files}' > "$work/archive/generation-manifest.json"
  mv -T --no-clobber -- "$work/archive" "$directory"
  [[ ! -e $work/archive ]] || fail 'generation destination appeared'
  if [[ -n ${GITHUB_OUTPUT:-} ]]; then printf 'artifact-name=%s\nrun-attempt=%s\n' "$name" "$attempt" >> "$GITHUB_OUTPUT"; fi
  exit 0
fi

# Check every destination before creating any canonical path.
while IFS=$'\t' read -r file path; do
  check_parents "$path" || fail 'canonical parent is a link/non-directory'
  if [[ -e $path || -L $path ]]; then
    [[ -f $path && ! -L $path && -s $path ]] || fail 'canonical destination is not a regular file'
    cmp -s -- "$work/archive/$file" "$path" || fail 'canonical destination differs; originals preserved'
  fi
done <<< "$expected"
while IFS=$'\t' read -r file path; do
  mkdir -p -- "$(dirname -- "$path")"
  cp --no-clobber -- "$work/archive/$file" "$path"
  [[ -f $path && ! -L $path ]] || fail 'canonical destination changed'
  cmp -s -- "$work/archive/$file" "$path" || fail 'canonical destination changed; originals preserved'
done <<< "$expected"
