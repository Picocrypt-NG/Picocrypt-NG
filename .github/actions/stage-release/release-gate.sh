#!/usr/bin/env bash

set -euo pipefail

usage="usage: release-gate.sh <preflight|upload|inspect-owner|verify-staged|strict-finalize> <version>"
mode="${1:?$usage}"
version="${2:?$usage}"
scope="${RELEASE_SCOPE:-full}"
windows_after_core="${RELEASE_WINDOWS_AFTER_CORE:-false}"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
driver_sha="${GITHUB_SHA:?GITHUB_SHA is required}"
source_sha="$driver_sha"
workspace="${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"

set_gate_output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
  fi
}
set_gate_output staged false
set_gate_output published false

case "$mode" in
  preflight|upload|inspect-owner|verify-staged|strict-finalize) ;;
  *)
    echo "release gate: unsupported mode '$mode'" >&2
    exit 2
    ;;
esac
case "$scope:$mode" in
  full:*|core:verify-staged|core:strict-finalize) ;;
  *) echo "release gate: invalid release scope for $mode" >&2; exit 2 ;;
esac
case "$windows_after_core:$mode" in
  false:*|true:inspect-owner|true:preflight|true:upload) ;;
  *) echo "release gate: invalid deferred Windows publication mode" >&2; exit 2 ;;
esac
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo "release gate: invalid version '$version'" >&2
  exit 2
fi
if [[ ! "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "release gate: invalid repository '$repo'" >&2
  exit 2
fi
if [[ ! "$driver_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "release gate: invalid workflow commit" >&2
  exit 2
fi
if [[ "$workspace" != /* ]] || [ ! -d "$workspace" ]; then
  echo "release gate: invalid GitHub workspace '$workspace'" >&2
  exit 2
fi

if [ "$repo" != "Picocrypt-NG/Picocrypt-NG" ]; then
  echo "release gate: unexpected repository '$repo'" >&2
  exit 2
fi
source_version="$(<"$workspace/VERSION")"
source_version="${source_version%$'\r'}"
if [ "$source_version" != "$version" ]; then
  echo "release gate: root VERSION '$source_version' does not match '$version'" >&2
  exit 2
fi
checkout_sha="$(git -C "$workspace" rev-parse HEAD)"
if [ "$checkout_sha" != "$driver_sha" ]; then
  echo "release gate: checkout commit '$checkout_sha' does not match '$driver_sha'" >&2
  exit 2
fi
workflow_ref="${GITHUB_WORKFLOW_REF:?GITHUB_WORKFLOW_REF is required}"
if [ "${GITHUB_WORKFLOW_SHA:-}" != "$driver_sha" ]; then
  echo "release gate: caller workflow commit must match the dispatch commit" >&2
  exit 2
fi
case "$workflow_ref" in
  "$repo/.github/workflows/build-linux.yml@refs/heads/main"| \
  "$repo/.github/workflows/build-macos.yml@refs/heads/main"| \
  "$repo/.github/workflows/build-windows.yml@refs/heads/main"| \
  "$repo/.github/workflows/build-windows-legacy.yml@refs/heads/main"| \
  "$repo/.github/workflows/build-android.yml@refs/heads/main"| \
  "$repo/.github/workflows/build-appimage.yml@refs/heads/main"| \
  "$repo/.github/workflows/build-snapcraft.yml@refs/heads/main"| \
  "$repo/.github/workflows/release.yml@refs/heads/main") ;;
  *) echo "release gate: workflow must be an exact trusted owner or coordinator" >&2; exit 2 ;;
esac
if { [ "$mode" = "inspect-owner" ] || [ "$mode" = "verify-staged" ] || [ "$mode" = "strict-finalize" ]; } &&
  [ "$workflow_ref" != "$repo/.github/workflows/release.yml@refs/heads/main" ]; then
  echo "release gate: $mode requires the trusted main-branch coordinator" >&2
  exit 2
fi

if [ "$mode" = "verify-staged" ] || [ "$mode" = "strict-finalize" ]; then
  if [ "${GITHUB_EVENT_NAME:-}" != "workflow_dispatch" ] || [ "${GITHUB_REF:-}" != "refs/heads/main" ]; then
    echo "release gate: $mode requires a manual main-branch dispatch" >&2
    exit 2
  fi
fi
if [ "$mode" = "strict-finalize" ]; then
  source_sha="${RELEASE_SOURCE_SHA:-}"
  approved_digest="${RELEASE_CANDIDATE_DIGEST:-}"
  approved_release_id="${RELEASE_DRAFT_ID:-}"
  if [[ ! "$source_sha" =~ ^[0-9a-f]{40}$ || ! "$approved_digest" =~ ^[0-9a-f]{64}$ ||
    ! "$approved_release_id" =~ ^[1-9][0-9]*$ ]]; then
    echo "release gate: publication requires the staged source SHA, candidate digest and release ID" >&2
    exit 2
  fi
  if ! git -C "$workspace" merge-base --is-ancestor "$source_sha" "$driver_sha"; then
    echo "release gate: candidate is not an ancestor of the trusted workflow checkout" >&2
    exit 2
  fi
  candidate_version="$(git -C "$workspace" show "$source_sha:VERSION")"
  if [ "${candidate_version%$'\r'}" != "$version" ]; then
    echo "release gate: candidate VERSION does not match '$version'" >&2
    exit 2
  fi
fi

for command in awk cat cmp comm cosign cp gh grep jq mkdir mktemp mv realpath sha256sum sort wc; do
  command -v "$command" >/dev/null || {
    echo "release gate: required command '$command' is unavailable" >&2
    exit 2
  }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
canonical_workspace="$(realpath -- "$workspace")"
cd "$workspace"

bash "$(dirname -- "${BASH_SOURCE[0]}")/release-manifest.sh" "$version" > "$work/primary-assets.txt"

if [ "$(wc -l < "$work/primary-assets.txt")" -ne 19 ]; then
  echo "release gate: internal primary manifest must contain exactly 19 assets" >&2
  exit 1
fi
if [ "$(awk '{print $1}' "$work/primary-assets.txt" | sort -u | wc -l)" -ne 19 ]; then
  echo "release gate: internal primary manifest contains duplicate asset names" >&2
  exit 1
fi
if [ "$(awk '{print $3}' "$work/primary-assets.txt" | sort -u | wc -l)" -ne 19 ]; then
  echo "release gate: internal primary manifest contains duplicate local paths" >&2
  exit 1
fi
awk '{print $1; print $1 ".sigstore.json"}' "$work/primary-assets.txt" \
  | LC_ALL=C sort > "$work/expected-assets.txt"
awk '$2 == "build-windows.yml" || $2 == "build-windows-legacy.yml"' "$work/primary-assets.txt" > "$work/windows-primary.txt"
awk '$2 != "build-windows.yml" && $2 != "build-windows-legacy.yml"' "$work/primary-assets.txt" > "$work/core-primary.txt"
awk '{print $1; print $1 ".sigstore.json"}' "$work/core-primary.txt" \
  | LC_ALL=C sort > "$work/core-assets.txt"
if [ "$(wc -l < "$work/core-assets.txt")" -ne 30 ] || [ "$(wc -l < "$work/windows-primary.txt")" -ne 4 ]; then
  echo "release gate: invalid phased release manifest" >&2
  exit 1
fi
awk '{print $3; print $3 ".sigstore.json"}' "$work/primary-assets.txt" \
  | LC_ALL=C sort > "$work/allowed-paths.txt"
if [ "$(wc -l < "$work/expected-assets.txt")" -ne 38 ]; then
  echo "release gate: internal public manifest must contain exactly 38 assets" >&2
  exit 1
fi
if [ "$mode" = "inspect-owner" ]; then
  owner_workflow="${OWNER_WORKFLOW:-}"
  case "$owner_workflow" in
    build-linux.yml|build-macos.yml|build-windows.yml|build-windows-legacy.yml|build-android.yml|build-appimage.yml|build-snapcraft.yml) ;;
    *) echo "release gate: invalid canonical owner '$owner_workflow'" >&2; exit 2 ;;
  esac
  awk -v owner="$owner_workflow" '$2 == owner {print}' "$work/primary-assets.txt" > "$work/owner-assets.txt"
  test -s "$work/owner-assets.txt"
fi

declare -A local_paths=()
local_owner=""
if [ "$mode" = "preflight" ] || [ "$mode" = "upload" ]; then
  files="${FILES:?FILES is required during preflight and upload}"
  while IFS= read -r path || [ -n "$path" ]; do
    path="${path%$'\r'}"
    [ -z "$path" ] && continue
    if ! LC_ALL=C grep -Fqx -- "$path" "$work/allowed-paths.txt"; then
      echo "release gate: local path '$path' is not in the public release manifest" >&2
      exit 1
    fi
    if [ ! -f "$path" ] || [ -L "$path" ] || [ ! -s "$path" ]; then
      echo "release gate: local release file '$path' must be a non-empty regular non-symlink file" >&2
      exit 1
    fi
    resolved_path="$(realpath -- "$path")"
    case "$resolved_path" in
      "$canonical_workspace"/*) ;;
      *)
        echo "release gate: local release file '$path' resolves outside the GitHub workspace" >&2
        exit 1
        ;;
    esac
    name="${path##*/}"
    if [[ -n "${local_paths[$name]+present}" ]]; then
      echo "release gate: duplicate local release asset '$name'" >&2
      exit 1
    fi
    primary_path="${path%.sigstore.json}"
    owner="$(
      awk -v path="$primary_path" '$3 == path {print $2}' "$work/primary-assets.txt"
    )"
    if [ -z "$owner" ]; then
      echo "release gate: local path '$path' has no primary artifact owner" >&2
      exit 1
    fi
    expected_workflow_ref="$repo/.github/workflows/$owner@refs/heads/main"
    if [ "$workflow_ref" != "$expected_workflow_ref" ] && [ "$workflow_ref" != "$repo/.github/workflows/release.yml@refs/heads/main" ]; then
      echo "release gate: workflow '$workflow_ref' does not own local path '$path'" >&2
      exit 1
    fi
    if [ -z "$local_owner" ]; then
      local_owner="$owner"
    elif [ "$local_owner" != "$owner" ]; then
      local_owner=mixed
    fi
    local_paths["$name"]="$path"
  done <<< "$files"
  if [ "${#local_paths[@]}" -eq 0 ]; then
    echo "release gate: no local release files were provided" >&2
    exit 1
  fi
  for name in "${!local_paths[@]}"; do
    if [[ "$name" == *.sigstore.json ]]; then
      primary="${name%.sigstore.json}"
      counterpart="$primary"
    else
      counterpart="$name.sigstore.json"
    fi
    if [[ -z "${local_paths[$counterpart]+present}" ]]; then
      echo "release gate: local release pair for '$name' is incomplete" >&2
      exit 1
    fi
  done
fi

if [ "$windows_after_core" = "true" ]; then
  selected_owner="$local_owner"
  if [ "$mode" = "inspect-owner" ]; then selected_owner="$owner_workflow"; fi
  if [[ "$selected_owner" != "build-windows.yml" && "$selected_owner" != "build-windows-legacy.yml" ]] ||
    [ "$workflow_ref" != "$repo/.github/workflows/release.yml@refs/heads/main" ] ||
    [ "${GITHUB_EVENT_NAME:-}" != "workflow_dispatch" ] || [ "${GITHUB_REF:-}" != "refs/heads/main" ]; then
    echo "release gate: deferred Windows publication requires a trusted coordinator Windows lane" >&2
    exit 2
  fi
  approved_core_id="${RELEASE_CORE_ID:-}"
  approved_core_digest="${RELEASE_CORE_DIGEST:-}"
  if [[ ! "$approved_core_id" =~ ^[1-9][0-9]*$ || ! "$approved_core_digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "release gate: deferred Windows publication requires the verified core release ID and digest" >&2
    exit 2
  fi
fi

if [ "$mode" = "upload" ]; then
  body_path="${BODY_PATH:?BODY_PATH is required during upload}"
  expected_body_path="$workspace/release-body.md"
  canonical_body_path="$canonical_workspace/release-body.md"
  if [ "$body_path" != "$expected_body_path" ] \
    || [ ! -f "$body_path" ] \
    || [ -L "$body_path" ] \
    || [ ! -s "$body_path" ] \
    || [ "$(realpath -- "$body_path")" != "$canonical_body_path" ]; then
    echo "release gate: release body must be the non-empty regular file '$expected_body_path'" >&2
    exit 1
  fi
  GITHUB_SHA="$source_sha" bash "$(dirname -- "${BASH_SOURCE[0]}")/../release-body/gen-release-body.sh" \
    "$version" "$workspace/Changelog.md" "$work/expected-release-body.md"
  if ! cmp -s "$body_path" "$work/expected-release-body.md"; then
    echo "release gate: release body does not match the source-bound deterministic release notes" >&2
    exit 1
  fi
fi

generate_expected_body() {
  body_path="$work/expected-release-body.md"
  git -C "$workspace" show "$source_sha:Changelog.md" > "$work/source-changelog.md"
  GITHUB_SHA="$source_sha" bash "$(dirname -- "${BASH_SOURCE[0]}")/../release-body/gen-release-body.sh" \
    "$version" "$work/source-changelog.md" "$body_path"
}
if [ "$mode" = "verify-staged" ] || [ "$mode" = "strict-finalize" ]; then
  generate_expected_body
fi

tag_present=false
validate_tag() {
  local allow_missing="${1:-false}"
  local count object_type object_sha depth
  tag_present=false
  gh api "repos/$repo/git/matching-refs/tags/$version" > "$work/tag-refs.json"
  count="$(
    jq --arg ref "refs/tags/$version" \
      '[.[] | select(.ref == $ref)] | length' \
      "$work/tag-refs.json"
  )"
  if [ "$count" -gt 1 ]; then
    echo "release gate: found $count exact refs for tag $version" >&2
    exit 1
  fi
  if [ "$count" -eq 0 ]; then
    if [ "$allow_missing" = "true" ]; then
      echo "release gate: tag $version does not exist yet"
      return
    fi
    echo "release gate: tag $version does not exist" >&2
    exit 1
  fi
  tag_present=true

  object_type="$(
    jq -r --arg ref "refs/tags/$version" \
      '[.[] | select(.ref == $ref)][0].object.type' \
      "$work/tag-refs.json"
  )"
  object_sha="$(
    jq -r --arg ref "refs/tags/$version" \
      '[.[] | select(.ref == $ref)][0].object.sha' \
      "$work/tag-refs.json"
  )"
  for ((depth = 0; depth < 4; depth++)); do
    if [ "$object_type" = "commit" ]; then
      break
    fi
    if [ "$object_type" != "tag" ] || [[ ! "$object_sha" =~ ^[0-9A-Fa-f]{40}$ ]]; then
      echo "release gate: tag $version has invalid object '$object_type:$object_sha'" >&2
      exit 1
    fi
    gh api "repos/$repo/git/tags/$object_sha" > "$work/annotated-tag.json"
    object_type="$(jq -r '.object.type' "$work/annotated-tag.json")"
    object_sha="$(jq -r '.object.sha' "$work/annotated-tag.json")"
  done
  if [ "$object_type" != "commit" ] || [[ ! "$object_sha" =~ ^[0-9A-Fa-f]{40}$ ]]; then
    echo "release gate: tag $version does not resolve to a commit" >&2
    exit 1
  fi
  if [ "$object_sha" != "$source_sha" ]; then
    echo "release gate: tag $version resolves to $object_sha, expected $source_sha" >&2
    exit 1
  fi
}

ensure_tag() {
  validate_tag true
  if [ "$tag_present" = "true" ]; then
    return
  fi

  jq -n \
    --arg ref "refs/tags/$version" \
    --arg sha "$source_sha" \
    '{ref: $ref, sha: $sha}' \
    > "$work/create-tag.json"
  if gh api --method POST "repos/$repo/git/refs" \
    --input "$work/create-tag.json" > "$work/created-tag.json"; then
    echo "release gate: created tag $version at $source_sha"
  else
    echo "release gate: tag creation raced or failed; validating the resulting ref"
  fi
  validate_tag false
}

load_release() {
  local release_count
  gh api --paginate "repos/$repo/releases?per_page=100" \
    | jq -s 'add // []' > "$work/releases.json" || {
      echo "release gate: cannot list releases; refusing to infer absence" >&2
      exit 1
    }
  release_count="$(
    jq --arg version "$version" \
      '[.[] | select(.tag_name == $version)] | length' \
      "$work/releases.json"
  )"
  if [ "$release_count" -gt 1 ]; then
    echo "release gate: found $release_count releases for tag $version" >&2
    exit 1
  fi
  if [ "$release_count" -eq 0 ]; then
    return 1
  fi
  jq --arg version "$version" \
    '[.[] | select(.tag_name == $version)][0]' \
    "$work/releases.json" > "$work/release.json"

  release_id="$(jq -r '.id' "$work/release.json")"
  release_target="$(jq -r '.target_commitish' "$work/release.json")"
  release_draft="$(jq -r '.draft' "$work/release.json")"
  release_prerelease="$(jq -r '.prerelease' "$work/release.json")"
  if [[ ! "$release_id" =~ ^[1-9][0-9]*$ ]]; then
    echo "release gate: release $version has invalid id '$release_id'" >&2
    exit 1
  fi
  if [ "$release_target" != "$source_sha" ]; then
    echo "release gate: release $version targets $release_target, expected $source_sha" >&2
    exit 1
  fi
  if [ "$release_prerelease" != "false" ]; then
    echo "release gate: release $version has invalid prerelease state '$release_prerelease'" >&2
    exit 1
  fi
  return 0
}

matches_release_draft() {
  jq -se --arg id "${1:-}" --arg version "$version" --arg sha "$source_sha" '
    length == 1 and (.[0] |
      (.id | type == "number" and . > 0 and floor == . and
        ($id == "" or tostring == $id))
      and (.tag_name == $version) and (.target_commitish == $sha)
      and (.draft == true) and (.prerelease == false))
  ' >/dev/null
}

confirm_created_draft() {
  local expected_id="$1" delay protocol status
  for delay in 0 1 2 4 8; do
    if [ "$delay" -gt 0 ]; then sleep "$delay"; fi
    if gh api --include "repos/$repo/releases/$expected_id" > "$work/draft-readback.http" 2>/dev/null; then
      if ! read -r protocol status _ < "$work/draft-readback.http" ||
         [[ "$protocol" != HTTP/* || "$status" != "200" ]] ||
         ! awk 'body {print; next} /^\r?$/ {body=1}' "$work/draft-readback.http" | matches_release_draft "$expected_id"; then
        echo "release gate: unexpected readback for created draft $expected_id" >&2
        return 1
      fi
      # The collection must also see this exact draft and rule out duplicate tags.
      if load_release; then
        if ! matches_release_draft "$expected_id" < "$work/release.json"; then
          echo "release gate: listed draft changed before upload" >&2
          return 1
        fi
        return 0
      fi
    elif ! read -r protocol status _ < "$work/draft-readback.http" ||
         [[ "$protocol" != HTTP/* || "$status" != "404" ]]; then
      echo "release gate: cannot read created draft $expected_id by ID" >&2
      return 1
    fi
  done
  echo "release gate: created draft $expected_id did not become visible before upload" >&2
  return 1
}

load_assets() {
  gh api --paginate "repos/$repo/releases/$release_id/assets?per_page=100" \
    | jq -s 'add // []' > "$work/assets.json"
}

validate_assets() {
  local duplicates invalid
  duplicates="$(
    jq -r 'group_by(.name)[] | select(length > 1) | .[0].name' "$work/assets.json"
  )"
  if [ -n "$duplicates" ]; then
    echo "release gate: duplicate release assets:" >&2
    printf '%s\n' "$duplicates" >&2
    exit 1
  fi

  jq -r '.[].name' "$work/assets.json" | LC_ALL=C sort > "$work/actual-assets.txt"
  LC_ALL=C comm -13 "$work/expected-assets.txt" "$work/actual-assets.txt" > "$work/unexpected-assets.txt"
  if [ -s "$work/unexpected-assets.txt" ]; then
    echo "release gate: unexpected release assets:" >&2
    cat "$work/unexpected-assets.txt" >&2
    exit 1
  fi

  invalid="$(
    jq -r '
      .[]
      | select(
          ((.id | type) != "number")
          or (.id <= 0)
          or ((.id | floor) != .id)
          or ((.name | type) != "string")
          or (.state != "uploaded")
          or ((.size | type) != "number")
          or (.size <= 0)
          or (((.digest // "") | test("^sha256:[0-9a-f]{64}$")) | not)
        )
      | "\(.name) id=\(.id) state=\(.state) size=\(.size) digest=\(.digest)"
    ' "$work/assets.json"
  )"
  if [ -n "$invalid" ]; then
    echo "release gate: release contains invalid, incomplete, empty, or digestless assets:" >&2
    printf '%s\n' "$invalid" >&2
    exit 1
  fi
}

download_dir="$work/downloads"
mkdir -p "$download_dir"

download_asset() {
  local name="$1" row id expected_size expected_digest destination actual_size actual_digest
  row="$(
    jq -r --arg name "$name" \
      '[.[] | select(.name == $name)][0] | [.id, .size, .digest] | @tsv' \
      "$work/assets.json"
  )"
  IFS=$'\t' read -r id expected_size expected_digest <<< "$row"
  if [[ ! "$id" =~ ^[0-9]+$ ]] || [[ ! "$expected_size" =~ ^[0-9]+$ ]]; then
    echo "release gate: cannot download invalid asset record '$name'" >&2
    exit 1
  fi
  destination="$download_dir/$name"
  gh api -H "Accept: application/octet-stream" \
    "repos/$repo/releases/assets/$id" > "$destination"
  actual_size="$(wc -c < "$destination")"
  actual_size="${actual_size//[[:space:]]/}"
  actual_digest="sha256:$(sha256sum "$destination" | awk '{print $1}')"
  if [ "$actual_size" != "$expected_size" ]; then
    echo "release gate: asset '$name' download size $actual_size, expected $expected_size" >&2
    exit 1
  fi
  if [ "$actual_digest" != "$expected_digest" ]; then
    echo "release gate: asset '$name' download digest $actual_digest, expected $expected_digest" >&2
    exit 1
  fi
}

verify_primary() {
  GITHUB_REPOSITORY="$repo" bash "$(dirname -- "${BASH_SOURCE[0]}")/../sign-and-attest/verify-primary.sh" \
    "$download_dir/$1" "$2" "$source_sha"
}

verify_remote_pair() {
  local name="$1" workflow="$2"
  download_asset "$name"
  download_asset "$name.sigstore.json"
  verify_primary "$name" "$workflow"
}

require_assets() {
  LC_ALL=C comm -23 "$1" "$work/actual-assets.txt" > "$work/missing-assets.txt"
  if [ -s "$work/missing-assets.txt" ]; then
    echo "release gate: release $version is still missing required assets:"
    cat "$work/missing-assets.txt"
    exit 1
  fi
}

require_release_body() {
  if ! jq -e --rawfile body "$body_path" '.body == $body' "$work/release.json" >/dev/null; then
    echo "release gate: release notes do not match the verified source" >&2
    exit 1
  fi
}

release_candidate_digest() {
  local profile="$1" manifest_digest body_digest
  manifest_digest=$(sha256sum "$work/primary-assets.txt")
  body_digest=$(sha256sum "$body_path")
  jq -ncS --arg repo "$repo" --arg version "$version" --arg source "$source_sha" \
    --argjson id "$release_id" --arg manifest "${manifest_digest%% *}" --arg notes "${body_digest%% *}" \
    --arg scope "$profile" --rawfile core_names "$work/core-assets.txt" --slurpfile raw "$work/assets.json" '
      ($core_names | split("\n")) as $required |
      ($raw[0] | [
        .[] | select($scope != "core" or (.name as $name | $required | index($name) != null))
        | {id,name,state,size,digest}
      ] | sort_by(.name)) as $assets |
      {schema:1,repository:$repo,version:$version,source_sha:$source,release_id:$id,
        manifest_sha256:$manifest,notes_sha256:$notes,assets:$assets}
      + (if $scope == "core" then {scope:$scope} else {} end)
    ' | sha256sum | awk '{print $1}'
}

verify_present_windows_pairs() {
  local recover_owner="${1:-}" allow_pending_sidecar="${2:-false}" name workflow primary bundle
  while read -r name workflow _; do
    primary=false
    bundle=false
    if LC_ALL=C grep -Fqx -- "$name" "$work/actual-assets.txt"; then primary=true; fi
    if LC_ALL=C grep -Fqx -- "$name.sigstore.json" "$work/actual-assets.txt"; then bundle=true; fi
    if [ "$primary" = "true" ] && [ "$bundle" = "true" ]; then
      verify_remote_pair "$name" "$workflow"
    elif [ "$primary" = "false" ] && [ "$bundle" = "true" ] && [ "$workflow" = "$recover_owner" ]; then
      download_asset "$name.sigstore.json"
      if ! cmp -s "${local_paths[$name.sigstore.json]}" "$download_dir/$name.sigstore.json"; then
        echo "release gate: Windows sidecar for '$name' does not match the original signed generation" >&2
        exit 1
      fi
    elif [ "$primary" = "false" ] && [ "$bundle" = "true" ] && [ "$allow_pending_sidecar" = "true" ]; then
      echo "release gate: Windows attachment for '$name' is pending"
    elif [ "$primary" != "$bundle" ]; then
      echo "release gate: incomplete Windows pair for '$name'" >&2
      exit 1
    fi
  done < "$work/windows-primary.txt"
}

freeze_windows_lane() {
  local name workflow
  mkdir "$work/local"
  for name in "${!local_paths[@]}"; do
    cp -- "${local_paths[$name]}" "$work/local/$name"
    local_paths["$name"]="$work/local/$name"
  done
  while read -r name workflow _; do
    if [ "$workflow" = "$local_owner" ]; then
      bash "$(dirname -- "${BASH_SOURCE[0]}")/../sign-and-attest/verify-primary.sh" \
        "${local_paths[$name]}" "$workflow" "$source_sha"
    fi
  done < "$work/windows-primary.txt"
}

upload_asset() {
  local name="$1" path="${local_paths[$1]}" size digest encoded_name upload_url
  size="$(wc -c < "$path")"
  size="${size//[[:space:]]/}"
  digest="sha256:$(sha256sum "$path" | awk '{print $1}')"
  encoded_name="$(jq -nr --arg name "$name" '$name | @uri')"
  upload_url="https://uploads.github.com/repos/$repo/releases/$release_id/assets?name=$encoded_name"
  gh api --method POST -H "Content-Type: application/octet-stream" \
    "$upload_url" --input "$path" > "$work/uploaded-asset.json"
  if ! jq -e --arg name "$name" --argjson size "$size" --arg digest "$digest" '
    (.id | type == "number" and . > 0 and floor == .)
    and (.name == $name) and (.state == "uploaded")
    and (.size == $size) and (.digest == $digest)
  ' "$work/uploaded-asset.json" >/dev/null; then
    echo "release gate: unexpected upload response for '$name'" >&2
    exit 1
  fi
  jq --slurpfile uploaded "$work/uploaded-asset.json" '. + $uploaded' \
    "$work/assets.json" > "$work/next-assets.json"
  mv "$work/next-assets.json" "$work/assets.json"
}

emit_owner_inspection() {
  local status=$1 digest
  digest="$(sha256sum "$work/primary-assets.txt" | awk '{print $1}')"
  jq -nS --arg repository "$repo" --arg version "$version" --arg source_sha "$source_sha" \
    --arg canonical_manifest_sha256 "$digest" --arg owner_workflow "$owner_workflow" --arg status "$status" \
    --slurpfile verified_pairs "$work/owner-pairs.jsonl" --rawfile missing "$work/owner-missing.txt" \
    '{repository:$repository,version:$version,source_sha:$source_sha,canonical_manifest_sha256:$canonical_manifest_sha256,
      owner_workflow:$owner_workflow,status:$status,verified_pairs:($verified_pairs|sort_by(.name)),
      missing_names:($missing|split("\n")|map(select(length > 0))|sort)}'
}

if [ "$mode" = "inspect-owner" ]; then
  : > "$work/owner-pairs.jsonl"
  awk '{print $1}' "$work/owner-assets.txt" > "$work/owner-missing.txt"
  validate_tag true >&2
else
  validate_tag true
fi
if ! load_release; then
  if [ "$mode" = "inspect-owner" ] &&
    { [ "$windows_after_core" = "false" ] || [ "$tag_present" = "false" ]; }; then
    # Read-only inspection may not see the core draft already verified by
    # the coordinator. Early Windows assets are only uploaded after publication.
    emit_owner_inspection missing
    exit 0
  fi
  if [ "$windows_after_core" = "true" ]; then
    echo "release gate: core release is pending; Windows attachment cannot start" >&2
    exit 1
  fi
  if [ "$mode" = "preflight" ]; then
    echo "release gate: no existing release for $version; a commit-bound draft may be created"
    exit 0
  fi
  if [ "$mode" != "upload" ]; then
    echo "release gate: draft release for $version was not found after asset upload" >&2
    exit 1
  fi
  jq -n --arg version "$version" --arg sha "$source_sha" --rawfile body "$body_path" \
    '{tag_name:$version,target_commitish:$sha,name:$version,body:$body,
      draft:true,prerelease:false,make_latest:"false"}' \
    | gh api --method POST "repos/$repo/releases" --input - > "$work/created-release.json"
  if ! matches_release_draft < "$work/created-release.json"; then
    echo "release gate: unexpected draft creation response" >&2
    exit 1
  fi
  created_release_id="$(jq -r '.id' "$work/created-release.json")"
  confirm_created_draft "$created_release_id"
fi
if [ "$windows_after_core" = "true" ] && [ "$release_id" != "$approved_core_id" ]; then
  echo "release gate: release ID does not match the verified core" >&2
  exit 1
fi
if [ "$windows_after_core" = "true" ] && [ "$mode" != "inspect-owner" ] && [ "$release_draft" != "false" ]; then
  echo "release gate: core release is still a draft; Windows attachment cannot start" >&2
  exit 1
fi
if [ "$mode" = "strict-finalize" ] && [ "$release_id" != "$approved_release_id" ]; then
  echo "release gate: release $release_id does not match the staged receipt ID $approved_release_id" >&2
  exit 1
fi
already_published=false
published_windows=false
if [ "$release_draft" != "true" ]; then
  if [ "$release_draft" = "false" ] &&
    { [ "$mode" = "strict-finalize" ] || { [ "$mode" = "verify-staged" ] && [ "$scope" = "full" ]; }; }; then
    already_published=true
    validate_tag false
  elif [ "$release_draft" = "false" ] && [ "$windows_after_core" = "true" ]; then
    if [ "$mode" != "inspect-owner" ] &&
      [ "${#local_paths[@]}" -ne "$(awk -v owner="$selected_owner" '$2 == owner {count += 2} END {print count}' "$work/windows-primary.txt")" ]; then
      echo "release gate: Windows attachment requires the complete signed owner lane" >&2
      exit 1
    fi
    published_windows=true
    validate_tag false
  else
    echo "release gate: release $version is already published; refusing to mutate or accept it" >&2
    exit 1
  fi
fi

load_assets
validate_assets
if [ "$windows_after_core" = "true" ]; then
  generate_expected_body
  require_release_body
  require_assets "$work/core-assets.txt"
  core_digest=$(release_candidate_digest core)
  if [ "$core_digest" != "$approved_core_digest" ]; then
    echo "release gate: published or staged core differs from the verified digest" >&2
    exit 1
  fi
  if [ "$mode" = "preflight" ]; then
    echo "release gate: published core metadata matches the verified release"
    exit 0
  fi
  if [ "$mode" = "upload" ]; then
    freeze_windows_lane
    while read -r name workflow _; do
      verify_remote_pair "$name" "$workflow"
    done < "$work/core-primary.txt"
    verify_present_windows_pairs "$local_owner"
  fi
fi

if [ "$mode" = "inspect-owner" ]; then
  inspected_release_id="$release_id"
  inspected_release_draft="$release_draft"
  jq -S '[.[] | {id,name,state,size,digest}] | sort_by(.name)' "$work/assets.json" > "$work/inspected-assets.json"
  : > "$work/owner-missing.txt"
  while read -r name workflow _; do
    primary_count="$(jq --arg name "$name" '[.[] | select(.name == $name)] | length' "$work/assets.json")"
    bundle_count="$(jq --arg name "$name.sigstore.json" '[.[] | select(.name == $name)] | length' "$work/assets.json")"
    if [ "$primary_count" -ne "$bundle_count" ]; then
      echo "release gate: incomplete staged pair for '$name'" >&2
      exit 1
    fi
    if [ "$primary_count" -eq 0 ]; then
      printf '%s\n' "$name" >> "$work/owner-missing.txt"
      continue
    fi
    verify_remote_pair "$name" "$workflow" >&2
    primary_digest="sha256:$(sha256sum "$download_dir/$name" | awk '{print $1}')"
    bundle_digest="sha256:$(sha256sum "$download_dir/$name.sigstore.json" | awk '{print $1}')"
    jq -c --arg name "$name" --arg primary_digest "$primary_digest" --arg bundle_digest "$bundle_digest" \
      '{name:$name,primary:{id:([.[]|select(.name == $name)][0].id),digest:$primary_digest},
        bundle:{id:([.[]|select(.name == ($name + ".sigstore.json"))][0].id),digest:$bundle_digest}}' \
      "$work/assets.json" >> "$work/owner-pairs.jsonl"
  done < "$work/owner-assets.txt"
  if ! load_release || [ "$release_id" != "$inspected_release_id" ] || [ "$release_draft" != "$inspected_release_draft" ]; then
    echo "release gate: release changed during owner inspection" >&2
    exit 1
  fi
  if [ "$windows_after_core" = "true" ]; then
    require_release_body >&2
    validate_tag "$inspected_release_draft" >&2
  fi
  load_assets
  validate_assets
  jq -S '[.[] | {id,name,state,size,digest}] | sort_by(.name)' "$work/assets.json" > "$work/current-assets.json"
  if ! cmp -s "$work/inspected-assets.json" "$work/current-assets.json"; then
    echo "release gate: release assets changed during owner inspection" >&2
    exit 1
  fi
  status=partial
  if [ ! -s "$work/owner-pairs.jsonl" ]; then status=missing
  elif [ ! -s "$work/owner-missing.txt" ]; then status=complete
  fi
  emit_owner_inspection "$status"
  exit 0
fi

if [ "$mode" = "preflight" ] || [ "$mode" = "upload" ]; then
  missing_pairs=()
  reused_pairs=()
  declare -A retained_sidecars=()
  while read -r name workflow _; do
    if [[ -z "${local_paths[$name]+present}" ]]; then
      continue
    fi
    primary_count="$(jq --arg name "$name" '[.[] | select(.name == $name)] | length' "$work/assets.json")"
    bundle_count="$(
      jq --arg name "$name.sigstore.json" \
        '[.[] | select(.name == $name)] | length' \
        "$work/assets.json"
    )"
    if [ "$published_windows" = "true" ] && [ "$primary_count" -eq 0 ] && [ "$bundle_count" -eq 1 ]; then
      # The published-lane checks already authenticated and matched this
      # sidecar against the local signed generation.
      retained_sidecars["$name"]=true
    elif [ "$primary_count" -ne "$bundle_count" ]; then
      echo "release gate: incomplete staged pair for '$name'" >&2
      exit 1
    fi
    if [ "$primary_count" -eq 1 ]; then
      if [ "$published_windows" != "true" ]; then
        verify_remote_pair "$name" "$workflow"
      fi
      reused_pairs+=("$name")
      echo "release gate: safely reusing verified staged pair '$name'"
    else
      missing_pairs+=("$name $workflow")
    fi
  done < "$work/primary-assets.txt"
  if [ "${#missing_pairs[@]}" -gt 0 ]; then
    for name in "${reused_pairs[@]}"; do
      if ! cmp -s "${local_paths[$name]}" "$download_dir/$name"; then
        echo "release gate: partially staged lane requires the original signed artifact set; '$name' differs from staged bytes" >&2
        exit 1
      fi
      if [ "$published_windows" = "true" ] &&
        ! cmp -s "${local_paths[$name.sigstore.json]}" "$download_dir/$name.sigstore.json"; then
        echo "release gate: existing Windows sidecar for '$name' differs from the original generation" >&2
        exit 1
      fi
    done
  fi
  if [ "$mode" = "upload" ]; then
    staged_release_id="$release_id"
    staged_release_draft="$release_draft"
    jq -S '[.[] | {id, name, state, size, digest}] | sort_by(.name)' \
      "$work/assets.json" > "$work/verified-assets.json"
    if ! load_release || [ "$release_id" != "$staged_release_id" ] || [ "$release_draft" != "$staged_release_draft" ]; then
      echo "release gate: release $version changed or was published during staging" >&2
      exit 1
    fi
    if [ "$published_windows" = "true" ]; then
      require_release_body
      validate_tag false
    fi
    load_assets
    validate_assets
    jq -S '[.[] | {id, name, state, size, digest}] | sort_by(.name)' \
      "$work/assets.json" > "$work/current-assets.json"
    if ! cmp -s "$work/verified-assets.json" "$work/current-assets.json"; then
      echo "release gate: release assets changed during staging" >&2
      exit 1
    fi
    for pair in "${missing_pairs[@]}"; do
      read -r name workflow <<< "$pair"
      if [ "$published_windows" = "true" ]; then
        if [[ -z "${retained_sidecars[$name]+present}" ]]; then
          upload_asset "$name.sigstore.json"
          download_asset "$name.sigstore.json"
        fi
        upload_asset "$name"
      else
        upload_asset "$name"
        upload_asset "$name.sigstore.json"
      fi
      verify_remote_pair "$name" "$workflow"
    done
    jq -S '[.[] | {id, name, state, size, digest}] | sort_by(.name)' \
      "$work/assets.json" > "$work/verified-assets.json"
    if ! load_release || [ "$release_id" != "$staged_release_id" ] || [ "$release_draft" != "$staged_release_draft" ]; then
      echo "release gate: release $version changed or was published during staging" >&2
      exit 1
    fi
    if [ "$published_windows" = "true" ]; then
      require_release_body
      validate_tag false
    fi
    load_assets
    validate_assets
    jq -S '[.[] | {id, name, state, size, digest}] | sort_by(.name)' \
      "$work/assets.json" > "$work/current-assets.json"
    if ! cmp -s "$work/verified-assets.json" "$work/current-assets.json"; then
      echo "release gate: release assets changed during staging" >&2
      exit 1
    fi
    set_gate_output staged true
    if [ "$published_windows" = "true" ]; then
      echo "release gate: appended or retained verified Windows lane pairs in published $version"
    else
      echo "release gate: staged verified lane pairs in draft $version"
    fi
    exit 0
  fi
  echo "release gate: existing release $version is safe for this workflow lane"
  exit 0
fi

required_primary="$work/primary-assets.txt"
required_assets="$work/expected-assets.txt"
if [ "$scope" = "core" ]; then
  required_primary="$work/core-primary.txt"
  required_assets="$work/core-assets.txt"
fi
require_assets "$required_assets"

require_verified_release() {
  local expected_draft="$1"
  if ! load_release || [ "$release_id" != "$verified_release_id" ] || [ "$release_draft" != "$expected_draft" ]; then
    echo "release gate: release $version changed or was published during verification" >&2
    exit 1
  fi
  require_release_body
  load_assets
  validate_assets
  jq -cS '[.[] | {id,name,state,size,digest}] | sort_by(.name)' \
    "$work/assets.json" > "$work/current-assets.json"
  if ! cmp -s "$work/verified-assets.json" "$work/current-assets.json"; then
    echo "release gate: release assets changed during verification" >&2
    exit 1
  fi
}

require_release_body
verified_release_id="$release_id"
jq -cS '[.[] | {id,name,state,size,digest}] | sort_by(.name)' \
  "$work/assets.json" > "$work/verified-assets.json"
candidate_digest=$(release_candidate_digest "$scope")
if [ "$mode" = "strict-finalize" ] && [ "$candidate_digest" != "$approved_digest" ]; then
  echo "release gate: remote candidate does not match the approved staged digest" >&2
  exit 1
fi

while read -r name _ _; do
  download_asset "$name"
  download_asset "$name.sigstore.json"
done < "$required_primary"
while read -r name workflow _; do
  verify_primary "$name" "$workflow"
done < "$required_primary"
if [ "$scope" = "core" ]; then
  verify_present_windows_pairs "" "$already_published"
fi

if [ "$already_published" = "true" ]; then
  require_verified_release false
  validate_tag false
  if [ "$mode" = "strict-finalize" ]; then
    set_gate_output published true
    echo "release gate: verified already-published $scope release $version"
    exit 0
  fi
else
  require_verified_release true
fi

if [ "$mode" = "verify-staged" ]; then
  validate_tag true
  set_gate_output candidate-digest "$candidate_digest"
  set_gate_output release-id "$release_id"
  echo "release gate: verified $scope $version candidate $candidate_digest"
  exit 0
fi

gh api "repos/$repo/compare/$source_sha...main" > "$work/compare.json"
compare_status="$(jq -r '.status' "$work/compare.json")"
case "$compare_status" in
  identical|ahead) ;;
  *)
    echo "release gate: source commit $source_sha is not an ancestor of main (status: $compare_status)" >&2
    exit 1
    ;;
esac
gh api -H "Accept: application/vnd.github.raw+json" \
  "repos/$repo/contents/VERSION?ref=main" > "$work/main-version"
main_version="$(<"$work/main-version")"
main_version="${main_version%$'\r'}"
if [ "$main_version" != "$version" ]; then
  echo "release gate: main currently declares version $main_version, refusing to publish $version as latest" >&2
  exit 1
fi

ensure_tag
require_verified_release true
jq -n --rawfile body "$body_path" \
  '{draft: false, make_latest: "true", body: $body}' \
  > "$work/publish.json"
gh api --method PATCH "repos/$repo/releases/$release_id" \
  --input "$work/publish.json" \
  > "$work/published-release.json"
published_id="$(jq -r '.id' "$work/published-release.json")"
published_tag="$(jq -r '.tag_name' "$work/published-release.json")"
published_target="$(jq -r '.target_commitish' "$work/published-release.json")"
published_draft="$(jq -r '.draft' "$work/published-release.json")"
published_prerelease="$(jq -r '.prerelease' "$work/published-release.json")"
if [ "$published_id" != "$release_id" ] \
  || [ "$published_tag" != "$version" ] \
  || [ "$published_target" != "$source_sha" ] \
  || [ "$published_draft" != "false" ] \
  || [ "$published_prerelease" != "false" ]; then
  echo "release gate: GitHub returned an unexpected state after publication" >&2
  exit 1
fi
if ! jq -e --rawfile body "$body_path" '.body == $body' "$work/published-release.json" >/dev/null; then
  echo "release gate: published response body does not match the validated source body" >&2
  exit 1
fi
require_verified_release false
validate_tag false
set_gate_output published true
echo "release gate: published $scope release $version with $(wc -l < "$work/actual-assets.txt") verified assets"
