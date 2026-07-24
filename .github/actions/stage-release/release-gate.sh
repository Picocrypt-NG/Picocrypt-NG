#!/usr/bin/env bash

set -euo pipefail

mode="${1:?usage: release-gate.sh <preflight|publish> <version>}"
version="${2:?usage: release-gate.sh <preflight|publish> <version>}"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
source_sha="${GITHUB_SHA:?GITHUB_SHA is required}"
workspace="${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"

case "$mode" in
  preflight|publish) ;;
  *)
    echo "release gate: unsupported mode '$mode'" >&2
    exit 2
    ;;
esac
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo "release gate: invalid version '$version'" >&2
  exit 2
fi
if [[ ! "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "release gate: invalid repository '$repo'" >&2
  exit 2
fi
if [[ ! "$source_sha" =~ ^[0-9A-Fa-f]{40}$ ]]; then
  echo "release gate: invalid source commit '$source_sha'" >&2
  exit 2
fi
if [[ "$workspace" != /* ]] || [ ! -d "$workspace" ]; then
  echo "release gate: invalid GitHub workspace '$workspace'" >&2
  exit 2
fi

for command in awk cat cmp comm cosign gh grep jq mkdir mktemp realpath sha256sum sort wc; do
  command -v "$command" >/dev/null || {
    echo "release gate: required command '$command' is unavailable" >&2
    exit 2
  }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
canonical_workspace="$(realpath -- "$workspace")"
cd "$workspace"

cat > "$work/primary-assets.txt" <<EOF
Picocrypt-NG build-linux.yml artifacts/build-linux-amd64/Picocrypt-NG
Picocrypt-NG-cli build-linux.yml artifacts/build-linux-amd64/Picocrypt-NG-cli
Picocrypt-NG.deb build-linux.yml artifacts/build-linux-amd64/Picocrypt-NG.deb
Picocrypt-NG-arm64 build-linux.yml artifacts/build-linux-arm64/Picocrypt-NG-arm64
Picocrypt-NG-cli-arm64 build-linux.yml artifacts/build-linux-arm64/Picocrypt-NG-cli-arm64
Picocrypt-NG.dmg build-macos.yml artifacts/build-macos/Picocrypt-NG.dmg
Picocrypt-NG-cli-macos build-macos.yml artifacts/build-macos/Picocrypt-NG-cli-macos
Picocrypt-NG-portable.exe build-windows.yml artifacts/build-windows/Picocrypt-NG-portable.exe
Picocrypt-NG-cli.exe build-windows.yml artifacts/build-windows/Picocrypt-NG-cli.exe
Picocrypt-NG-Setup.exe build-windows.yml artifacts/build-windows/Picocrypt-NG-Setup.exe
Picocrypt-NG-cli-Legacy.exe build-windows-legacy.yml artifacts/build-windows-legacy/Picocrypt-NG-cli-Legacy.exe
Picocrypt-NG-android-arm64-v8a.apk build-android.yml out/Picocrypt-NG-android-arm64-v8a.apk
Picocrypt-NG-android-x86_64.apk build-android.yml out/Picocrypt-NG-android-x86_64.apk
Picocrypt-NG-android-universal.apk build-android.yml out/Picocrypt-NG-android-universal.apk
Picocrypt-NG-${version}-x86_64.AppImage build-appimage.yml artifacts/Picocrypt-NG-${version}-x86_64.AppImage
Picocrypt-NG-${version}-x86_64.AppImage.zsync build-appimage.yml artifacts/Picocrypt-NG-${version}-x86_64.AppImage.zsync
picocrypt-ng_${version}_amd64.snap build-snapcraft.yml out/picocrypt-ng_${version}_amd64.snap
EOF

if [ "$(wc -l < "$work/primary-assets.txt")" -ne 17 ]; then
  echo "release gate: internal primary manifest must contain exactly 17 assets" >&2
  exit 1
fi
if [ "$(awk '{print $1}' "$work/primary-assets.txt" | sort -u | wc -l)" -ne 17 ]; then
  echo "release gate: internal primary manifest contains duplicate asset names" >&2
  exit 1
fi
if [ "$(awk '{print $3}' "$work/primary-assets.txt" | sort -u | wc -l)" -ne 17 ]; then
  echo "release gate: internal primary manifest contains duplicate local paths" >&2
  exit 1
fi
awk '{print $1; print $1 ".sigstore.json"}' "$work/primary-assets.txt" \
  | LC_ALL=C sort > "$work/expected-assets.txt"
awk '{print $3; print $3 ".sigstore.json"}' "$work/primary-assets.txt" \
  | LC_ALL=C sort > "$work/allowed-paths.txt"
if [ "$(wc -l < "$work/expected-assets.txt")" -ne 34 ]; then
  echo "release gate: internal public manifest must contain exactly 34 assets" >&2
  exit 1
fi

declare -A local_paths=()
if [ "$mode" = "preflight" ]; then
  files="${FILES:?FILES is required during preflight}"
  workflow_ref="${GITHUB_WORKFLOW_REF:?GITHUB_WORKFLOW_REF is required during preflight}"
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
    if [ "$workflow_ref" != "$expected_workflow_ref" ]; then
      echo "release gate: workflow '$workflow_ref' does not own local path '$path'" >&2
      exit 1
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
  for depth in 1 2 3 4; do
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
    | jq -s 'add // []' > "$work/releases.json"
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
  if [[ ! "$release_id" =~ ^[0-9]+$ ]]; then
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

load_assets() {
  gh api --paginate "repos/$repo/releases/$release_id/assets?per_page=100" \
    | jq -s 'add // []' > "$work/assets.json"
}

validate_assets() {
  local duplicates invalid unexpected
  duplicates="$(
    jq -r 'group_by(.name)[] | select(length > 1) | .[0].name' "$work/assets.json"
  )"
  if [ -n "$duplicates" ]; then
    echo "release gate: duplicate release assets:" >&2
    printf '%s\n' "$duplicates" >&2
    exit 1
  fi

  jq -r '.[].name' "$work/assets.json" | LC_ALL=C sort > "$work/actual-assets.txt"
  comm -13 "$work/expected-assets.txt" "$work/actual-assets.txt" > "$work/unexpected-assets.txt"
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
  local name="$1" workflow="$2"
  local artifact="$download_dir/$name"
  local bundle="$download_dir/$name.sigstore.json"
  local identity="https://github.com/$repo/.github/workflows/$workflow@refs/heads/main"
  cosign verify-blob "$artifact" \
    --bundle "$bundle" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --certificate-github-workflow-sha "$source_sha" \
    --certificate-github-workflow-ref "refs/heads/main" \
    --certificate-github-workflow-repository "$repo"
  gh attestation verify "$artifact" \
    --repo "$repo" \
    --cert-identity "$identity" \
    --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
    --signer-digest "$source_sha" \
    --source-ref "refs/heads/main" \
    --source-digest "$source_sha" \
    --predicate-type "https://slsa.dev/provenance/v1" \
    --deny-self-hosted-runners
}

verify_remote_pair() {
  local name="$1" workflow="$2"
  download_asset "$name"
  download_asset "$name.sigstore.json"
  verify_primary "$name" "$workflow"
}

validate_tag true
if ! load_release; then
  if [ "$mode" = "preflight" ]; then
    echo "release gate: no existing release for $version; a commit-bound draft may be created"
    exit 0
  fi
  echo "release gate: draft release for $version was not found after asset upload" >&2
  exit 1
fi
if [ "$release_draft" != "true" ]; then
  echo "release gate: release $version is already published; refusing to mutate or accept it" >&2
  exit 1
fi

load_assets
validate_assets

if [ "$mode" = "preflight" ]; then
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
    if [ "$primary_count" -ne "$bundle_count" ]; then
      echo "release gate: incomplete staged pair for '$name'" >&2
      exit 1
    fi
    if [ "$primary_count" -eq 1 ]; then
      verify_remote_pair "$name" "$workflow"
      echo "release gate: safely reusing verified staged pair '$name'"
    fi
  done < "$work/primary-assets.txt"
  echo "release gate: existing draft $version is safe for this workflow lane"
  exit 0
fi

comm -23 "$work/expected-assets.txt" "$work/actual-assets.txt" > "$work/missing-assets.txt"
if [ -s "$work/missing-assets.txt" ]; then
  echo "release gate: draft $version is still missing required assets:"
  cat "$work/missing-assets.txt"
  exit 0
fi

jq -S '[.[] | {id, name, state, size, digest}] | sort_by(.name)' \
  "$work/assets.json" > "$work/verified-assets.json"
while read -r name _ _; do
  download_asset "$name"
  download_asset "$name.sigstore.json"
done < "$work/primary-assets.txt"
while read -r name workflow _; do
  verify_primary "$name" "$workflow"
done < "$work/primary-assets.txt"

body_path="${BODY_PATH:?BODY_PATH is required during publication}"
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

ensure_tag
verified_release_id="$release_id"
load_release || {
  echo "release gate: release $version disappeared during verification" >&2
  exit 1
}
if [ "$release_id" != "$verified_release_id" ] || [ "$release_draft" != "true" ]; then
  echo "release gate: release $version changed or was published during verification" >&2
  exit 1
fi
load_assets
validate_assets
comm -23 "$work/expected-assets.txt" "$work/actual-assets.txt" > "$work/missing-assets.txt"
if [ -s "$work/missing-assets.txt" ]; then
  echo "release gate: release assets disappeared during verification" >&2
  exit 1
fi
jq -S '[.[] | {id, name, state, size, digest}] | sort_by(.name)' \
  "$work/assets.json" > "$work/current-assets.json"
if ! cmp -s "$work/verified-assets.json" "$work/current-assets.json"; then
  echo "release gate: release assets changed during verification" >&2
  exit 1
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
validate_tag false
echo "release gate: published complete release $version with 34 verified assets"
