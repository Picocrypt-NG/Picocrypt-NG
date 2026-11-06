#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
    metadata|payload) ;;
    *) echo 'usage: verify-artifacts.sh metadata|payload' >&2; exit 2 ;;
esac

test "$SOURCE_SHA" = "$GITHUB_SHA"
test "$(git rev-parse HEAD)" = "$SOURCE_SHA"
version=$(cat VERSION)
test "${version%$'\r'}" = "$SOURCE_VERSION"
canonical=$(bash .github/actions/stage-release/release-manifest.sh "$SOURCE_VERSION")
actual=$(printf '%s\n' "$canonical" | sha256sum)
test "${actual%% *}" = "$CANONICAL_MANIFEST_SHA256"
[[ $GITHUB_RUN_ID =~ ^[1-9][0-9]*$ && $GITHUB_RUN_ATTEMPT =~ ^[1-9][0-9]*$ ]]
: "${PLATFORM_MANIFEST:?Set PLATFORM_MANIFEST to the final platform-artifacts.json path}"

arches='{"build-appimage.yml":"amd64","build-snapcraft.yml":"amd64","build-macos.yml":"arm64",
    "build-android.yml":"all","build-windows.yml":"amd64","build-windows-legacy.yml":"amd64"}'
if [[ -n ${PLATFORM_OWNER:-} ]]; then
    arches=$(jq -ce --arg owner "$PLATFORM_OWNER" \
        'if has($owner) then {($owner):.[$owner]} else error("unknown platform owner") end' <<< "$arches")
fi
jq -e --argjson current_attempt "$GITHUB_RUN_ATTEMPT" --argjson arches "$arches" '
    type == "array" and length == ($arches|length)
      and all(.[]; type == "object" and keys == ["arch","attempt","digest","id","owner"]
        and (.owner|type == "string") and (.arch|type == "string")
        and (.id|type == "number" and . > 0 and floor == .)
        and (.attempt|type == "number" and . > 0 and floor == .)
        and (.digest|type == "string" and test("^[0-9a-f]{64}$")))
      and ([.[].owner]|sort) == ($arches|keys)
      and ([.[].id]|unique|length) == ($arches|length)
      and all(.[]; .arch == $arches[.owner] and .attempt <= $current_attempt)
    ' <<< "$PLATFORM_ARTIFACTS_JSON" >/dev/null
descriptors=$(jq -c 'sort_by(.owner)' <<< "$PLATFORM_ARTIFACTS_JSON")
rows=$(jq -r '.[] | [.owner,.arch,.id,.digest,.attempt] | @tsv' <<< "$descriptors")

verify_metadata() {
    local owner=$1 id=$2 digest=$3 attempt=$4 name metadata
    case "$owner" in
        build-appimage.yml) name="validate-appimage-amd64-attempt-$attempt" ;;
        build-snapcraft.yml) name="build-snapcraft-attempt-$attempt" ;;
        build-macos.yml) name="build-macos-attempt-$attempt" ;;
        build-android.yml) name="validate-android-all-attempt-$attempt" ;;
        build-windows.yml) name="validate-windows-current-amd64-attempt-$attempt" ;;
        build-windows-legacy.yml) name="validate-windows-legacy-amd64-attempt-$attempt" ;;
        *) return 1 ;;
    esac
    metadata=$(gh api --method GET "repos/$GITHUB_REPOSITORY/actions/artifacts/$id") || return 1
    jq -e --argjson id "$id" --arg digest "sha256:$digest" --arg name "$name" \
        --argjson run "$GITHUB_RUN_ID" --arg sha "$SOURCE_SHA" \
        '.id == $id and .name == $name and .digest == $digest and .expired == false
          and .workflow_run.id == $run and .workflow_run.head_sha == $sha' <<< "$metadata" >/dev/null
}

verify_payload() {
    local owner=$1 arch=$2 attempt=$3 directory expected actual_names manifest
    directory="$ARTIFACT_ROOT/${owner%.yml}"
    test -d "$directory" && test ! -L "$directory" || return 1
    manifest="$directory/payload-manifest.json"
    test -f "$manifest" && test ! -L "$manifest" && test -s "$manifest" || return 1
    expected=$(awk -v owner="$owner" '$2 == owner {print $1}' <<< "$canonical" | LC_ALL=C sort) || return 1
    test -n "$expected" || return 1
    jq -e --arg repository "$GITHUB_REPOSITORY" --arg source "$SOURCE_SHA" --arg version "$SOURCE_VERSION" \
        --arg canonical "$CANONICAL_MANIFEST_SHA256" --arg owner "$owner" --arg arch "$arch" \
        --arg run "$GITHUB_RUN_ID" --arg attempt "$attempt" --arg names "$expected" '
        type == "object" and keys == ["arch","canonical_manifest_sha256","files","owner_workflow","repository",
          "run_attempt","run_id","schema_version","source_sha","version"]
          and .schema_version == 1 and .repository == $repository and .source_sha == $source and .version == $version
          and .canonical_manifest_sha256 == $canonical and .owner_workflow == $owner
          and .arch == $arch and .run_id == $run and .run_attempt == $attempt
          and (.files|type == "array") and ([.files[].name]|sort) == ($names|split("\n"))
          and all(.files[]; type == "object" and keys == ["name","sha256"]
            and (.name|type == "string") and (.sha256|type == "string" and test("^[0-9a-f]{64}$")))
        ' "$manifest" >/dev/null || return 1
    actual_names=$(find "$directory" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort) || return 1
    test "$actual_names" = "$(printf '%s\npayload-manifest.json\n' "$expected" | LC_ALL=C sort)" || return 1
    while IFS= read -r name; do
        test -f "$directory/$name" && test ! -L "$directory/$name" && test -s "$directory/$name" || return 1
    done <<< "$expected"
    (cd "$directory"; jq -r '.files[] | "\(.sha256)  \(.name)"' payload-manifest.json | sha256sum --check --strict --status) || return 1
    jq -c --arg owner "$owner" --arg prefix "artifacts/${owner%.yml}/" \
        '.files[] | {name,sha256,owner:$owner,path:($prefix + .name)}' "$manifest"
}

case "$1" in
    metadata)
        while IFS=$'\t' read -r owner _arch id digest attempt; do
            verify_metadata "$owner" "$id" "$digest" "$attempt"
        done <<< "$rows"
        ;;
    payload)
        files=$(while IFS=$'\t' read -r owner arch _id _digest attempt; do
            verify_payload "$owner" "$arch" "$attempt" || exit 1
        done <<< "$rows" | jq -sc 'sort_by(.name)')
        expected_count=$(awk -v owner="${PLATFORM_OWNER:-}" '$2 != "build-linux.yml" && (owner == "" || $2 == owner) {count++} END {print count+0}' <<< "$canonical")
        jq -e --argjson count "$expected_count" 'length == $count and ([.[].name]|unique|length) == $count' <<< "$files" >/dev/null
        artifacts=$(jq -c 'map({owner,arch,id,zip_sha256:.digest,run_attempt:.attempt})' <<< "$descriptors")
        temporary=$(mktemp "$PLATFORM_MANIFEST.XXXXXX")
        trap 'rm -f -- "$temporary"' EXIT
        jq -nS --arg source_sha "$SOURCE_SHA" --arg version "$SOURCE_VERSION" \
            --arg canonical_manifest_sha256 "$CANONICAL_MANIFEST_SHA256" --arg repository "$GITHUB_REPOSITORY" \
            --arg run_id "$GITHUB_RUN_ID" --argjson artifacts "$artifacts" --argjson files "$files" \
            '{schema_version:1,repository:$repository,source_sha:$source_sha,version:$version,
              canonical_manifest_sha256:$canonical_manifest_sha256,run_id:$run_id,artifacts:$artifacts,files:$files}' > "$temporary"
        mv -- "$temporary" "$PLATFORM_MANIFEST"
        ;;
esac
