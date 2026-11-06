#!/usr/bin/env bash
set -euo pipefail

test "$SOURCE_SHA" = "$GITHUB_SHA"
test "$(git rev-parse HEAD)" = "$SOURCE_SHA"
test "$(cat VERSION)" = "$SOURCE_VERSION"
canonical=$(bash .github/actions/stage-release/release-manifest.sh "$SOURCE_VERSION")
actual=$(printf '%s\n' "$canonical" | sha256sum)
test "${actual%% *}" = "$CANONICAL_MANIFEST_SHA256"
[[ $AMD64_ARTIFACT_ID =~ ^[1-9][0-9]*$ && $ARM64_ARTIFACT_ID =~ ^[1-9][0-9]*$ ]]
test "$AMD64_ARTIFACT_ID" != "$ARM64_ARTIFACT_ID"

verify_metadata() {
    local arch=$1 id=$2 digest=$3 attempt=$4 metadata
    [[ $digest =~ ^[0-9a-f]{64}$ && $attempt =~ ^[1-9][0-9]*$ ]] || return 1
    (( attempt <= GITHUB_RUN_ATTEMPT )) || return 1
    metadata=$(gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$id") || return 1
    jq -e --arg id "$id" --arg digest "sha256:$digest" \
        --arg name "build-linux-$arch-attempt-$attempt" --arg run "$GITHUB_RUN_ID" --arg sha "$SOURCE_SHA" \
        '(.id|tostring) == $id and .name == $name and .digest == $digest and .expired == false
          and (.workflow_run.id|tostring) == $run and .workflow_run.head_sha == $sha' <<< "$metadata" >/dev/null || return 1
    jq -cn --arg arch "$arch" --arg id "$id" --arg zip_sha256 "$digest" --arg attempt "$attempt" \
        '{arch:$arch,id:$id,zip_sha256:$zip_sha256,run_attempt:$attempt}'
}

verify_payload() {
    local arch=$1 attempt=$2 directory expected actual_names manifest
    directory="$ARTIFACT_ROOT/build-linux-$arch"
    test -d "$directory" && test ! -L "$directory" || return 1
    manifest="$directory/payload-manifest.json"
    test -f "$manifest" && test ! -L "$manifest" && test -s "$manifest" || return 1
    expected=$(awk -v prefix="artifacts/build-linux-$arch/" '$2 == "build-linux.yml" && index($3,prefix) == 1 {print $1}' <<< "$canonical" | LC_ALL=C sort)
    test -n "$expected"
    jq -e --arg repository "$GITHUB_REPOSITORY" --arg source "$SOURCE_SHA" --arg version "$SOURCE_VERSION" \
        --arg canonical "$CANONICAL_MANIFEST_SHA256" --arg arch "$arch" --arg run "$GITHUB_RUN_ID" --arg attempt "$attempt" \
        --arg names "$expected" \
        '.schema_version == 1 and .repository == $repository and .source_sha == $source and .version == $version
          and .canonical_manifest_sha256 == $canonical and .owner_workflow == "build-linux.yml"
          and .arch == $arch and .run_id == $run and .run_attempt == $attempt
          and ([.files[].name]|sort) == ($names|split("\n"))
          and all(.files[]; .sha256|test("^[0-9a-f]{64}$"))' "$manifest" >/dev/null
    actual_names=$(find "$directory" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
    test "$actual_names" = "$(printf '%s\npayload-manifest.json\n' "$expected" | LC_ALL=C sort)"
    while IFS= read -r name; do
        test -f "$directory/$name" && test ! -L "$directory/$name" && test -s "$directory/$name" || return 1
    done <<< "$expected"
    (cd "$directory"; jq -r '.files[] | "\(.sha256)  \(.name)"' payload-manifest.json | sha256sum --check --strict)
}

case "${1:-}" in
    metadata)
        amd64=$(verify_metadata amd64 "$AMD64_ARTIFACT_ID" "$AMD64_ARTIFACT_DIGEST" "$AMD64_RUN_ATTEMPT")
        arm64=$(verify_metadata arm64 "$ARM64_ARTIFACT_ID" "$ARM64_ARTIFACT_DIGEST" "$ARM64_RUN_ATTEMPT")
        jq -nS --arg source_sha "$SOURCE_SHA" --arg version "$SOURCE_VERSION" \
            --arg canonical_manifest_sha256 "$CANONICAL_MANIFEST_SHA256" --arg repository "$GITHUB_REPOSITORY" \
            --arg run_id "$GITHUB_RUN_ID" --argjson artifacts "$(printf '%s\n%s\n' "$amd64" "$arm64" | jq -sc .)" \
            '{schema_version:1,repository:$repository,source_sha:$source_sha,version:$version,
              canonical_manifest_sha256:$canonical_manifest_sha256,run_id:$run_id,artifacts:$artifacts}' > "$LINUX_MANIFEST"
        ;;
    payload)
        verify_payload amd64 "$AMD64_RUN_ATTEMPT"
        verify_payload arm64 "$ARM64_RUN_ATTEMPT"
        ;;
    *) echo 'usage: verify-artifacts.sh metadata|payload' >&2; exit 2 ;;
esac
