#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

[[ $# == 1 && -d $1 ]] || { echo 'Usage: install-appimage-build-tools.sh EMPTY_DIRECTORY' >&2; exit 1; }
destination=$(realpath -e -- "$1")
[[ -z $(find "$destination" -mindepth 1 -maxdepth 1 -print -quit) ]] || { echo 'Tool directory must be empty' >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
manifest="$script_dir/../toolchains/appimage-build.json"
jq -e '
  .schema_version == 1 and
  ([.tools[].name] == ["linuxdeploy", "appimagetool", "runtime"]) and
  all(.tools[];
    (.source_commit | test("^[0-9a-f]{40}$")) and
    (.sha256 | test("^[0-9a-f]{64}$")) and
    (.asset_id | type == "number") and
    (.version | test("^[0-9][0-9A-Za-z.-]*$")) and
    (.url | test("^https://github.com/(linuxdeploy/linuxdeploy|AppImage/appimagetool|AppImage/type2-runtime)/releases/download/[0-9][0-9A-Za-z.-]*/[A-Za-z0-9_.-]+$")))
' "$manifest" >/dev/null
while IFS=$'\t' read -r name url expected; do
  curl --fail --location --proto '=https' --proto-redir '=https' --silent --show-error \
    --connect-timeout 20 --max-time 180 --retry 2 --retry-max-time 180 \
    --output "$destination/$name" "$url"
  actual=$(sha256sum < "$destination/$name")
  [[ ${actual%% *} == "$expected" ]] || { echo "Checksum mismatch: $name" >&2; exit 1; }
done < <(jq -r '.tools[] | [.name, .url, .sha256] | @tsv' "$manifest")
# All bytes are checked before any downloaded producer can execute.
chmod +x "$destination/linuxdeploy" "$destination/appimagetool"
