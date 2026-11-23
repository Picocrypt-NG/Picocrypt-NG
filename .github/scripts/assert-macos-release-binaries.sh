#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
test "$#" -gt 0
scripts=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
for binary; do
    test "$(/usr/bin/lipo -archs "$binary")" = arm64
    bash "$scripts/assert-macos-minos.sh" "$binary" 15.0
    /usr/bin/otool -L "$binary" | awk '
        NR > 1 {
            if ($1 !~ "^(/System/Library/|/usr/lib/)") {
                print "Unexpected load dependency: " $1 > "/dev/stderr"
                exit 1
            }
            linked++
        }
        END { if (!linked) exit 1 }
    '
done
