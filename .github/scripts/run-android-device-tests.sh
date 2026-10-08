#!/usr/bin/env bash
set -euo pipefail

api="$1"
shift
case "$api" in 26|36) ;; *) echo "Unsupported device test API: $api" >&2; exit 1 ;; esac
if (( $# == 0 )); then
  echo "At least one device test selector is required" >&2
  exit 1
fi
actual_api=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
if [[ "$actual_api" != "$api" ]]; then
  echo "Device API $actual_api does not match required API $api" >&2
  exit 1
fi

for selector in "$@"; do
  if [[ "$selector" == *,* ]]; then
    echo "Pass each device test selector as a separate argument" >&2
    exit 1
  fi
  destination="app/build/ci-device-tests/api-$api/$selector"
  mkdir -p "$(dirname "$destination")"
  mkdir "$destination"
  # AGP 9.4's test engine serializes runner arguments with commas, so a
  # comma-separated class value silently loses every class after the first.
  status=0
  ./gradlew connectedDebugAndroidTest "-Pandroid.testInstrumentationRunnerArguments.class=$selector" || status=$?

  for path in outputs/androidTest-results/connected reports/androidTests/connected; do
    if [[ -d "app/build/$path" ]]; then
      cp -R "app/build/$path" "$destination/$(basename "$(dirname "$path")")"
    fi
  done
  if (( status != 0 )); then
    exit "$status"
  fi

  python3 - "$selector" "$destination" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

selector, destination = sys.argv[1:]
classname, separator, method = selector.partition("#")
source = Path("app/src/androidTest/java") / (classname.replace(".", "/") + ".kt")
text = source.read_text()
declared = set(re.findall(r"@Test\s+fun\s+([A-Za-z_]\w*)\s*\(", text))
if not declared or len(declared) != len(re.findall(r"@Test\b", text)):
    raise SystemExit(f"Cannot account for all @Test methods in {source}")
expected = {method} if separator else declared
if not expected <= declared:
    raise SystemExit(f"Selected method is absent from {source}: {method}")
cases = [case for path in Path(destination).rglob("TEST-*.xml")
         for case in ET.parse(path).iter("testcase")]
executed = set()
for case in cases:
    name = case.get("name")
    if case.get("classname") != classname or name not in expected:
        raise SystemExit(f"Unexpected device test: {case.attrib}")
    if any(case.find(result) is not None for result in ("failure", "error", "skipped")):
        raise SystemExit(f"Device test did not pass: {classname}#{name}")
    executed.add(name)
missing = expected - executed
if missing:
    raise SystemExit(f"Device tests did not execute: {classname}: {sorted(missing)}")
print(f"Verified actual device results for {selector}: {', '.join(sorted(executed))}")
PY
done
