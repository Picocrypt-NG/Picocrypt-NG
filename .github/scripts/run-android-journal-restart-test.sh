#!/usr/bin/env bash
# Run after the ordinary Gradle suites on an owned emulator; hold is intentionally killed.
set -euo pipefail
umask 077
if [[ "${PICOCRYPT_JOURNAL_RESTART_BOUNDED:-}" != 1 ]]; then
  exec timeout --kill-after=10s 420s env PICOCRYPT_JOURNAL_RESTART_BOUNDED=1 bash "$0" "$@"
fi

api=${1:?API 26 or 36 required}
case "$api" in 26|36) ;; *) echo "Unsupported restart test API: $api" >&2; exit 1 ;; esac
: "${ANDROID_SERIAL:?exact owned emulator serial required}"
: "${PICOCRYPT_EXPECTED_AVD:?exact owned AVD name required}"
[[ "$ANDROID_SERIAL" =~ ^emulator-[0-9]+$ ]] || { echo "Expected an owned emulator serial" >&2; exit 1; }
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
attempt=$(realpath -m "${2:-$repo/android/app/build/ci-device-tests/api-$api/journal-restart}")
run_id=${3:-api${api}-$(date -u +%Y%m%dT%H%M%S)-$$}
[[ "$run_id" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { echo "Invalid restart run ID" >&2; exit 1; }
package=io.github.picocrypt_ng.picocrypt_ng
selector="$package.Pcv3JournalRestartDeviceTest#optInNativeV2JournalRestartRetiresOnlyTheOwnedStage"
cd "$repo"
[[ "$(timeout 15s adb shell getprop ro.build.version.sdk | tr -d '\r')" == "$api" ]] || { echo "Device API does not match $api" >&2; exit 1; }
[[ "$(timeout 15s adb shell am get-current-user | tr -d '\r')" == 0 ]] || { echo "Restart test requires Android user 0" >&2; exit 1; }
avd=$(timeout 15s adb emu avd name | tr -d '\r')
[[ "$avd" == "$PICOCRYPT_EXPECTED_AVD"$'\nOK' ]] || { echo "Device AVD does not match $PICOCRYPT_EXPECTED_AVD" >&2; exit 1; }
mkdir -p "$(dirname "$attempt")"
mkdir "$attempt"
printf 'api=%s\nserial=%s\navd=%s\nrun_id=%s\nselector=%s\n' \
  "$api" "$ANDROID_SERIAL" "$PICOCRYPT_EXPECTED_AVD" "$run_id" "$selector" > "$attempt/device.txt"
git ls-files --cached --others --exclude-standard -- 'src/*.go' 'src/go.mod' 'src/go.sum' \
  'android/app/src/*.kt' 'android/app/src/*/AndroidManifest.xml' \
  'android/build-gomobile.sh' 'android/*.gradle.kts' 'android/app/build.gradle.kts' \
  '.github/scripts/run-android-journal-restart-test.sh' |
  LC_ALL=C sort -u | while IFS= read -r file; do sha256sum "$file"; done > "$attempt/source-before.sha256"
app_apk=android/app/build/outputs/apk/debug/app-debug.apk
test_apk=android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
sha256sum android/app/libs/picocrypt-mobile.aar "$app_apk" "$test_apk" > "$attempt/artifacts-before.sha256"
# Same-signature replacements preserve app data; never uninstall or clear unresolved custody.
timeout --kill-after=10s 60s adb install -r "$app_apk" > "$attempt/install-app.txt" 2>&1
timeout --kill-after=10s 60s adb install -r -t "$test_apk" > "$attempt/install-test.txt" 2>&1
for kind in app test; do
  installed_package=$package
  expected_apk=$app_apk
  if [[ "$kind" == test ]]; then installed_package=$package.test; expected_apk=$test_apk; fi
  installed=$(timeout 15s adb shell pm path "$installed_package" | tr -d '\r')
  [[ "$installed" =~ ^package:/data/app/[A-Za-z0-9_+./=~-]+/base\.apk$ ]] || { echo "Unexpected installed $kind APK path" >&2; exit 1; }
  printf '%s\n' "$installed" > "$attempt/installed-$kind-path.txt"
  timeout --kill-after=10s 30s adb exec-out cat "${installed#package:}" |
    sha256sum > "$attempt/installed-$kind.sha256"
  [[ "$(cut -d' ' -f1 "$attempt/installed-$kind.sha256")" == "$(sha256sum "$expected_apk" | cut -d' ' -f1)" ]] || { echo "Installed $kind APK bytes differ from the build" >&2; exit 1; }
done

timeout --kill-after=10s 180s adb shell am instrument -w -r -e class "$selector" \
  -e pcv3JournalPhase hold -e pcv3JournalRunId "$run_id" \
  "$package.test/androidx.test.runner.AndroidJUnitRunner" > "$attempt/hold-intentionally-killed.log" 2>&1 &
hold_pid=$!
# Only stop the host command owned by this script. Failed custody stays on the device.
trap 'kill "$hold_pid" 2>/dev/null || true' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 -I - "$package" "$run_id" "$attempt" <<'PY'
import datetime, hashlib, json, re, subprocess, sys, time
from pathlib import Path

package, run_id, output = sys.argv[1:]; output = Path(output)
def adb(*args, input=None):
    return subprocess.run(['adb', *args], input=input, capture_output=True, timeout=10)
def private(*args):
    result = adb('exec-out', 'run-as', package, *args)
    assert result.returncode == 0, (args, result.stderr.decode(errors='replace'))
    return result.stdout
marker_path = f'files/pcv3-journal-restart-{run_id}/ready.json'
deadline = time.monotonic() + 90
while True:
    result = adb('exec-out', 'run-as', package, 'cat', marker_path)
    try: marker = json.loads(result.stdout) if result.returncode == 0 else None
    except json.JSONDecodeError: marker = None
    if marker is not None: break
    assert time.monotonic() < deadline, 'hold produced no complete ready marker'
    time.sleep(0.05)
assert 0 < len(result.stdout) <= 2048, 'unbounded hold marker'
assert marker['runId'] == run_id and marker['status'] in ('checking-resources', 'deriving-key')
assert re.fullmatch(r'\.picocrypt-pcv3-private-[A-Z2-7]+', marker['directory'])
assert re.fullmatch(r'\.picocrypt-pcv3-[A-Z2-7]+', marker['stage'])
pid = str(marker['pid']); assert pid.isdecimal()
assert adb('shell', 'pidof', package).stdout.decode().strip().split() == [pid], 'ready PID is not the exact task app'
(output/'ready.json').write_bytes(result.stdout)
# Exactly one host kill. Missing post-death custody cannot become a cleanup PASS.
killed = adb('shell', 'am', 'force-stop', '--user', '0', package)
assert killed.returncode == 0, killed.stderr
death_deadline = time.monotonic() + 5
while adb('shell', 'pidof', package).stdout.strip() or adb('shell', 'test', '!', '-d', f'/proc/{pid}').returncode != 0:
    assert time.monotonic() < death_deadline, 'hold app or PID remains alive after force-stop'
    time.sleep(0.05)
assert private('cat', marker_path) == result.stdout, 'marker changed across death'
directory = f"files/picocrypt_files/{marker['directory']}"
journal = directory + '/.picocrypt-pcv3-stage.journal'
for path, prefix in ((directory, 'directory'), (journal, 'journal'), (directory+'/'+marker['stage'], 'stage')):
    identity = private('stat', '-c', '%d:%i', path).decode().strip()
    assert identity == f"{marker[prefix+'Device']}:{marker[prefix+'Inode']}", (path, identity)
assert hashlib.sha256(private('cat', journal)).hexdigest() == marker['journalSha256'], 'native v2 journal changed or retired before restart'
# API 26's test is a shell builtin; pass the reviewed absence check on stdin.
absence = adb('shell', '-T', 'run-as', package, '/system/bin/sh', '-s', input=b'''set -eu
[ ! -e files/picocrypt_files/pcv3_retained_output ]
[ ! -L files/picocrypt_files/pcv3_retained_output ]
[ ! -e files/pcv3-deny-only.receipt ]
[ ! -L files/pcv3-deny-only.receipt ]
''')
(output/'post-death-absence.stdout').write_bytes(absence.stdout)
(output/'post-death-absence.stderr').write_bytes(absence.stderr)
assert absence.returncode == 0, ('publication/receipt absence failed', absence.returncode, absence.stdout, absence.stderr)
(output/'post-death-custody.json').write_text(json.dumps({'pid':int(pid),'runId':run_id,'journalSha256':marker['journalSha256'],'verifiedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
PY
hold_status=0
wait "$hold_pid" || hold_status=$?
trap - EXIT
printf '%s\n' "$hold_status" > "$attempt/hold-exit-code-not-a-pass.txt"
recover_status=0
timeout --kill-after=10s 180s adb shell am instrument -w -r -e class "$selector" \
  -e pcv3JournalPhase recover -e pcv3JournalRunId "$run_id" \
  "$package.test/androidx.test.runner.AndroidJUnitRunner" > "$attempt/recover-actual-instrumentation.log" 2>&1 || recover_status=$?
printf '%s\n' "$recover_status" > "$attempt/recover-exit-code.txt"
if (( recover_status != 0 )); then exit "$recover_status"; fi
python3 -I - "$attempt/recover-actual-instrumentation.log" "$selector" <<'PY'
import re, sys
from pathlib import Path

path, selector = sys.argv[1:]; expected_class, expected_method = selector.split('#')
text = Path(path).read_text(); fields = {}; events = []
for line in text.splitlines():
    if line.startswith('INSTRUMENTATION_STATUS: '):
        key, separator, value = line.removeprefix('INSTRUMENTATION_STATUS: ').partition('=')
        if separator: fields[key] = value
    elif line.startswith('INSTRUMENTATION_STATUS_CODE: '):
        code = int(line.split(': ', 1)[1])
        assert code in (1, 0), ('failed/error/skipped test status', code, fields)
        assert fields.get('class') == expected_class and fields.get('test') == expected_method, fields
        assert fields.get('numtests') == '1' and fields.get('current') == '1', fields
        events.append(code); fields = {}
assert events == [1, 0], ('test did not actually start and pass once', events)
assert re.findall(r'^INSTRUMENTATION_CODE: (-?\d+)$', text, re.M) == ['-1']
assert re.findall(r'^OK \((\d+) tests?\)$', text, re.M) == ['1']
assert not re.search(r'INSTRUMENTATION_FAILED|INSTRUMENTATION_ABORTED|Process crashed|FAILURES!!!', text)
print('Verified actual native JUnit START/PASS/one test/no skip for', selector)
PY
sha256sum -c "$attempt/artifacts-before.sha256" > "$attempt/artifacts-after.txt"
sha256sum -c "$attempt/source-before.sha256" > "$attempt/source-after.txt"
