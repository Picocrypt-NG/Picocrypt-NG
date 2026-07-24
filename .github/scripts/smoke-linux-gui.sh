#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ ! -x "$1" ]; then
  echo "Usage: $0 <executable-gui-binary>" >&2
  exit 2
fi

for command_name in Xvfb openbox xdotool wmctrl ps; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Required command not found: $command_name" >&2
    exit 2
  fi
done

binary="$1"

process_running() {
  local pid="$1"
  local state

  kill -0 "$pid" 2>/dev/null || return 1
  state="$(ps -o stat= -p "$pid" 2>/dev/null)" || return 1
  case "$state" in
    Z*) return 1 ;;
  esac
}

terminate_child() {
  local pid="$1"
  local deadline

  if process_running "$pid"; then
    kill -TERM "$pid" 2>/dev/null || true
    deadline=$((SECONDS + 3))
    while process_running "$pid" && ((SECONDS < deadline)); do
      sleep 0.1
    done
    if process_running "$pid"; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  local status="$?"

  trap - EXIT INT TERM HUP
  if [ -n "$app_pid" ]; then
    terminate_child "$app_pid"
  fi
  if [ -n "$openbox_pid" ]; then
    terminate_child "$openbox_pid"
  fi
  if [ -n "$xvfb_pid" ]; then
    terminate_child "$xvfb_pid"
  fi
  rm -rf -- "$temp_root"
  exit "$status"
}

print_logs() {
  printf '%s\n' '--- Xvfb log ---' >&2
  cat "$xvfb_log" >&2 || true
  printf '%s\n' '--- Openbox log ---' >&2
  cat "$openbox_log" >&2 || true
  printf '%s\n' '--- Picocrypt NG log ---' >&2
  cat "$app_log" >&2 || true
}

fail() {
  echo "Linux GUI smoke failed: $*" >&2
  print_logs
  exit 1
}

reap_status=0
reap_child() {
  if wait "$1"; then
    reap_status=0
  else
    reap_status="$?"
  fi
}

temp_root="$(mktemp -d)"
xvfb_pid=""
openbox_pid=""
app_pid=""
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
xvfb_log="$temp_root/xvfb.log"
openbox_log="$temp_root/openbox.log"
app_log="$temp_root/app.log"
display_file="$temp_root/display"

mkdir -p \
  "$temp_root/home" \
  "$temp_root/config" \
  "$temp_root/cache" \
  "$temp_root/data"
export HOME="$temp_root/home"
export XDG_CONFIG_HOME="$temp_root/config"
export XDG_CACHE_HOME="$temp_root/cache"
export XDG_DATA_HOME="$temp_root/data"
export XDG_SESSION_TYPE=x11
export FYNE_PLATFORM=x11
export LIBGL_ALWAYS_SOFTWARE=1

Xvfb -displayfd 3 -screen 0 1024x768x24 -nolisten tcp -ac +extension GLX \
  3>"$display_file" >"$xvfb_log" 2>&1 &
xvfb_pid="$!"

display_number=""
xvfb_probe_error=""
deadline=$((SECONDS + 30))
while :; do
  if ! process_running "$xvfb_pid"; then
    reap_child "$xvfb_pid"
    xvfb_pid=""
    fail "Xvfb exited before becoming ready (status $reap_status)"
  fi

  if IFS= read -r display_number <"$display_file" &&
    [[ "$display_number" =~ ^[0-9]+$ ]]; then
    export DISPLAY=":$display_number"
    if xvfb_probe_error="$(xdotool getdisplaygeometry 2>&1)"; then
      break
    fi
  fi

  if ((SECONDS >= deadline)); then
    if [[ "$display_number" =~ ^[0-9]+$ ]]; then
      fail "Xvfb published display $DISPLAY but xdotool could not connect within 30 seconds: ${xvfb_probe_error:-no diagnostic}"
    fi
    fail "Xvfb did not publish a display number within 30 seconds"
  fi
  sleep 0.1
done

openbox --sm-disable >"$openbox_log" 2>&1 &
openbox_pid="$!"

deadline=$((SECONDS + 10))
while ! wmctrl -m >/dev/null 2>&1; do
  if ! process_running "$xvfb_pid"; then
    reap_child "$xvfb_pid"
    xvfb_pid=""
    fail "Xvfb exited while Openbox was starting (status $reap_status)"
  fi
  if ! process_running "$openbox_pid"; then
    reap_child "$openbox_pid"
    openbox_pid=""
    fail "Openbox exited before becoming ready (status $reap_status)"
  fi
  if ((SECONDS >= deadline)); then
    fail "Openbox did not become ready within 10 seconds"
  fi
  sleep 0.1
done

"$binary" >"$app_log" 2>&1 &
app_pid="$!"

window_id=""
deadline=$((SECONDS + 15))
while :; do
  if ! process_running "$xvfb_pid"; then
    reap_child "$xvfb_pid"
    xvfb_pid=""
    fail "Xvfb exited before the application window appeared (status $reap_status)"
  fi
  if ! process_running "$openbox_pid"; then
    reap_child "$openbox_pid"
    openbox_pid=""
    fail "Openbox exited before the application window appeared (status $reap_status)"
  fi
  if ! process_running "$app_pid"; then
    reap_child "$app_pid"
    app_pid=""
    fail "the application exited before its window appeared (status $reap_status)"
  fi

  if window_id="$(xdotool search --onlyvisible --limit 1 --name '^Picocrypt NG$' 2>/dev/null)"; then
    break
  fi
  if ((SECONDS >= deadline)); then
    fail "the Picocrypt NG window did not appear within 15 seconds"
  fi
  sleep 0.1
done

if ! wmctrl -i -c "$window_id"; then
  fail "wmctrl could not request a graceful close"
fi

deadline=$((SECONDS + 10))
while process_running "$app_pid"; do
  if ! process_running "$xvfb_pid"; then
    reap_child "$xvfb_pid"
    xvfb_pid=""
    fail "Xvfb exited while the application was closing (status $reap_status)"
  fi
  if ! process_running "$openbox_pid"; then
    reap_child "$openbox_pid"
    openbox_pid=""
    fail "Openbox exited while the application was closing (status $reap_status)"
  fi
  if ((SECONDS >= deadline)); then
    fail "the application did not exit within 10 seconds of the close request"
  fi
  sleep 0.1
done

reap_child "$app_pid"
app_pid=""
if [ "$reap_status" -ne 0 ]; then
  fail "the application exited with status $reap_status"
fi
if ! process_running "$xvfb_pid"; then
  reap_child "$xvfb_pid"
  xvfb_pid=""
  fail "Xvfb exited as the application closed (status $reap_status)"
fi
if ! process_running "$openbox_pid"; then
  reap_child "$openbox_pid"
  openbox_pid=""
  fail "Openbox exited as the application closed (status $reap_status)"
fi

if grep -Fq \
  -e 'panic:' \
  -e 'Failed to initialize' \
  -e '*** Error in Fyne call thread,' \
  -e '*** This application has not been migrated to the fyne.Do threading model ***' \
  -e 'failed to initialise GLFW' \
  -e 'failed to initialise OpenGL' \
  -e 'GLX: Failed' \
  -e 'in GL Renderer' \
  "$app_log"; then
  fail "the application log contains a fatal GL or Fyne diagnostic"
fi

echo "PASS: Picocrypt NG opened a real GL window and closed cleanly"
