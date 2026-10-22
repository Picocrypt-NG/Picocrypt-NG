#!/bin/sh
set -eu

backend="${PICOCRYPT_BACKEND:-auto}"

case "$backend" in
wayland|x11)
	FYNE_PLATFORM="$backend"
	export FYNE_PLATFORM
	;;
auto)
	if [ -z "${WAYLAND_DISPLAY:-}" ] && [ -z "${DISPLAY:-}" ] && [ "$#" -eq 0 ]; then
		echo "Picocrypt-NG: no display detected (WAYLAND_DISPLAY/DISPLAY unset)." >&2
		echo "Set PICOCRYPT_BACKEND=x11|wayland to force backend selection." >&2
		exit 1
	fi
	;;
*)
	echo "Picocrypt-NG: invalid PICOCRYPT_BACKEND value '$backend'." >&2
	echo "Expected one of: auto, x11, wayland." >&2
	exit 2
	;;
esac

exec /app/bin/picocrypt-ng "$@"
