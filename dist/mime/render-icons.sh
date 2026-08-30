#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

SRC="images/pcv-icon.svg"

if [ ! -f "$SRC" ]; then
  echo "ERROR: $SRC not found" >&2
  exit 1
fi

for tool in rsvg-convert inkscape; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: required tool '$tool' not found in PATH" >&2
    exit 1
  fi
done

# Sizes 64+: rsvg-convert (fast, accurate at this scale)
for SIZE in 64 128 256; do
  rsvg-convert -w "$SIZE" -h "$SIZE" -a "$SRC" -o "images/pcv-icon-${SIZE}.png"
done

# Sizes 16/32/48: inkscape (pixel-perfect at small sizes — rsvg crops 1-2 px)
for SIZE in 16 32 48; do
  inkscape "$SRC" \
    --export-type=png \
    --export-filename="images/pcv-icon-${SIZE}.png" \
    --export-width="$SIZE" \
    --export-height="$SIZE"
done

# Strip non-critical chunks for reproducible diffs (per RESEARCH.md §"PNG storage")
if command -v optipng >/dev/null 2>&1; then
  shopt -s nullglob
  pngs=(images/pcv-icon-*.png)
  shopt -u nullglob
  if [ ${#pngs[@]} -gt 0 ]; then
    optipng -o5 -strip all -quiet "${pngs[@]}"
  fi
fi

# --- ICO build for Windows ---
# Reproducible byte-identical output via explicit metadata stripping.
# ImageMagick does not honor SOURCE_DATE_EPOCH reliably as of 7.1.x
# (see arch reproducible-builds todo + ImageMagick issues #1565, #8301).
# Order of PNG arguments is explicit ascending (16->256) for deterministic
# ICONDIR entry order regardless of locale glob sort.
if command -v magick >/dev/null 2>&1; then
  magick \
    images/pcv-icon-16.png  \
    images/pcv-icon-32.png  \
    images/pcv-icon-48.png  \
    images/pcv-icon-64.png  \
    images/pcv-icon-128.png \
    images/pcv-icon-256.png \
    +set date:create +set date:modify \
    -strip \
    images/pcv-icon.ico
  echo "ICO regenerated."
elif command -v convert >/dev/null 2>&1; then
  # ImageMagick 6 fallback (deprecated 'convert' alias)
  convert \
    images/pcv-icon-16.png  \
    images/pcv-icon-32.png  \
    images/pcv-icon-48.png  \
    images/pcv-icon-64.png  \
    images/pcv-icon-128.png \
    images/pcv-icon-256.png \
    +set date:create +set date:modify \
    -strip \
    images/pcv-icon.ico
  echo "ICO regenerated (ImageMagick 6)."
else
  echo "WARNING: 'magick' (ImageMagick 7) or 'convert' (ImageMagick 6) not found; skipping ICO." >&2
fi

echo "Icons regenerated successfully."
