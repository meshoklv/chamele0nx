#!/usr/bin/env bash
# Render every diagram to PNG so a human (or a model) can look at the
# result instead of guessing from the SVG source.
#
#   docs/assets/preview.sh            # both languages into /tmp/diagram-preview
#   docs/assets/preview.sh en         # one language
#   OUT=~/look docs/assets/preview.sh # somewhere else
#
# Needs rsvg-convert:  apt-get install librsvg2-bin
set -euo pipefail
cd "$(dirname "$0")"

command -v rsvg-convert >/dev/null || {
  echo "rsvg-convert not found: apt-get install librsvg2-bin" >&2; exit 1; }

OUT=${OUT:-/tmp/diagram-preview}
langs=${*:-en ru}

python3 generate.py >/dev/null

for lang in $langs; do
  mkdir -p "$OUT/$lang"
  for f in "$lang"/*.svg; do
    rsvg-convert -w 1180 "$f" -o "$OUT/${f%.svg}.png"
  done
done

echo "PNG written to $OUT:"
find "$OUT" -name '*.png' | sort
