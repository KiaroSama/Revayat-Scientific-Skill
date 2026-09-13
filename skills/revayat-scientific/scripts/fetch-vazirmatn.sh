#!/usr/bin/env bash
# Put Vazirmatn Regular + Bold (Western digits) into a fonts/ directory for
# @font-face embedding. Never the UI-FD / Farsi-digits cut, which draws ۳٫۱۴.
#
#   fetch-vazirmatn.sh [dest-dir]
#
# Reuses an installed system face or a previous download before hitting the
# network, so an offline machine with the font already present still works.
# Vazirmatn is SIL Open Font License 1.1; keep the licence file beside the
# TTFs when you ship the HTML.
set -uo pipefail

dest=${1:-fonts}
cache="${XDG_CACHE_HOME:-$HOME/.cache}/fa-fonts"
ver=${VAZIRMATN_VERSION:-33.003}
url="https://github.com/rastikerdar/vazirmatn/releases/download/v${ver}/vazirmatn-v${ver}.zip"

mkdir -p "$dest" "$cache"

want=(Vazirmatn-Regular.ttf Vazirmatn-Bold.ttf)

have_all() {
  local dir=$1 f
  for f in "${want[@]}"; do
    [[ -s "$dir/$f" ]] || return 1
  done
  return 0
}

report() {
  local f
  for f in "${want[@]}"; do printf '%s\n' "$dest/$f"; done
}

if have_all "$dest"; then
  echo "fetch-vazirmatn: already present in $dest" >&2
  report
  exit 0
fi

# 1. A previous download.
if have_all "$cache"; then
  echo "fetch-vazirmatn: using cache $cache" >&2
  cp -f "$cache"/Vazirmatn-Regular.ttf "$cache"/Vazirmatn-Bold.ttf "$dest/"
  report
  exit 0
fi

# 2. An installed system copy — no network needed.
if command -v fc-match >/dev/null 2>&1; then
  reg=$(fc-match -f '%{file}' 'Vazirmatn:style=Regular' 2>/dev/null || true)
  bold=$(fc-match -f '%{file}' 'Vazirmatn:style=Bold' 2>/dev/null || true)
  if [[ -n ${reg:-} && $reg == *[Vv]azirmatn* && -f $reg ]]; then
    echo "fetch-vazirmatn: copying the installed face" >&2
    cp -f "$reg" "$dest/Vazirmatn-Regular.ttf"
    if [[ -n ${bold:-} && $bold == *[Vv]azirmatn* && -f $bold ]]; then
      cp -f "$bold" "$dest/Vazirmatn-Bold.ttf"
    else
      cp -f "$reg" "$dest/Vazirmatn-Bold.ttf"
    fi
    cp -f "$dest/Vazirmatn-Regular.ttf" "$cache/" 2>/dev/null || true
    cp -f "$dest/Vazirmatn-Bold.ttf" "$cache/" 2>/dev/null || true
    report
    exit 0
  fi
fi

# 3. Download.
for tool in curl unzip; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "fetch-vazirmatn: need $tool to download the font" >&2
    echo "fetch-vazirmatn: or install any fa face and re-run" >&2
    exit 1
  }
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "fetch-vazirmatn: downloading v${ver}" >&2
if ! curl -fsSL --retry 2 --connect-timeout 15 -o "$tmp/v.zip" "$url"; then
  echo "fetch-vazirmatn: download failed: $url" >&2
  echo "fetch-vazirmatn: fall back to any installed fa face, e.g." >&2
  echo "  fc-list :lang=fa family | sort -u" >&2
  exit 1
fi

if ! unzip -q -o "$tmp/v.zip" "fonts/ttf/Vazirmatn-Regular.ttf" \
        "fonts/ttf/Vazirmatn-Bold.ttf" -d "$tmp"; then
  echo "fetch-vazirmatn: archive layout changed; unzip -l $tmp/v.zip" >&2
  exit 1
fi

for f in "${want[@]}"; do
  src="$tmp/fonts/ttf/$f"
  [[ -s $src ]] || { echo "fetch-vazirmatn: missing $f in archive" >&2; exit 1; }
  cp -f "$src" "$dest/$f"
  cp -f "$src" "$cache/$f" 2>/dev/null || true
done

if command -v sha256sum >/dev/null 2>&1; then
  echo "fetch-vazirmatn: sha256" >&2
  ( cd "$dest" && sha256sum "${want[@]}" >&2 )
fi

report
