#!/usr/bin/env bash
# Compile a Persian print document and copy the PDF to $HOME/Documents/books.
#
#   build-pdf.sh <file.tex|file.html> [slug] [--verify] [--engine ENGINE]
#                [--level system-docs|journal] [--terms FILE] [--manifest FILE]
#
# Lints with check-fa.py --strict before any engine runs, and will not copy
# a PDF to Documents/books if lint, figure check, compile, or --verify fail.
#
# Engine order for .tex: isolated XeLaTeX in Docker/Podman. For .html:
# Chromium, then WeasyPrint. A missing engine falls back; a *failing* engine
# does not — it reports the error and stops, so a broken build is never
# quietly downgraded.
#
# Rendered layout and PyMuPDF text extraction are checked separately.
# A PDF engine name alone does not prove readable extracted text.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() {
  echo "usage: build-pdf.sh <file.tex|file.html> [slug] [--verify]" \
       "[--engine tex|chromium|weasyprint]" \
       "[--level system-docs|journal] [--terms FILE] [--manifest FILE]" >&2
  exit 2
}

[[ $# -ge 1 ]] || usage

src=""
slug=""
verify=0
engine=""
level=system-docs
terms=""
manifest=""
output_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify) verify=1; shift ;;
    --engine)
      [[ $# -ge 2 ]] || usage
      engine=$2; shift 2 ;;
    --level)
      [[ $# -ge 2 ]] || usage
      level=$2; shift 2 ;;
    --terms)
      [[ $# -ge 2 ]] || usage
      terms=$2; shift 2 ;;
    --manifest)
      [[ $# -ge 2 ]] || usage
      manifest=$2; shift 2 ;;
    --output-dir)
      [[ $# -ge 2 ]] || usage
      output_dir=$2; shift 2 ;;
    -h|--help) usage ;;
    -*) echo "build-pdf.sh: unknown option: $1" >&2; usage ;;
    *) if [[ -z $src ]]; then src=$1; elif [[ -z $slug ]]; then slug=$1;
       else usage; fi; shift ;;
  esac
done

[[ -n $src ]] || usage
if [[ ! -f $src ]]; then
  echo "build-pdf.sh: not a file: $src" >&2
  exit 1
fi
if [[ $level != system-docs && $level != journal ]]; then
  echo "build-pdf.sh: --level must be system-docs or journal" >&2
  exit 2
fi

src_dir=$(cd "$(dirname "$src")" && pwd)
src_base=$(basename "$src")
ext=${src_base##*.}
requested_source="${src_dir}/${src_base}"
stem_src=${src_base%.*}
stem=${slug:-$stem_src}
case "$stem" in
  ''|.|..|*/*|*\\*) echo "build-pdf: slug must be a filename" >&2; exit 2 ;;
esac
dest_dir=${output_dir:-"${HOME}/Documents/books"}
if [[ $dest_dir != /* ]]; then dest_dir="$PWD/$dest_dir"; fi
dest="${dest_dir}/${stem}.pdf"
local_pdf="${src_dir}/${stem_src}.pdf"
[[ -n $terms ]] || terms="${src_dir}/terms.tsv"
[[ -n $manifest ]] || manifest="${src_dir}/manifest.txt"

log() { printf 'build-pdf: %s\n' "$*" >&2; }

if [[ $(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]) == os.path.realpath(sys.argv[2]))' "$dest" "$local_pdf") == True ]]; then
  log "output destination must differ from the working PDF; use --output-dir"
  exit 2
fi

if [[ ! -f $terms ]]; then
  log "no terms.tsv at ${terms} — write it before drafting (SKILL.md)"
  exit 1
fi
if [[ ! -f $manifest ]]; then
  log "no manifest.txt at ${manifest} — write it at ingest (extraction.md)"
  exit 1
fi

have_xelatex() {
  python3 "$here/tex-container.py" --probe >/dev/null 2>&1
}

find_chrome() {
  local c resolved
  if [[ -n ${REVAYAT_CHROMIUM:-} ]]; then
    [[ -x $REVAYAT_CHROMIUM ]] || return 1
    printf '%s\n' "$REVAYAT_CHROMIUM"
    return 0
  fi
  for c in google-chrome google-chrome-stable chromium chromium-browser; do
    resolved=$(type -P "$c") || continue
    [[ -f $resolved && -x $resolved ]] || continue
    if [[ $resolved != /* ]]; then resolved="$PWD/$resolved"; fi
    printf '%s\n' "$resolved"
    return 0
  done
  c='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  if [[ -x $c ]]; then printf '%s\n' "$c"; return 0; fi
  return 1
}

available=""
have_xelatex && available="tex,"
selected_chrome=""
if selected_chrome=$(find_chrome) && python3 -c 'import playwright.sync_api, pymupdf' 2>/dev/null; then
  available="${available}chromium,"
fi
python3 -c 'from weasyprint import HTML; from weasyprint.urls import URLFetcher, URLFetcherResponse, FatalURLFetchingError; import pymupdf' 2>/dev/null && available="${available}weasyprint"
plan=$(python3 "$here/build-support.py" select "$src" --engine "${engine:-auto}" --available "$available") || exit 1
src=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["source"])' <<<"$plan") || exit 1
engine=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["engine"])' <<<"$plan") || exit 1
src_base=$(basename "$src")
ext=${src_base##*.}
ext=$(printf '%s' "$ext" | tr '[:upper:]' '[:lower:]')
python3 "$here/build-support.py" destination "$dest" "$src" "$local_pdf" || exit 1

# Reserve every artifact and bind the pre-lint source revision to later stages.
guard_dir=$(mktemp -d "$src_dir/.revayat-build-XXXXXXXX") || exit 1
trap 'rm -rf -- "$guard_dir"' EXIT
guard="$guard_dir/build.json"
guard_args=("$here/build-support.py" guard "$guard" --source "$src"
            --requested "$requested_source" --terms "$terms" --manifest "$manifest"
            --working "$local_pdf" --output "$dest")
if [[ $verify -eq 1 ]]; then
  for sample in first last mid; do
    guard_args+=(--sample "$src_dir/verify-$stem-$sample.png")
  done
fi
python3 "${guard_args[@]}" || exit 1

python3 "$here/check-fa.py" "${src_dir}/${src_base}" \
  --level "$level" --terms "$terms" --manifest "$manifest" --strict || {
  log "lint failed; not writing ${dest}"
  exit 1
}

python3 "$here/build-support.py" assets "$src" || {
  log "figure check failed; inspect the required source assets"
  exit 1
}

python3 "$here/build-support.py" guard-check "$guard" || exit 1

cd "$src_dir" || exit 1

# A PDF that exists is not a PDF that is complete. XeLaTeX can exit 0 while
# the xdvipdfmx driver dies, leaving a truncated file with a valid header and
# no trailer - poppler then reports "Couldn't find trailer dictionary".
pdf_is_complete() {
  local f=$1
  [[ -s $f ]] || return 1
  [[ $(head -c 5 "$f") == '%PDF-' ]] || return 1
  tail -c 2048 "$f" | grep -q '%%EOF' || return 1
  return 0
}

warn_html_copy_order() {
  log "HTML engine selected; verify layout and text extraction separately"
}

# Selection already established container readiness; never execute native TeX.
compile_tex() {
  python3 "$here/tex-container.py" "$src" "$local_pdf" --build-guard "$guard" >&2 || return 2
  return 0
}

html_to_pdf() {
  local html=$1 out=$2 chrome
  local arguments=("$here/render-html.py" "$html" "$out" --engine "$engine" --build-guard "$guard")
  if [[ $engine == chromium ]]; then
    chrome=$selected_chrome
    [[ -f $chrome && -x $chrome ]] || { log "selected Chromium became unavailable"; return 2; }
    arguments+=(--browser "$chrome")
  fi
  python3 "${arguments[@]}" || return 2
  warn_html_copy_order
  return 0
}

_first_glob() {
  local f
  for f in "$@"; do
    if [[ -e "$f" && -s "$f" ]]; then
      return 0
    fi
  done
  return 1
}

verify_pdf() {
  local pdf=$1
  pdf_is_complete "$pdf" || {
    log "VERIFY FAIL: $pdf is empty or truncated (no %%EOF trailer)"; return 1; }

  if ! command -v pdfinfo >/dev/null 2>&1; then
    log "VERIFY FAIL: pdfinfo not found (poppler-utils)"
    return 1
  fi
  if ! command -v pdffonts >/dev/null 2>&1; then
    log "VERIFY FAIL: pdffonts not found (poppler-utils)"
    return 1
  fi
  if ! command -v pdftoppm >/dev/null 2>&1; then
    log "VERIFY FAIL: pdftoppm not found (poppler-utils)"
    return 1
  fi

  local pages
  pages=$(pdfinfo "$pdf" 2>/dev/null | awk '/^Pages:/{print $2}')
  log "pages: ${pages:-unknown}"
  if [[ -z ${pages} || ${pages} -lt 1 ]]; then
    log "VERIFY FAIL: could not read page count"
    return 1
  fi

  log "embedded fonts:"
  pdffonts "$pdf" 2>/dev/null | sed -n '1,8p' >&2
  if ! pdffonts "$pdf" 2>/dev/null | awk 'NR > 2 && NF {found=1; if ($(NF-4) != "yes") bad=1} END {exit (!found || bad)}'; then
    log "VERIFY FAIL: no embedded font; Persian may render as boxes"
    return 1
  fi

  # Render diagnostics privately; never unlink a user file to create a sample.
  local out_prefix="${guard_dir}/verify-${stem}"
  local samples=("${out_prefix}-first.png")
  python3 "$here/build-support.py" guard-check "$guard" || return 1
  pdftoppm -singlefile -png -r 110 -f 1 -l 1 "$pdf" "${out_prefix}-first" || {
    log "VERIFY FAIL: pdftoppm first page failed"
    return 1
  }
  if ! _first_glob "${out_prefix}-first.png"; then
    log "VERIFY FAIL: first-page raster was not written"
    return 1
  fi
  # All three roles are refreshed even when their page numbers coincide.
  local mid=$(( (pages + 1) / 2 )) role number
  for role in last mid; do
    number=$pages
    [[ $role != mid ]] || number=$mid
    samples+=("${out_prefix}-${role}.png")
    if [[ $number -eq 1 ]]; then
      cp -- "${out_prefix}-first.png" "${out_prefix}-${role}.png" || return 1
    else
      pdftoppm -singlefile -png -r 110 -f "$number" -l "$number" "$pdf" \
        "${out_prefix}-${role}" || { log "VERIFY FAIL: $role page failed"; return 1; }
    fi
    if ! _first_glob "${out_prefix}-${role}.png"; then
      log "VERIFY FAIL: $role-page raster was not written"
      return 1
    fi
  done
  python3 "$here/build-support.py" samples "$guard" "${samples[@]}" || return 1
  log "rasterised samples: ${src_dir}/verify-${stem}-*.png — look at them, do not"
  log "  judge *display* RTL from pdftotext"

  local order_rc=0 order_out=""
  order_out=$(python3 "$here/check-pdf-text-order.py" "$pdf" \
    --source "${src_dir}/${src_base}" --json 2>&1) || order_rc=$?
  if [[ $order_rc -ne 0 ]] || ! python3 -c 'import json,sys; r=json.load(sys.stdin); raise SystemExit(r.get("status") != "passed")' <<<"$order_out"; then
    log "VERIFY FAIL: text extraction order failed or is inconclusive"
    log "$order_out"
    return 1
  fi
  return 0
}

rc=0
case "$ext" in
  tex)
    compile_tex; rc=$?
    if [[ $rc -ne 0 ]]; then
      log "selected TeX engine failed or became unavailable; no fallback after source checks"
      exit 1
    fi
    ;;
  html|htm)
    html_to_pdf "$src_base" "$local_pdf"; rc=$?
    ;;
  *)
    echo "build-pdf.sh: expected .tex or .html, got: $src_base" >&2
    exit 2
    ;;
esac

if [[ $rc -ne 0 ]]; then
  log "build failed"
  exit 1
fi

pdf_is_complete "$local_pdf" || { log "expected complete PDF missing: ${local_pdf}"; exit 1; }

if [[ $verify -eq 1 ]]; then
  verify_pdf "$local_pdf" || exit 1
fi

python3 "$here/build-support.py" publish "$local_pdf" "$dest" --guard "$guard" || {
  log "delivery failed; previous destination was preserved"
  exit 1
}
echo "$dest"
