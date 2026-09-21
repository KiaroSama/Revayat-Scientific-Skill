#!/usr/bin/env bash
# Regression tests for scripts/check-fa.py, check-pdf-text-order.py, and
# the build-pdf lint gate.
#
# The `good` fixtures must lint clean; the `bad` fixtures must report every
# check id listed below. Run before changing a rule so a loosened regex
# cannot pass silently.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# The skill payload lives in its own directory so it can be copied straight
# into ~/.claude/skills, ~/.cursor/skills, or ~/.codex/skills.
skill="$here/../skills/revayat-scientific"
lint="$skill/scripts/check-fa.py"
fixtures="$here/fixtures"
fail=0
mkdir -p "$here/../.scratch"
test_root=$(mktemp -d "$here/../.scratch/upstream.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT

expect_clean() {
  local file=$1
  shift
  local out rc
  out=$(python3 "$lint" "$file" "$@" 2>&1)
  rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "FAIL $(basename "$file") ${*}: expected clean, got:"
    echo "$out" | sed 's/^/    /'
    fail=1
  else
    echo "ok   $(basename "$file") ${*} lints clean"
  fi
}

expect_checks() {
  local file=$1
  shift
  local out rc missing=()
  out=$(python3 "$lint" "$file" 2>&1)
  rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "FAIL $(basename "$file"): expected a non-zero exit"
    fail=1
  fi
  local id
  for id in "$@"; do
    grep -q -- "$id" <<<"$out" || missing+=("$id")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "FAIL $(basename "$file"): checks not reported: ${missing[*]}"
    fail=1
  else
    echo "ok   $(basename "$file") reports ${#@} expected checks"
  fi
}

expect_no_errors() {
  local file=$1 out errs
  out=$(python3 "$lint" "$file" 2>&1)
  errs=$(sed -n 's/^check-fa: \([0-9]*\) error.*/\1/p' <<<"$out")
  if [[ ${errs:-1} -ne 0 ]]; then
    echo "FAIL $(basename "$file"): expected 0 errors, got ${errs:-?}"
    echo "$out" | sed 's/^/    /'
    fail=1
  else
    echo "ok   $(basename "$file") has no errors"
  fi
}

empty_terms="$fixtures/terms-empty.tsv"
empty_manifest="$fixtures/manifest-empty.txt"
good_manifest="$fixtures/manifest-good.txt"
strict_good=(--strict --terms "$empty_terms" --manifest "$good_manifest")
strict_journal=(--level journal --strict --terms "$empty_terms"
                --manifest "$empty_manifest")

expect_clean "$fixtures/good.tex" "${strict_good[@]}"
expect_clean "$fixtures/good.html" "${strict_good[@]}"
expect_clean "$fixtures/journal.tex" "${strict_journal[@]}"

# The shipped templates must not trigger errors. Placeholder TITLE sits in
# an isolate (TeX) or in <title> (HTML).
expect_no_errors "$skill/assets/rtl-document.tex"
expect_no_errors "$skill/assets/rtl-document.html"

expect_checks "$fixtures/bad.tex" \
  arabic-letters eastern-digits zwnj-verb zwnj-plural latin-punct \
  forbidden-fa half-translation fa-morphology en-plural split-isolate \
  unisolated-latin unisolated-number code-direction missing-image \
  bookmark-guard figure-direction full-page-figure

expect_checks "$fixtures/bad.html" \
  arabic-letters eastern-digits zwnj-verb forbidden-fa half-translation \
  fa-morphology en-plural split-isolate unisolated-latin unisolated-number \
  code-direction html-root mirrored-image missing-image print-css \
  figure-direction full-page-figure

# Journal-correct field nouns must fail at the default system-docs level.
journal_out=$(python3 "$lint" "$fixtures/journal.tex" 2>&1) || true
if grep -q forbidden-fa <<<"$journal_out"; then
  echo "ok   journal.tex reports forbidden-fa at system-docs"
else
  echo "FAIL journal.tex: expected forbidden-fa at system-docs"
  echo "$journal_out" | sed 's/^/    /'
  fail=1
fi

# --pairs must merge, not replace, the house list.
extra=$(mktemp "$test_root/pairs.XXXXXX")
printf 'english\tforbidden_fa\tscope\tlevels\nfoo\tبار\tuniversal\tall\n' >"$extra"
merge_out=$(python3 "$lint" "$fixtures/journal.tex" --pairs "$extra" 2>&1) || true
rm -f "$extra"
if grep -q forbidden-fa <<<"$merge_out" && grep -q گره <<<"$merge_out"; then
  echo "ok   --pairs merges house term-pairs.tsv"
else
  echo "FAIL --pairs dropped house rows"
  echo "$merge_out" | sed 's/^/    /'
  fail=1
fi

# --strict without a terms ledger (or sidecar) is a usage error.
strict_rc=0
strict_out=$(python3 "$lint" "$fixtures/nginx-calque.tex" --strict 2>&1) \
  || strict_rc=$?
if [[ $strict_rc -eq 2 ]] && grep -q -- '--terms' <<<"$strict_out"; then
  echo "ok   --strict requires --terms"
else
  echo "FAIL --strict without --terms: expected exit 2"
  echo "$strict_out" | sed 's/^/    /'
  fail=1
fi

strict_man_rc=0
strict_man_out=$(python3 "$lint" "$fixtures/nginx-calque.tex" --strict \
  --terms "$empty_terms" 2>&1) || strict_man_rc=$?
if [[ $strict_man_rc -eq 2 ]] && grep -q -- '--manifest' <<<"$strict_man_out"; then
  echo "ok   --strict requires --manifest"
else
  echo "FAIL --strict without --manifest: expected exit 2"
  echo "$strict_man_out" | sed 's/^/    /'
  fail=1
fi

# Keep-English rows with empty forbidden_fa fail closed, they are not skipped.
inc_rc=0
inc_out=$(python3 "$lint" "$fixtures/nginx-calque.tex" \
  --terms "$fixtures/terms-incomplete.tsv" \
  --manifest "$empty_manifest" 2>&1) || inc_rc=$?
if [[ $inc_rc -eq 2 ]] && grep -q terms-calque <<<"$inc_out" \
    && grep -q proxy_pass <<<"$inc_out"; then
  echo "ok   keep-English row without forbidden_fa is terms-calque"
else
  echo "FAIL incomplete terms.tsv: expected terms-calque exit 2"
  echo "$inc_out" | sed 's/^/    /'
  fail=1
fi

# --terms reads keep-English calques; Persian-output rows stay ignored.
terms_out=$(python3 "$lint" "$fixtures/nginx-calque.tex" \
  --terms "$fixtures/terms-nginx.tsv" \
  --manifest "$empty_manifest" --strict 2>&1) || true
if grep -q forbidden-fa <<<"$terms_out" && grep -q مکان <<<"$terms_out" \
    && grep -q بالادست <<<"$terms_out"; then
  echo "ok   --terms reports job lexicon calques"
else
  echo "FAIL --terms missed nginx calques"
  echo "$terms_out" | sed 's/^/    /'
  fail=1
fi

# Optional deprecated column forms are also forbidden.
dep_out=$(python3 "$lint" "$fixtures/terms-deprecated.tex" \
  --terms "$fixtures/terms-nginx.tsv" \
  --manifest "$empty_manifest" 2>&1) || true
if grep -qE 'کد مبدأ|بالادست|مکان' <<<"$dep_out"; then
  echo "ok   --terms forbids deprecated column forms"
else
  echo "FAIL deprecated column not enforced"
  echo "$dep_out" | sed 's/^/    /'
  fail=1
fi
house_out=$(python3 "$lint" "$fixtures/journal.tex" \
  --terms "$fixtures/terms-nginx.tsv" 2>&1) || true
if grep -q گره <<<"$house_out"; then
  echo "ok   --terms keeps house term-pairs.tsv"
else
  echo "FAIL --terms dropped house rows"
  echo "$house_out" | sed 's/^/    /'
  fail=1
fi

# Manifest names that never appear in the translation are missing-image.
man_out=$(python3 "$lint" "$fixtures/journal.tex" --level journal \
  --terms "$empty_terms" --manifest "$fixtures/manifest-missing.txt" \
  --strict 2>&1) || true
if grep -q missing-image <<<"$man_out" && grep -q fig-never.png <<<"$man_out"; then
  echo "ok   --manifest reports omitted figures"
else
  echo "FAIL --manifest missed omitted figure"
  echo "$man_out" | sed 's/^/    /'
  fail=1
fi

# prepare-figures.py: flatten alpha onto white so the print PDF matches the source.
if python3 -c "import PIL.Image" 2>/dev/null; then
  alpha="$test_root/alpha.png"
  python3 - "$alpha" <<'PY'
import struct, zlib, sys
from pathlib import Path
path = Path(sys.argv[1])
w, h = 4, 2
# RGBA: first pixel transparent black (the Cairo/WeasyPrint trap), rest white.
row = bytes([
    0,  # filter
    0, 0, 0, 0,
    255, 255, 255, 255,
    255, 255, 255, 255,
    255, 255, 255, 255,
])
raw = b"".join(row for _ in range(h))

def chunk(tag, data):
    c = tag + data
    return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)

path.write_bytes(
    b"\x89PNG\r\n\x1a\n"
    + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
    + chunk(b"IDAT", zlib.compress(raw))
    + chunk(b"IEND", b"")
)
PY
  prep="$skill/scripts/prepare-figures.py"
  check_out=$(python3 "$prep" "$alpha" --check 2>&1) || check_rc=$?
  if [[ ${check_rc:-0} -ne 0 ]] && grep -q alpha <<<"$check_out"; then
    echo "ok   prepare-figures --check reports alpha"
  else
    echo "FAIL prepare-figures --check missed alpha"
    echo "$check_out" | sed 's/^/    /'
    fail=1
  fi
  python3 "$prep" "$alpha" >"$test_root/prep.out" 2>&1 || true
  mode=$(python3 -c 'from PIL import Image; import sys; print(Image.open(sys.argv[1]).mode)' "$alpha")
  if [[ $mode == RGB ]]; then
    echo "ok   prepare-figures flattened alpha to RGB"
  else
    echo "FAIL prepare-figures left mode=$mode"
    fail=1
  fi
  rm -f "$alpha" "$alpha.orig"
else
  echo "skip prepare-figures (no Pillow)"
fi

# Missing sidecars must fail before engine selection.
build="$skill/scripts/build-pdf.sh"
missing_terms_rc=0
missing_terms_out=$("$build" "$fixtures/nginx-calque.tex" \
  --manifest "$empty_manifest" 2>&1) || missing_terms_rc=$?
if [[ $missing_terms_rc -ne 0 ]] && grep -q terms.tsv <<<"$missing_terms_out"; then
  echo "ok   build-pdf requires terms.tsv"
else
  echo "FAIL build-pdf without terms.tsv"
  echo "$missing_terms_out" | sed 's/^/    /'
  fail=1
fi

help_out=$(python3 "$skill/scripts/crop-source-figures.py" --help 2>&1) || help_rc=$?
if [[ ${help_rc:-0} -eq 0 ]] && grep -q crop-source-figures <<<"$help_out"; then
  echo "ok   crop-source-figures.py --help"
else
  echo "FAIL crop-source-figures.py --help"
  echo "$help_out" | sed 's/^/    /'
  fail=1
fi

help_out=$(python3 "$skill/scripts/extract-pdf-pages.py" --help 2>&1) || help_rc=$?
if [[ ${help_rc:-0} -eq 0 ]] && grep -q extract-pdf-pages <<<"$help_out"; then
  echo "ok   extract-pdf-pages.py --help"
else
  echo "FAIL extract-pdf-pages.py --help"
  echo "$help_out" | sed 's/^/    /'
  fail=1
fi

# Exercise the shell adapter at the isolated-controller boundary. Actual Docker
# resource isolation and real XeLaTeX rendering are covered by scientific CI.
stub_skill="$test_root/payload"
work="$test_root/build"
mkdir -p "$work/delivered"
python3 - "$skill" "$stub_skill" <<'PY'
from pathlib import Path
import shutil, sys
source, target = map(Path, sys.argv[1:])
shutil.copytree(source, target, ignore=shutil.ignore_patterns('logs', '__pycache__'))
PY
cat >"$stub_skill/scripts/tex-container.py" <<'STUB'
import os
from pathlib import Path
import sys
import pymupdf
mode = os.environ.get('CONTAINER_FIXTURE_MODE', 'ok')
if '--probe' in sys.argv:
    raise SystemExit(2 if mode == 'unavailable' else 0)
marker = os.environ.get('REVAYAT_TEST_ENGINE_MARKER')
if marker:
    Path(marker).write_text('compiler invoked', encoding='utf-8')
output = Path(sys.argv[2])
if mode == 'error':
    print('fixture container failed', file=sys.stderr)
    raise SystemExit(1)
if mode == 'truncated':
    output.write_bytes(b'%PDF-1.7\ntruncated fixture')
else:
    with pymupdf.open() as document:
        document.new_page(width=230, height=340)
        document.save(output)
raise SystemExit(42 if mode == 'failed-valid' else 0)
STUB

expect_build() {
  local label=$1 mode=$2 want_rc=$3
  shift 3
  local out rc=0 missing=() phrase
  cp "$skill/assets/rtl-document.tex" "$work/probe.tex"
  cp "$empty_terms" "$work/terms.tsv"
  cp "$empty_manifest" "$work/manifest.txt"
  printf 'previous approved delivery\n' >"$work/delivered/fa-selftest.pdf"
  cp "$work/delivered/fa-selftest.pdf" "$work/previous.pdf"
  # A failed controller must not make this stale working PDF deliverable.
  printf '%%PDF-1.7 stale working output\n%%%%EOF\n' >"$work/probe.pdf"
  out=$(CONTAINER_FIXTURE_MODE="$mode" bash "$stub_skill/scripts/build-pdf.sh" \
        "$work/probe.tex" fa-selftest --engine tex --output-dir "$work/delivered" 2>&1) || rc=$?
  for phrase in "$@"; do
    grep -qF -- "$phrase" <<<"$out" || missing+=("$phrase")
  done
  if [[ $rc -ne $want_rc || ${#missing[@]} -gt 0 ]]; then
    echo "FAIL build-pdf $label: exit=$rc expected=$want_rc missing=${missing[*]}"
    echo "$out" | sed 's/^/    /'
    fail=1
  elif [[ $want_rc -ne 0 ]] && ! cmp -s "$work/previous.pdf" "$work/delivered/fa-selftest.pdf"; then
    echo "FAIL build-pdf $label changed the approved delivery"
    fail=1
  else
    echo "ok   build-pdf $label"
  fi
}
expect_build "uses isolated controller" ok 0 "fa-selftest.pdf"
expect_build "refuses unavailable explicit container" unavailable 1 "unavailable"
expect_build "rejects failed controller despite stale PDF" error 1 "selected TeX engine failed"
expect_build "rejects failed controller despite valid PDF" failed-valid 1 "selected TeX engine failed"
expect_build "rejects truncated controller output" truncated 1 "expected complete PDF missing"

# The real strict gate runs before the selected controller can compile anything.
cp "$fixtures/nginx-calque.tex" "$work/probe.tex"
build_rc=0
build_out=$(REVAYAT_TEST_ENGINE_MARKER="$work/engine-invoked" \
  bash "$stub_skill/scripts/build-pdf.sh" "$work/probe.tex" fa-selftest \
  --engine tex --output-dir "$work/delivered" --terms "$fixtures/terms-nginx.tsv" \
  --manifest "$empty_manifest" 2>&1) || build_rc=$?
if [[ $build_rc -ne 0 ]] && grep -q forbidden-fa <<<"$build_out" \
    && grep -q 'lint failed' <<<"$build_out" && [[ ! -e $work/engine-invoked ]] \
    && cmp -s "$work/previous.pdf" "$work/delivered/fa-selftest.pdf"; then
  echo "ok   build-pdf lint gate prevents compiler execution and delivery"
else
  echo "FAIL build-pdf lint gate"
  echo "$build_out" | sed 's/^/    /'
  fail=1
fi

# The .tex template resolves fonts with \IfFontExistsTF chains whose last
# entry is unguarded: if that face is missing, fontspec aborts the build.
# A chain made only of Linux faces therefore cannot compile on Windows,
# which is exactly how "DejaVu Serif" broke a MiKTeX build. Each chain must
# name at least one face that ships with Windows.
tex_template="$skill/assets/rtl-document.tex"
# Strip comment lines: a face named only in the prose above the chain does
# not make the chain compile, and matching it would make this test toothless.
tex_code=$(grep -v '^[[:space:]]*%' "$tex_template")
check_font_chain() {
  local label=$1 setter=$2
  shift 2
  local found=0 face
  # -F: the setter names start with a backslash, which grep would otherwise
  # read as a regex escape ('\s' matches whitespace, not a literal "\s").
  if ! grep -qF -- "$setter" <<<"$tex_code"; then
    echo "FAIL font chain $label: no $setter in the template"
    fail=1
    return
  fi
  for face in "$@"; do
    grep -qF -- "$face" <<<"$tex_code" && found=1
  done
  if [[ $found -eq 1 ]]; then
    echo "ok   font chain $label reaches a Windows face"
  else
    echo "FAIL font chain $label is Linux-only; it cannot compile on Windows"
    echo "     add one of: $*"
    fail=1
  fi
}
check_font_chain "persian"  '\settextfont'      'Tahoma' 'Segoe UI' 'Arial'
check_font_chain "latin"    '\setlatintextfont' 'Times New Roman' 'Cambria' 'Arial'
check_font_chain "monospace" '\setmonofont'     'Consolas' 'Courier New'

# MiKTeX answers \IfFontExistsTF "yes" for faces it does not have and then
# dies in the driver, so the OS-native face must be tested FIRST, not last.
check_font_order() {
  local label=$1 native=$2 trap_face=$3
  local native_at trap_at
  native_at=$(grep -nF -- "$native" <<<"$tex_code" | head -1 | cut -d: -f1)
  trap_at=$(grep -nF -- "$trap_face" <<<"$tex_code" | head -1 | cut -d: -f1)
  if [[ -z $native_at || -z $trap_at ]]; then
    echo "FAIL font order $label: expected both '$native' and '$trap_face'"
    fail=1
  elif [[ $native_at -lt $trap_at ]]; then
    echo "ok   font order $label tests the OS face before $trap_face"
  else
    echo "FAIL font order $label: '$trap_face' is tested before '$native';"
    echo "     on MiKTeX that reaches makemf and kills the PDF driver"
    fail=1
  fi
}
check_font_order "latin"     'Times New Roman' 'TeX Gyre Termes'
check_font_order "monospace" 'Consolas'        'TeX Gyre Cursor'

# A family name resolves to a named instance when the only installed cut is
# a variable font, and xdvipdfmx cannot embed one - it dies with "Invalid
# font: -1 (4)". Loading the same file by path avoids the instance index
# entirely, so the local fonts/ directory must be tried before the name.
file_at=$(grep -nF -- 'fonts/Vazirmatn-Regular.ttf' <<<"$tex_code" | head -1 | cut -d: -f1)
name_at=$(grep -nF -- '{Vazirmatn}' <<<"$tex_code" | head -1 | cut -d: -f1)
if [[ -n $file_at && -n $name_at && $file_at -lt $name_at ]]; then
  echo "ok   font chain persian tries fonts/ before the family name"
else
  echo "FAIL font chain persian must test fonts/Vazirmatn-Regular.ttf before"
  echo "     {Vazirmatn}; a variable font picked by name cannot be embedded"
  fail=1
fi

# Browser ownership and exit/resource-denial consequences are exercised by
# test_native_build.py and test_build_integrity.py through render-html.py.

# check-fa.py prints Persian, so it must not depend on the console encoding.
# On Windows an unredirected stdout is cp1252 and the first finding dies
# with UnicodeEncodeError, taking every later check down with it.
cp1252_out=$(PYTHONIOENCODING=cp1252 python3 "$lint" "$fixtures/bad.tex" \
             --level system-docs 2>&1) || true
if grep -q UnicodeEncodeError <<<"$cp1252_out"; then
  echo "FAIL check-fa.py dies on a non-UTF-8 stdout (Windows console)"
  echo "$cp1252_out" | sed 's/^/    /' | tail -5
  fail=1
elif grep -q full-page-figure <<<"$cp1252_out"; then
  echo "ok   check-fa.py forces UTF-8 output"
else
  echo "FAIL check-fa.py under cp1252 did not report the last check"
  echo "$cp1252_out" | sed 's/^/    /' | tail -5
  fail=1
fi

order="$skill/scripts/check-pdf-text-order.py"
order_rc=0
order_out=$(python3 "$order" --extracted "$fixtures/pdf-text-logical.txt" \
  --source "$fixtures/good.tex" 2>&1) || order_rc=$?
if [[ $order_rc -eq 0 ]] && grep -q 'check-pdf-text-order: logical' <<<"$order_out"; then
  echo "ok   check-pdf-text-order reports logical dump"
else
  echo "FAIL check-pdf-text-order logical dump (rc=$order_rc)"
  echo "$order_out" | sed 's/^/    /'
  fail=1
fi
order_rc=0
order_out=$(python3 "$order" --extracted "$fixtures/pdf-text-visual.txt" \
  --source "$fixtures/good.tex" 2>&1) || order_rc=$?
if [[ $order_rc -eq 2 ]] && grep -q 'check-pdf-text-order: visual' <<<"$order_out"; then
  echo "ok   check-pdf-text-order reports visual dump"
else
  echo "FAIL check-pdf-text-order visual dump (rc=$order_rc)"
  echo "$order_out" | sed 's/^/    /'
  fail=1
fi
order_rc=0
order_out=$(python3 "$order" --extracted "$fixtures/pdf-text-visual-words.txt" \
  --source "$fixtures/good.tex" 2>&1) || order_rc=$?
if [[ $order_rc -eq 2 ]] && grep -q 'check-pdf-text-order: visual' <<<"$order_out"; then
  echo "ok   check-pdf-text-order reports visual word order"
else
  echo "FAIL check-pdf-text-order visual word order (rc=$order_rc)"
  echo "$order_out" | sed 's/^/    /'
  fail=1
fi

# Real Docker XeLaTeX and restricted Chromium rendering are owned by
# test_scientific_render.py and test_native_build.py, not duplicated here.
# These suites require their configured CI backends; no unrestricted TeX or
# raw --no-sandbox browser invocation is an accepted test substitute.

if [[ $fail -eq 0 ]]; then
  echo "all tests passed"
else
  echo "tests failed"
fi
exit $fail
