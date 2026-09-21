#!/usr/bin/env bash
# Report which PDF engines, fonts, and extraction tools exist on this machine
# and what to install for the missing ones. Run before planning a build.
#
#   preflight.sh [--require-tex]
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

require_tex=0
[[ ${1:-} == --require-tex ]] && require_tex=1
if [[ $# -gt 1 || ( $# -eq 1 && ${1:-} != --require-tex ) ]]; then
  echo 'usage: preflight.sh [--require-tex]' >&2
  exit 2
fi

ok()   { printf '  yes   %-22s %s\n' "$1" "${2:-}"; }
no()   { printf '  NO    %-22s %s\n' "$1" "${2:-}"; }

have() { command -v "$1" >/dev/null 2>&1; }
python=''
have python3 && python=$(command -v python3)
py_probe() { [[ -n $python ]] && "$python" -c "$1" >/dev/null 2>&1; }

find_browser() {
  local candidate
  if [[ -n ${REVAYAT_CHROMIUM:-} ]]; then
    [[ -x $REVAYAT_CHROMIUM && -f $REVAYAT_CHROMIUM ]] || return 1
    printf '%s\n' "$REVAYAT_CHROMIUM"
    return 0
  fi
  for candidate in google-chrome google-chrome-stable chromium chromium-browser; do
    if have "$candidate"; then command -v "$candidate"; return 0; fi
  done
  candidate='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  [[ -x $candidate ]] || return 1
  printf '%s\n' "$candidate"
}

tex=0 chrome=0 weasy=0 fa_font=0

echo "PDF engines"
if [[ -n $python ]] && "$python" "$here/tex-container.py" --probe >/dev/null 2>&1 \
    && py_probe 'import pymupdf'; then
  ok "isolated XeLaTeX" "local Linux runtime/image and PyMuPDF available; no document rendered"
  tex=1
else
  no "isolated XeLaTeX" "set up Docker/Podman and assets/Dockerfile.tex; no native fallback"
fi

browser_path=$(find_browser) || browser_path=''
if [[ -n $browser_path ]] && py_probe 'from playwright.sync_api import sync_playwright; import pymupdf'; then
  ok "Chromium candidate" "executable and same-Python Playwright/PyMuPDF available; not launched"
  chrome=1
else
  no "Chromium candidate" "needs a valid REVAYAT_CHROMIUM/PATH browser and same-Python Playwright/PyMuPDF"
fi

if py_probe "import re; from importlib.metadata import version; from weasyprint import HTML; from weasyprint.urls import URLFetcher, URLFetcherResponse, FatalURLFetchingError; import pymupdf; v=version('weasyprint'); raise SystemExit(0 if re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', v) and int(v.split('.')[0]) >= 68 else 1)"; then
  ok "WeasyPrint candidate" "same-Python stable 68+ and restricted-fetcher APIs import; not rendered"
  weasy=1
  echo '        Keep whole English/number clusters inside one dir="ltr" span.'
else
  no "WeasyPrint candidate" "needs same-Python stable 68+, URLFetcher APIs, native libraries and PyMuPDF"
fi

echo
echo "Fonts"
if have fc-list; then
  faces=$(fc-list :lang=fa family 2>/dev/null | tr ',' '\n' | sort -u \
          | grep -v '^$' | head -8 | paste -sd, - | sed 's/,/, /g')
  if [[ -n $faces ]]; then
    ok "host font candidates" "$faces"
    fc-list :lang=fa family 2>/dev/null | grep -qi vazirmatn \
      && ok "Vazirmatn" "host entry only; actual rendering/embedding still requires verification" \
      || no "Vazirmatn" "run scripts/fetch-vazirmatn.sh fonts"
    fa_font=1
  else
    no "fa-capable face" "run scripts/fetch-vazirmatn.sh fonts"
  fi
  fc-list :lang=fa family 2>/dev/null | grep -qi 'UI-FD\|Farsi.*Digit' \
    && echo "        warn: a Farsi-digit cut is installed; never select it"
else
  no "fc-list" "install fontconfig to detect fonts"
fi

echo
echo "Source extraction and verification"
for t in pdftotext pdfimages pdftoppm pdfinfo pdffonts curl unzip; do
  have "$t" && ok "$t" || no "$t"
done
[[ -n $python ]] && ok "python3" "selected interpreter: $python" \
             || no "python3" "check-fa.py will not run"
if py_probe 'import PIL.Image'; then
  ok "Pillow" "scripts/prepare-figures.py"
else
  no "Pillow" "image inspection/preparation requires the skill requirements"
fi
for module in docx playwright; do
  if py_probe "import $module"; then
    ok "$module" "built-in document helpers"
  else
    no "$module" "install the skill requirements"
  fi
done
if py_probe 'import pymupdf'; then
  ok "PyMuPDF" "scripts/crop-source-figures.py"
else
  no "PyMuPDF" "cannot crop PDF artwork; pip install pymupdf"
fi

echo
echo "Verdict"
echo '  Discovery only: no document, browser launch, font usage or extraction quality was verified.'
if [[ $tex -eq 1 ]]; then
  echo '  TeX candidate: isolated XeLaTeX; run the actual build and --verify.'
elif [[ $chrome -eq 1 ]]; then
  echo '  HTML candidate: Chromium through the restricted renderer; verify layout and extraction.'
elif [[ $weasy -eq 1 ]]; then
  echo "  no TeX and no Chromium: build .html with WeasyPrint, and keep"
  echo "  every English cluster in a single dir=\"ltr\" isolate"
  echo "  (verify text extraction separately)"
else
  echo '  No configured engine has the required prerequisites; resolve the missing items.'
fi
[[ $fa_font -eq 0 ]] && echo '  Host Persian font discovery found no candidate; container/job-local fonts are separate.'
echo '  HTML/local fonts: deliver real static Regular/Bold files, OFL.txt and provenance beside the source.'
echo '  --verify requires pdfinfo, pdffonts, pdftoppm and same-Python PyMuPDF; missing tools fail.'

if [[ $tex -eq 0 ]]; then
  echo "  TeX setup: build assets/Dockerfile.tex as revayat-scientific-tex:1"
  echo "  The helper never installs a runtime or pulls an image automatically."
fi

if [[ $require_tex -eq 1 && $tex -eq 0 ]]; then
  exit 1
fi
exit 0
