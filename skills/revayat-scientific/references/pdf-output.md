# Printable PDF output

Agent chat is **not** the RTL surface — not in Cursor, not in Claude Code,
not in Codex. Do not spend effort right-aligning the conversation. The
deliverable is a printable PDF with maximum bidi precision.

Read this file whenever the output is a paper, article, book, or the user
asks for PDF / چاپ.

## Destination

Use the directory requested by the user. Otherwise default to
`$HOME/Documents/books/<slug>.pdf`. Pass `--output-dir` to the portable dispatcher
(or `-OutputDirectory` to the native Windows script). The working PDF must be in
another location so a failed build cannot overwrite the previous delivered edition.
`<slug>` is a filename without directory separators. Retain editable sources and
job ledgers outside temporary directories for resumption.

## Preflight

The XeLaTeX template enables `\XeTeXgenerateactualtext=1` so the PDF carries
source Unicode alongside shaped glyphs. This prevents missing or presentation-form
Persian in extraction with fonts whose glyph mappings are incomplete. Keep the
actual PyMuPDF extraction check; setting the primitive is not proof of correct output.

Run this **first**, before choosing an approach:

```bash
scripts/preflight.sh
```

```powershell
.\scripts\preflight.ps1
```

It reports which engines and fonts actually exist and prints the install
command for what is missing. Do not plan a XeLaTeX build on a machine
without XeLaTeX and then discover it at compile time — decide up front, and
tell the user which engine will be used and what that costs.

## Windows

Every shell script has a PowerShell twin with the same name and the same
behaviour, so the workflow is identical — only the extension and the flag
style change:

| POSIX | Windows |
| --- | --- |
| `scripts/preflight.sh` | `.\scripts\preflight.ps1` |
| `scripts/build-pdf.sh doc.tex slug --verify` | `.\scripts\build-pdf.ps1 doc.tex slug -Verify` |
| `scripts/build-pdf.sh doc.html slug --engine chromium` | `.\scripts\build-pdf.ps1 doc.html slug -Engine chromium` |
| `scripts/fetch-vazirmatn.sh fonts` | `.\scripts\fetch-vazirmatn.ps1 fonts` |

The `.py` helpers need no port — run them as `python scripts\check-fa.py …`.
The `.ps1` scripts run on Windows PowerShell 5.1 *and* PowerShell 7.x, so
the shell that ships with Windows is enough and `pwsh` is equally fine.
They are Windows-only by design: under `pwsh` on Linux or macOS each one
exits 2 and points at its `.sh` twin. If execution policy blocks them,
start them with
`powershell -ExecutionPolicy Bypass -File .\scripts\preflight.ps1` (or
`pwsh -ExecutionPolicy Bypass -File …`) rather than relaxing the
machine-wide policy.

These traps are already handled inside the scripts, and any new `.ps1` code
must handle them too. They are all about probing a native command for its
exit code, which the scripts do constantly:

- **5.1** turns each stderr line of a native command into an `ErrorRecord`
  that honours `$ErrorActionPreference`. Under `Stop` the first line
  throws — and headless Chromium, `latexmk -silent`, and a failing
  `python -c "import …"` all write to stderr on ordinary paths. PowerShell
  7.2 exempted redirected native stderr from `$ErrorActionPreference`, so
  this one is 5.1-only; the twins still have to serve both.
- **`$PSNativeCommandUseErrorActionPreference`** (7.3+) makes a non-zero
  *exit code* raise `NativeCommandExitException`, which honours
  `$ErrorActionPreference` too. It ships `$false`, so this is insurance
  rather than a fix for a current default — but a profile or a CI runner
  can set it, and `kpsewhich` exiting 1 means "package not installed", not
  "abort the script".
- **Command discovery.** `& 'pdfinfo'` runs full discovery and prefers an
  alias, function, or cmdlet over the executable; those leave
  `$LASTEXITCODE` stale, or unset in a fresh session, where StrictMode
  then throws on the read. Worse, `Get-Command python` routinely returns
  *several* matches on Windows — 3.13, 3.11, and the WindowsApps Store
  stub are all on a typical `PATH` — so `$cmd.Source` is an array of paths
  that nothing can execute. `Get-Tool` takes the first match, which is the
  one PATH order would have selected anyway.
- **A command that never launches.** If the executable cannot start,
  nothing writes `$LASTEXITCODE`, so a stale or unset value reads as a
  clean exit. That is how a probe like `python -c "import PIL"` can report
  a missing module as installed. `Invoke-Tool` clears `$LASTEXITCODE`
  before every call and reports 127 when it comes back unset.
- **A GUI-subsystem executable is never waited for.** PowerShell blocks on
  console applications only. `msedge.exe` and `chrome.exe` are GUI
  binaries, so `& $browser --print-to-pdf …` returns the moment the
  process starts: nothing is captured, nothing writes `$LASTEXITCODE`, and
  the check for the finished PDF runs while the browser is still booting.
  `Invoke-Tool` reads that as its "never launched" sentinel and reports
  127 — which is why the HTML path failed on every Windows machine with
  Edge until `Invoke-Browser` was split out. Only `Start-Process -Wait`
  blocks on a GUI process, and it joins the arguments into one string, so
  anything containing a space has to be quoted on the way in.

All of these are neutralised in one place — the `Invoke-Tool` helper sets
`$ErrorActionPreference = 'Continue'` and
`$PSNativeCommandUseErrorActionPreference = $false` as function-scoped
locals (they revert on return), and reads `$LASTEXITCODE` defensively.
Route every native call through it, and always hand it the resolved path
from `Get-Tool`, never a bare command name.

Windows specifics worth knowing:

- **Browser engine.** Edge is checked before Chrome — it ships with
  Windows, so a browser fallback is almost always available. The headless
  run gets its own `--user-data-dir`, because otherwise an already-open
  Edge or Chrome window makes `--print-to-pdf` exit 0 without writing
  anything.
- **Poppler** (`pdfinfo`, `pdffonts`, `pdftoppm`, `pdfimages`) is not
  present by default. Without it `-Verify` still checks that the PDF is
  non-empty but cannot rasterise sample pages, and figure extraction is
  unavailable. `winget install oschwartz10612.Poppler`.
- **TeX.** MiKTeX (`winget install MiKTeX.MiKTeX`) can install `xepersian`
  and `bidi` on demand; TeX Live for Windows works as well.
- **`\IfFontExistsTF` lies on MiKTeX.** Asked about a face that is not
  installed, MiKTeX does not answer "no" — it tries to *manufacture* a
  METAFONT font for it. The name is truncated on the way
  (`Couldn't open 'TeX Gyre Term.cfg'`), `makemf` fails, TeX carries on,
  and the run dies much later in the driver with
  `dvipdfmx:fatal: Invalid font: -1 (4)` and a truncated PDF. So a font
  chain must test an **OS-native face first** — `Times New Roman`,
  `Consolas` — and keep the TeX Gyre / Liberation / DejaVu names as the
  tail that only Linux reaches, where fontconfig answers honestly.
  `assets/rtl-document.tex` is ordered that way; preserve it.
- **latexmk needs Perl, which MiKTeX does not ship.** `build-pdf` detects
  this (latexmk dies without writing a `.log`) and falls back to calling
  `xelatex` twice, so no action is required. Install Strawberry Perl only
  if you want latexmk's bibliography reruns.
- **MiKTeX's on-the-fly installer will stall an unattended build.** The
  basic install carries only a small package set, and MiKTeX may fetch the
  rest during the first compile — `fancyvrb`, `bidi`, and the xepersian
  dependencies among them. Out of the box it *asks first*, with a modal
  dialog per package. A person clicks Install; an agent-driven build hangs
  on a window it cannot see, with no error and no `.log`. Turn the prompt
  off only after the user approves dependency installation:

  ```powershell
  initexmf --set-config-value "[MPM]AutoInstall=1"
  ```

  `preflight` reports this setting whenever it detects MiKTeX, so check it
  there rather than discovering it as a hung build. The first compile
  afterwards is still slow — it is downloading packages — so give it time
  before deciding it is stuck.
- **Fonts.** There is no `fc-list`, so `preflight.ps1` reads the font
  registry instead, and `fetch-vazirmatn.ps1` copies an installed
  Vazirmatn from `C:\Windows\Fonts` or the per-user font directory before
  it downloads anything.
- **A variable font cannot be selected by family name.** Google Fonts
  ships Vazirmatn as `Vazirmatn-VariableFont_wght.ttf`, and that is what
  most Windows machines have installed. Asked for the *family*, XeTeX
  hands the driver a named instance of it, which `xdvipdfmx` cannot
  embed — `Invalid TTC index (not TTC font)`, then
  `dvipdfmx:fatal: Invalid font: -1 (4)`, then no PDF. The identical file
  loaded by **path** carries no instance index and embeds normally, so
  `assets/rtl-document.tex` tries `fonts/Vazirmatn-Regular.ttf` before any
  family name. Put the files there first (see below); `build-pdf` prints
  that instruction when it recognises the driver error.

## Engine order

| Priority | Engine | When |
| --- | --- | --- |
| 1 | XeLaTeX + `xepersian` | best Persian print RTL; **logical** text order (copy-paste works); needs a TeX install |
| 2 | Headless Chromium print of the RTL HTML | no TeX; display RTL is correct; **visual** text order (copy-paste reverses Persian) |
| 3 | WeasyPrint on the same HTML | no TeX and no Chrome; same visual-order copy-paste limit |

Do not use pdfLaTeX. Do not use pandoc's default PDF engine without
`xepersian` / `bidi`. Do not ship a Chromium/WeasyPrint PDF when XeLaTeX
is installed — `--verify` will refuse it. CSS `dir="rtl"`, tagged-PDF
flags, and `unicode-bidi` do not fix extraction.

Debian/Ubuntu install for the preferred path:

```bash
sudo apt install texlive-xetex texlive-lang-arabic texlive-fonts-recommended
```

If nothing can produce a PDF, say so, list what to install, and still write
the `.tex` and figures so the user can compile later.

## XeLaTeX + xepersian

Start from `assets/rtl-document.tex`. Load `graphicx`, `hyperref`, and
`geometry` **before** `xepersian`. Put the font beside the document first —
the same `fonts/` the HTML template embeds, and the only form a variable
Vazirmatn can be used in at all:

```bash
scripts/fetch-vazirmatn.sh fonts       # run in the document's directory
```

```powershell
.\scripts\fetch-vazirmatn.ps1 fonts
```

The template resolves the rest itself with
`\IfFontExistsTF`, so there is nothing to hand-edit — but confirm the chosen
face covers Persian:

```bash
fc-list :lang=fa family | sort -u
```

Prefer Vazirmatn, then Shabnam, Sahel, Amiri, DejaVu Sans. Latin serif for
`\setlatintextfont` (isolates). Digit font is the **Persian** text face:
xepersian 25+ requires U+06F0 in `\setdigitfont`, which TeX Gyre Termes
and other Latin serifs lack. Western digits still come from `\lr{…}` /
`\en{…}` (latin text font). Never `\setdigitfont` to a Latin-only face.

### Bidi mapping

| Role | xepersian |
| --- | --- |
| Persian prose | default (RTL) |
| English term, acronym, citation, URL, number | `\lr{…}` / `\en{…}` |
| Code listing | `\begin{latin}…\end{latin}` around `Verbatim` |
| Inline code | `\lr{\texttt{…}}` |
| Math | math mode (LTR) |
| Bibliography | `latin` environment, source language |
| Figure | `\includegraphics` inside `LTR`, Persian caption with `\en` on terms; flatten PNG alpha first |

Numbers inside Persian sentences get `\lr{3}` / `\lr{3.14}`. The wrap is
what keeps digits Western; `\setdigitfont` only has to satisfy xepersian
(U+06F0). Verify once per document with the digit smoke test below rather
than trusting the font setting.

Two traps the template already handles, worth knowing why:

- `\lr` inside `\section` or `\caption` reaches `hyperref` bookmarks and
  breaks them. The template disables it there with
  `\pdfstringdefDisableCommands`. The checker warns if that guard is
  missing.
- A table that runs past one page needs `longtable`, not a hand-split
  `tabular`. Port lists and requirement matrices always hit this.
- `\includegraphics` in an RTL context is painted black or mirrored by
  `xepersian` unless it sits in `LTR` (or `latin`). The template's figure
  example wraps it. Flatten PNG alpha with `scripts/prepare-figures.py`
  before compiling — leftover transparency composites onto black.

## HTML engines: measured behaviour

The HTML path is not a poor relation — on a machine without TeX it is the
path — but it has one hard limit worth knowing before writing a 174-page
document. WeasyPrint 69 does not implement `unicode-bidi: isolate` and says
so on every run:

```text
WARNING: Ignored `unicode-bidi: isolate`, property not supported yet.
```

What that means in practice, measured on rendered output rather than assumed:

- A `dir="ltr"` **attribute** still creates a bidi embedding, and that is
  what actually places English runs correctly. Keep the attribute on every
  isolate; keep the CSS property too, for Chromium and browsers.
- Ordinary cases — `Adam (Kingma & Ba, 2015)`, a trailing `RMSE` before the
  sentence period, `STARTED -> LOCKED_IN` inside one span — render
  correctly even without the property, because the base direction plus the
  Unicode algorithm resolve them.
- The case that genuinely breaks is a cluster split across two spans:
  `<span dir="ltr">OP_IF</span>/<span dir="ltr">OP_NOTIF</span>` renders as
  `OP_NOTIF/OP_IF`. One span around `OP_IF/OP_NOTIF` renders correctly.

So on the HTML path the whole-cluster rule in `rtl-bidi.md` is not a style
preference, it is the difference between right and wrong output. The
checker's `split-isolate` rule exists for this, and Chromium is preferred
over WeasyPrint when both are present.

**Text extraction is separate from display.** The checker uses PyMuPDF
`page.get_text("text", sort=False)` with default ActualText handling and compares
Persian source phrases. This measures readable text through that extractor;
MuPDF applies bidi heuristics, so it does not prove raw storage order or every
viewer's clipboard behavior. Never reverse extracted strings to force a match.

Poppler's `pdftotext -raw` still reverses RTL fragments and inserts bidi controls.
Stripping those controls is not a valid test of stored Unicode order. Use Poppler
for page/font/raster inspection, and install the pinned PyMuPDF requirement for
text verification. A conclusive `logical` result matches source phrases; `visual`
means the extractor reverses them. Inconclusive output fails verification.
With no TeX available, a visual-order HTML fallback may be delivered with the
explicit warning that selectable text is unverified.

References: [PyMuPDF text extraction](https://pymupdf.readthedocs.io/en/latest/recipes-text.html)
and [Poppler's text output implementation](https://skia.googlesource.com/third_party/poppler/+/master/poppler/TextOutputDev.cc).

Surface WeasyPrint's warnings instead of discarding them; `build-pdf.sh`
keeps them.

## HTML font

The template names Vazirmatn. A family name is not enough — without the font
the PDF shows missing-glyph boxes.

1. `fc-list :lang=fa family | head`
2. If no `fa` face is installed: `scripts/fetch-vazirmatn.sh path/to/fonts`
   next to the HTML. Regular and Bold only. Never the `UI-FD` /
   Farsi-digits cut, which draws `۳٫۱۴` and violates the Western-digit
   lock.
3. Keep the template's `@font-face` `url("fonts/Vazirmatn-Regular.ttf")` so
   both engines embed the files. Relative URLs resolve from the HTML
   directory; `build-pdf.sh` `cd`s there.
4. Latin fallback for `pre`/`code`: DejaVu Sans Mono or Liberation Mono.

## Chromium

```bash
scripts/build-pdf.sh path/to/translation.html <slug>
```

Manual equivalent, with the flag that matters — without a virtual-time
budget Chromium can print before webfonts finish loading:

```bash
mkdir -p $HOME/Documents/books
chromium --headless=new --no-pdf-header-footer \
  --virtual-time-budget=10000 \
  --run-all-compositor-stages-before-draw \
  --print-to-pdf="$HOME/Documents/books/<slug>.pdf" \
  "file://$(realpath translation.html)"
```

Try `chromium`, `chromium-browser`, `google-chrome`, `google-chrome-stable`.
A4 comes from the template's `@page`. Do **not** pass `--disable-gpu`:
headless Chrome then paints raster images as black rectangles.

## WeasyPrint

Needs Pango/Cairo (Debian: `libpango-1.0-0`, `libcairo2`, `python3-venv`).
Install the module in a venv, not with `--break-system-packages` and not
with sudo. Then put that venv on `PATH` so `build-pdf.sh` can see
`weasyprint`:

```bash
python3 -m venv $HOME/.venvs/weasyprint
$HOME/.venvs/weasyprint/bin/pip install weasyprint
export PATH="$HOME/.venvs/weasyprint/bin:$PATH"
```

It reads `@font-face` from disk, so it must run with the HTML file's
directory as cwd — the build script does this.

## Verify the artifact

A PDF that exists is not a PDF that is correct. `build-pdf.sh --verify`
runs all of this and **exits non-zero** if poppler tools are missing, the
page count cannot be read, no font is embedded, a raster file was not
written, or (when XeLaTeX is installed) PyMuPDF extraction reverses source phrases. First, last, and (when there are more than two pages) a middle
page are sampled. Do it every time. The script will not copy the PDF to
the selected output directory until lint, figure check, compile, and this
verification have succeeded.

```bash
pdfinfo out.pdf | grep -E 'Pages|Page size'
pdffonts out.pdf | head                    # a real fa face, no fallback
pdftoppm -png -r 110 -f 1 -l 2 out.pdf /tmp/check-p
```

Then **look at the PNG**. Do not treat default `pdftotext` as visual
truth on an RTL PDF; it reorders. Use the PyMuPDF-backed
`scripts/check-pdf-text-order.py` for the separate extraction check. What to look for
on the raster is in `review.md`. Figures must match
the **artwork** on the source page — a black rectangle is a failed extract
or unflattened alpha; a whole English book page (header, body, folio) is
a failed crop, not “the figure”.

Digit smoke test, once per document: put `3.14` in a Persian sentence, build,
rasterise, and confirm the glyphs are `3.14` and not `۳٫۱۴`.

## Page ranges and file size

The full build is the source of truth. A “pages 1–20” or “this chapter”
PDF is an extract of that file, not a second translation.

```bash
scripts/extract-pdf-pages.py doc.pdf $HOME/Documents/books/<slug>-1-20.pdf 1-20
```

Extract a **contiguous range in one call**. Looping `insert_pdf` (or
`pdfseparate` then a naive merge) one page at a time copies every shared
image and font onto every page. A WeasyPrint book that is 2 MB for 44
pages becomes 40 MB for 20 pages that way. The extract script uses one
range and then `garbage=4` / deflate. Ghostscript
`-dFirstPage` / `-dLastPage` is the same idea if PyMuPDF is missing.

Do not overwrite the full-book slug when the user asked for a slice;
use `<slug>-1-20.pdf` or `<slug>-chapter-01.pdf`.

## Chat after success

One short message: what was translated, the absolute PDF path, the page
count, the engine used, and any queued ambiguities. No chat RTL. Do not
paste the article body into chat.
