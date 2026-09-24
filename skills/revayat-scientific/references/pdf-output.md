# Printable PDF output

Use the PDF as the RTL reading surface. Preserve measured source page/book
sizes and scientific image information described in
[layout-and-images.md](layout-and-images.md). A4 values in a template are examples,
not permission to resize the source. Keep editable sources, job ledgers and the
agent workflow log beside the translation output.

Examples below run from the installed skill directory. Use the Python interpreter
where the skill requirements are installed. The portable dispatcher selects the
platform adapter and keeps its Python available to child helpers.

## Discover prerequisites

```sh
python scripts/revayat-scientific.py doctor
python scripts/revayat-scientific.py doctor --require-tex
```

The native equivalents are `scripts/preflight.sh [--require-tex]` and
`scripts/preflight.ps1 [-RequireTex]`. PowerShell supports Windows PowerShell 5.1
and PowerShell 7 on Windows; use the Bash adapter on Linux/macOS.

The report distinguishes configured prerequisites from a successful render.
TeX readiness requires a local Linux Docker/Podman runtime, a previously built
compatible image and same-Python PyMuPDF. Chromium needs a discovered browser
plus same-Python `playwright.sync_api` and PyMuPDF. `REVAYAT_CHROMIUM` overrides
browser discovery; an invalid explicit path is not replaced with another browser.
Windows also checks standard Edge/Chrome locations; macOS checks the standard
Google Chrome application path.

WeasyPrint requires a stable version at least 68 and importable `HTML`, `URLFetcher`,
`URLFetcherResponse`, `FatalURLFetchingError`, native libraries and PyMuPDF in that
same interpreter. A `weasyprint` executable from another environment proves
nothing about this renderer. Install optional dependencies using the selected
interpreter and official platform prerequisites; do not alter system Python.
Host font names or registry entries are candidates, not evidence of actual font
selection, embedding, glyph coverage or readable text extraction.

## Prepare the isolated TeX toolchain

TeX compilation has **no native fallback**. A native `xelatex`, MiKTeX or `latexmk`
installation does not satisfy the build path. After runtime/image setup is
authorized, build the supplied toolchain from the installed `assets` directory:

```sh
docker build --tag revayat-scientific-tex:1 --file assets/Dockerfile.tex assets
```

Podman uses the same context and Dockerfile:

```sh
podman build --tag revayat-scientific-tex:1 --file assets/Dockerfile.tex assets
```

The image build downloads its Linux toolchain packages. Translation runs do not
install a runtime, pull an image or download TeX packages. The Dockerfile installs
XeLaTeX, `xepersian`, recommended TeX font metrics (including `pzdr`), static
Vazirmatn Regular/Bold and the entry script
`assets/tex-container-entry.sh`. That script performs two compilation passes with
shell escape disabled; it does not run bibliography tools automatically.

`REVAYAT_CONTAINER_RUNTIME` selects the installed `docker` or `podman` executable;
`REVAYAT_TEX_IMAGE` selects a previously built image, default
`revayat-scientific-tex:1`. The controller checks the local runtime/connection,
Linux-container mode, supported toolchain label and immutable image ID. Remote
daemon endpoints are refused. A local VM managed by Docker/Podman is supported
when its endpoint satisfies the controller's local-only rules.

Only the bounded literal TeX include closure, referenced graphics and dedicated
job-local font files enter the read-only input mount. The whole source directory,
home directory and credentials are not mounted. The container has no network,
a read-only root, no added capabilities, a non-root user and bounded memory,
process and time resources. Its output is staged and validated. Cleanup checks
the run label, container name and ID; uncertain cleanup retains recovery evidence
and fails. Never substitute a raw native TeX command for a missing prerequisite
or failed isolation check.

A nonzero compiler exit reports a bounded error category such as a missing
resource, unavailable font or undefined control sequence. It does not print
manuscript lines from TeX's raw console log. Use the source and the reported
category for a local correction; keep the source private during diagnosis.

The dispatcher and the bundled CI runner keep host-only ownership receipts in a
surviving process. If their child build is cancelled or times out, that owner
checks and removes only containers carrying its exact receipt and label before
returning. If a whole host process is abruptly killed, the container's internal
deadline and Docker/Podman auto-removal still bound its lifetime; inspect retained
recovery receipts before retrying an interrupted job.

## Choose the actual source and engine

| Source | Automatic selection | Explicit selection |
| --- | --- | --- |
| `.tex` | Isolated XeLaTeX; otherwise an existing sibling `.html` and available HTML engine | `--engine tex` requires isolated TeX; an HTML engine requires the sibling HTML |
| `.html` / `.htm` | Chromium, then WeasyPrint | `--engine chromium` or `--engine weasyprint`; `tex` is incompatible |

Selection happens before lint, assets and extraction probes, so those checks
cover the file that will render. An explicitly unavailable or incompatible engine
fails. Once a selected engine starts and fails, the build does not switch engines.
Record the selected source and engine in the job log.

```sh
python scripts/revayat-scientific.py build job/translation.tex paper --engine tex --level journal --verify --output-dir delivery
python scripts/revayat-scientific.py build job/translation.html paper --engine chromium --level journal --verify --output-dir delivery
```

`terms.tsv` and `manifest.txt` are required beside the source unless explicit
`--terms` / `--manifest` paths are supplied. Literal TeX includes inherit the main
job's sidecars and compile-root asset paths. Cycles, dynamic includes and closure
limit violations fail explicitly. A legitimate figure-free document may have an
empty manifest; missing expected figures remain a failure.

Use the user's destination. Otherwise delivery defaults to
`$HOME/Documents/books/<slug>.pdf`. A slug is a filename without directory
separators. The working PDF must differ from the delivered PDF. Inputs and previous
delivery remain protected while a replacement is staged and checked. Keep separate
slugs for excerpts and complete books.

## Fonts, Western digits and RTL

Start with `assets/rtl-document.tex` or `assets/rtl-document.html`. Set physical
sizes from the source. In TeX, load `graphicx`, `hyperref` and `geometry` before
`xepersian`, and retain `\usepackage[mathdigits=default]{xepersian}` so math does
not switch to Persian digits. Use real static font weights. Never rename a
variable font or Regular file to impersonate a static Bold font.

For approved job-local font delivery:

```sh
python scripts/revayat-scientific.py fonts job/fonts
```

The font helper delivers validated static `Vazirmatn-Regular.ttf` and
`Vazirmatn-Bold.ttf` with `OFL.txt` and `font-provenance.json`. Provenance includes
release version and hashes. Incomplete fonts/licenses and destination failures are
errors; an optional cache-write failure after delivery is a warning. Versioned
cache entries remain separate from delivery. `REVAYAT_FONT_OFFLINE=1` forbids font
downloads. This helper does not register fonts globally.

The TeX image contains static fonts; host-installed families are not automatically
available inside it. A job-local `fonts/` directory can supply reviewed files.
HTML must reference delivered files through local `@font-face` URLs. Do not choose
a UI-FD/Farsi-digit cut. Inspect actual font names and relevant glyphs: an installed
or embedded font can still be the wrong face.

| Content | TeX | HTML |
| --- | --- | --- |
| Persian prose | RTL default | `lang="fa" dir="rtl"` |
| English term, citation, number and unit | One `\en{...}` / `\lr{...}` cluster | One `dir="ltr"` span for the whole cluster |
| Code | `latin` around `Verbatim`; inline `\lr{\texttt{...}}` | Actual code elements with LTR direction and preserved whitespace |
| Equations | Math mode, `mathdigits=default` | Reviewed LTR mathematical content |
| Figure | LTR placement with separately reviewed Persian caption | Preserve aspect ratio and reviewed caption direction |

Keep `OP_IF/OP_NOTIF`, decimals, signs, ranges and number/unit pairs in one LTR
cluster; separate spans can reverse their order. Font digit settings alone do not
replace these boundaries. The TeX digit font must cover the Persian glyphs required
by `xepersian`; this is not a reason to localize Western scientific digits. Use
`longtable` for tables spanning pages and retain bookmark-safe handling of
`\lr`/`\en` in headings and captions.

Transparent or low-quality figures need the source-preserving workflow from
[layout-and-images.md](layout-and-images.md), not unconditional conversion or
downsampling. Check rendered artwork for black fills, mirroring and unwanted
page furniture after any approved image preparation.

## HTML rendering boundaries

Both HTML engines run through `render-html.py`. Chromium uses a separate headless
Playwright context with disabled document scripts, blocked service workers and
intercepted resource requests. It waits for document fonts; an existing user
browser session is never reused. Do not replace this with raw Chrome
`--print-to-pdf` commands or an unrestricted `file://` page.

WeasyPrint uses a fatal restricted URL fetcher. Both paths permit only bounded
approved local assets and supported embedded resources; network fetches, outside
files, active content and PDF attachments are refused. Limits are 64 MiB per
resource, 256 MiB total and 2048 resource requests. Keep fonts, CSS and images in
the document job. Citation hyperlinks are not permission to fetch remote content.
Resource failure blocks publication; fetched input hashes are checked again before
the staged PDF is published.

Keep explicit `dir="ltr"` attributes even where CSS has `unicode-bidi: isolate`.
CSS support varies between engines and versions; inspect warnings and rendered
output instead of assuming identical bidi behavior. A correct visible page and
readable extracted text are separate requirements.

## Verify before delivery

`--verify` / `-Verify` is a strict gate. It requires host `pdfinfo`, `pdffonts`,
`pdftoppm` and same-Python PyMuPDF. Missing tools, failed extractors or inconclusive
results fail regardless of which TeX/HTML engines are installed.

The gate checks a complete PDF, a positive page count, at least one reported font
and embedding for **every reported font row**. It generates first/last sample
PNGs and a middle sample when there are more than two pages. The source-bound
`check-pdf-text-order.py --json` result must be `passed`; `failed` or `inconclusive`
is not successful verification. Only then is the PDF copied to the selected
delivery path. A failed gate preserves the previous delivered edition.

These checks do not prove the requested font was used everywhere, full translation
coverage, source geometry equality or visually correct pages. Open sample images
and pages affected by complex layout; review source/output sizes, tables, figures,
equations and font substitutions separately. Raster generation is not visual
approval. Check Western digits in prose **and** inline/display math, exponents,
decimals, signs, ranges and units. Include a visible `3.14` check rather than
trusting the extraction string alone.

PyMuPDF source-phrase probes use NFKC normalization for compatible presentation
forms; they measure extraction order, not completeness. Never reverse extracted
strings to force a pass. Do not enable blanket per-glyph
`\XeTeXgenerateactualtext` as an assumed cure: font/extractor combinations can
interleave characters. Honor existing ActualText but verify the actual artifact.
An Amiri fallback or another readable-looking face may still yield inconclusive
extraction; that must remain a failure, not a weakened gate.

Use `python scripts/revayat-scientific.py pages full.pdf excerpt.pdf 1-20` for a
contiguous excerpt. The source stays unchanged and shared PDF objects are copied
in one range, avoiding the duplication caused by rebuilding one page at a time.

At handoff, give the absolute PDF and workflow-log paths, page count, actual engine
and unresolved ambiguities. Do not present an explicitly unverified build as a
verified delivery or paste the complete article into chat.

References: [Playwright browsers](https://playwright.dev/python/docs/browsers),
[WeasyPrint URL fetchers](https://doc.courtbouillon.org/weasyprint/stable/api_reference.html#url-fetchers),
[PyMuPDF text extraction](https://pymupdf.readthedocs.io/en/latest/recipes-text.html).
