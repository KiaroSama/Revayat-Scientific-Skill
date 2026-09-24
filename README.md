# Revayat Scientific — روایت علمی

[![GPL-3.0-or-later license](https://img.shields.io/badge/License-GPL--3.0--or--later-blue?style=flat-square)](LICENSE)
[![Plugin version 1.0.0](https://img.shields.io/badge/Plugin-1.0.0-blue?style=flat-square)](.codex-plugin/plugin.json)
[![Python 3.10 or newer](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square&logo=python)](skills/revayat-scientific/requirements.txt)
[![One integrated skill](https://img.shields.io/badge/Skills-1-6f42c1?style=flat-square)](skills/revayat-scientific/SKILL.md)
[![Agent Skills format](https://img.shields.io/badge/Format-Agent%20Skills-6f42c1?style=flat-square)](skills/revayat-scientific/SKILL.md)
[![Installable skill ZIP](https://img.shields.io/badge/Package-.skill%20ZIP-6f42c1?style=flat-square)](docs/installation.md)
[![English and Persian docs](https://img.shields.io/badge/Docs-EN%20%7C%20FA-6f42c1?style=flat-square)](README.fa.md)
<br>
[![CI status on main](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml)
[![CodeQL status on main](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/codeql.yml)
[![Weekly security scans configured](https://img.shields.io/badge/Security-Weekly%20scans-167f71?style=flat-square)](.github/workflows/codeql.yml)
[![Shell and workflow lint configured](https://img.shields.io/badge/Lint-ShellCheck%20%2B%20actionlint-167f71?style=flat-square)](.github/workflows/ci.yml)
[![Dependency and workflow audits configured](https://img.shields.io/badge/Audit-pip--audit%20%2B%20zizmor-167f71?style=flat-square)](.github/workflows/ci.yml)
[![PR dependency review configured](https://img.shields.io/badge/PR%20review-Dependency%20review-167f71?style=flat-square)](.github/workflows/dependency-review.yml)
[![Weekly Dependabot updates configured](https://img.shields.io/badge/Dependencies-Dependabot%20weekly-167f71?style=flat-square)](.github/dependabot.yml)
<br>
[![Windows, macOS and Linux](https://img.shields.io/badge/Platforms-Windows%20%7C%20macOS%20%7C%20Linux-287c91?style=flat-square)](.github/workflows/ci.yml)
[![Any source language to Persian](https://img.shields.io/badge/Languages-Any%20source%20to%20Persian-287c91?style=flat-square)](skills/revayat-scientific/references/source-languages.md)
[![Native DOCX and PDF tools](https://img.shields.io/badge/Documents-DOCX%20%7C%20PDF-287c91?style=flat-square)](docs/architecture.md)
[![Isolated Docker or Podman TeX](https://img.shields.io/badge/TeX-Docker%20%7C%20Podman-287c91?style=flat-square)](skills/revayat-scientific/references/pdf-output.md)
[![Codex, Claude Code and Cursor support](https://img.shields.io/badge/Agents-Codex%20%7C%20Claude%20Code%20%7C%20Cursor-287c91?style=flat-square)](docs/installation.md)
[![Optional parallel translation and editing](https://img.shields.io/badge/Parallel-Opt--in-287c91?style=flat-square)](skills/revayat-scientific/references/parallel-work.md)
<br>
[![GitHub stars](https://img.shields.io/github/stars/KiaroSama/Revayat-Scientific-Skill?style=flat-square)](https://github.com/KiaroSama/Revayat-Scientific-Skill/stargazers)
[![Open GitHub issues](https://img.shields.io/github/issues/KiaroSama/Revayat-Scientific-Skill?style=flat-square)](https://github.com/KiaroSama/Revayat-Scientific-Skill/issues)
[![Open pull requests](https://img.shields.io/github/issues-pr/KiaroSama/Revayat-Scientific-Skill?style=flat-square)](https://github.com/KiaroSama/Revayat-Scientific-Skill/pulls)
[![Last main commit](https://img.shields.io/github/last-commit/KiaroSama/Revayat-Scientific-Skill/main?style=flat-square)](https://github.com/KiaroSama/Revayat-Scientific-Skill/commits/main/)
[![Support the project](https://img.shields.io/badge/Support-Donate-ef9b20?style=flat-square)](#donate)

**Translate scientific sources from any language into accurate Persian, preserving page dimensions and image fidelity, with editable output and a verified PDF.**

An agent skill for Claude Code, Claude Desktop, Codex, Kiro, Cursor, Cline,
Hermes, OpenCode, Antigravity and any other agent that can read a `SKILL.md`.
It handles the work around scientific translation: terminology that stays
consistent, claims whose uncertainty survives, figures and equations that
remain accounted for, and Persian pages whose output is actually checked.

<div align="left"><a href="LICENSE">GPL-3.0 licensed</a></div>
<div align="right"><a href="README.fa.md">فارسی</a></div>

---

## What it does that a generic translator does not

| | |
| --- | --- |
| **A source inventory before drafting** | Record sections, figures, tables, equations, notes and references so a missing object cannot be dismissed as a layout choice. |
| **Scientific claims keep their force** | The workflow reviews negation, hedges, quantities and units against the source; fluency edits must preserve their meaning. |
| **One form per concept** | A job-local terms ledger keeps preferred terms consistent. Papers use `journal`; operational guides use `system-docs`. |
| **Source-located term briefs** | A bundled offline command finds approved terms in reviewed text from any source script, records source and glossary hashes, and flags ambiguous choices. |
| **Figures remain source artwork** | Crop and prepare original figures, compare them with source pages, and check the figure manifest before delivery. |
| **Real right-to-left typesetting** | Persian stays in logical order; retained source spans follow their own script direction, with complete formula and number isolates. |
| **Source-aware language and style** | Identify language/script and research uncertain terms. Journal prose uses familiar Persian scientific concepts, with source-language fidelity review. |
| **Page and image fidelity** | Keep physical page/book size, original pixels and aspect ratio; improve poor figures faithfully. Raster crops preserve higher source density above the selected minimum DPI. |
| **Mechanical quality gates** | Check orthography, terminology, isolates, missing images, embedded fonts, page count and sampled rasters. |
| **Text extraction is measured** | Compare normalized Persian source phrases with PyMuPDF extraction; record limits instead of promising every viewer's clipboard behavior. |
| **One portable entry point** | The same Python command chooses PowerShell on Windows and Bash on Linux/macOS, using the current host model for translation. |
| **Built-in DOCX and PDF tools** | Inspect/create/edit DOCX; extract PDF text, tables and images, inspect/fill forms, merge pages and run optional OCR. Preserve originals and untouched document structures. |
| **Optional parallel translation/editing** | Ask before using subagents; separate section ownership, shared terminology, worker logs and coordinator review keep the document consistent. |

## Install

```bash
git clone https://github.com/KiaroSama/Revayat-Scientific-Skill.git
cd Revayat-Scientific-Skill
python -m pip install -r skills/revayat-scientific/requirements.txt
```

Then install the skill into whichever agents you use:

```bash
# macOS / Linux
./install/install.sh

# Windows
powershell -NoProfile -ExecutionPolicy Bypass -File .\install\install.ps1
```

By default this installs into every agent it detects — Claude Code, Codex,
Kiro, Cursor, Cline, Hermes, OpenCode and Antigravity. Use `--agent claude`
for one, or `--scope project --path <dir>` for a project. Both installers
accept the same options and create real copies. Existing installations require
`--force`; a complete replacement is staged first and the previous copy is
retained outside skill discovery. [Host paths and installation details](docs/installation.md).

### As a Claude Code plugin

```text
/plugin marketplace add KiaroSama/Revayat-Scientific-Skill
/plugin install revayat-scientific@revayat-scientific-skill
```

That provides `/translate-paper`, `/revayat-scientific-resume` and
`/revayat-scientific-qa`. Cursor and Codex manifests are included too.
In Codex the skill itself is invoked as `$revayat-scientific`.

### Check the install

**Python 3.10 or newer**, on Linux, macOS or Windows. Prefer an existing
project virtual environment. The installer and text linter use the standard
library; figure processing and PDF extraction checks need the pinned requirements.

```bash
python skills/revayat-scientific/scripts/revayat-scientific.py doctor
```

Read the report before promising a PDF:

| Report item | What it controls |
| --- | --- |
| Docker/Podman + XeLaTeX / xepersian image | Isolated TeX build; see the PDF output setup |
| Edge, Chrome or WeasyPrint | HTML build path when selected |
| Persian font | A readable Persian page; Vazirmatn is the preferred face |
| Poppler and PyMuPDF | PDF page/font/raster inspection and extraction checks |
| Pillow | Figure preparation |

Missing optional tools affect only their stages. Install prerequisites with the
user's approval; the installer and doctor do not install them automatically.

## Use

The agent asks whether to use **parallel subagents for translation and editing**.
This is optional: affirmative consent enables available workers; declining or
leaving it unanswered keeps sequential work. Workers handle separate sections or
review patches, keep their own logs, and the coordinator integrates the document
against one glossary before final checks. Parallel work may use more tokens.
[Parallel workflow and limits](skills/revayat-scientific/references/parallel-work.md).

Tell the agent:

> Translate `paper.pdf` into Persian, preserve its equations and figures, and give me a verified PDF.

Or with the plugin: `/translate-paper ./paper.pdf`.

The agent follows nine stages in `SKILL.md`. Reading, translating, judging
scientific meaning and looking at rendered pages are the agent's work. The
scripts prepare and validate files. No fixed model or translation API is required.

### Or drive it yourself

```bash
PY=python   # or python3; use the same interpreter throughout
SKILL=skills/revayat-scientific
WORK=work

"$PY" "$SKILL/scripts/revayat-scientific.py" doctor
# Preserve the source; write inventory.md, terms.tsv and manifest.txt.
# Translate the document into work/doc.tex, then review its claims and prose.
"$PY" "$SKILL/scripts/revayat-scientific.py" figures "$WORK/figures" --check
"$PY" "$SKILL/scripts/revayat-scientific.py" lint "$WORK/doc.tex" --level journal --terms "$WORK/terms.tsv" --manifest "$WORK/manifest.txt" --strict
"$PY" "$SKILL/scripts/revayat-scientific.py" build "$WORK/doc.tex" article --level journal --output-dir "$WORK/output" --verify
"$PY" "$SKILL/scripts/revayat-scientific.py" text-order "$WORK/output/article.pdf" --source "$WORK/doc.tex"
```

Run the figures command when the job has figures. A figure-free job uses a
comment-only manifest. In PowerShell use `&` before a quoted executable.

**In:** a paper, thesis, technical book or reference supplied as a local file,
attachment, accessible web page or source text. PDFs need text extraction or
an available visual/OCR reader.

**Out:** an editable TeX or HTML source and a verified PDF; reviewed text when
that is what the user requests.

**Source language:** identified from the actual source, including mixed-language
documents. **Target:** scientific Persian. The skill includes researched starting
profiles and a research procedure for other languages; accuracy depends on the
host's language competence and actual source review, not a language-code list.

## Without a shell

An agent can still read the skill and its references, establish terminology,
translate the supplied text and record review findings. File processing,
compilation and PDF verification need an environment able to run the helpers.
Report those stages as unperformed until they actually run; the existence of
Persian text does not establish that a PDF was built.

## How it works

```text
source → inventory → terms → figures → translation
                                      ↓
                        fidelity → fluency → strict lint
                                      ↓
                            build → inspect → deliver
```

One folder holds the distributable skill; repository tooling stays beside it:

```text
commands/                    translate-paper, resume and QA entry points
install/                     shared installer + Bash/PowerShell launchers
skills/revayat-scientific/
  SKILL.md                   ordered stages and decisions
  agents/openai.yaml         Codex discovery metadata
  assets/                    TeX/HTML templates and terms header
  references/                policies loaded by the relevant stage
  scripts/                   portable command and deterministic helpers
tests/                       fixtures and public-command regressions
tools/                       package construction and source validation
docs/                        installation and architecture
```

A translation job keeps its own source, `inventory.md`, `terms.tsv`,
`manifest.txt`, `progress.md` and editable document. A failed lint, build or
requested verification preserves the previous delivered PDF. The output defaults
to `$HOME/Documents/books`; `--output-dir` selects another directory.
[Architecture and responsibilities](docs/architecture.md).

## What it is honest about

- A green mechanical check does not establish scientific accuracy. Meaning and fluency require actual reading.
- Scanned or complex multi-column sources need visual/OCR inspection. Figure cropping is a heuristic and each crop needs comparison with the source.
- Some fonts or HTML renderers produce difficult extracted text. The checker measures normalized PyMuPDF output, not all viewers' clipboard behavior.
- Exact recreation of a publisher's layout is not promised. Scientific content and readable typesetting take priority.
- CI uses synthetic fixtures to verify tooling. It does not evaluate translation quality on an arbitrary paper or automate every host's skill menu.

## Documentation

- [SKILL.md](skills/revayat-scientific/SKILL.md) — the full ordered workflow
- [Translation policy](skills/revayat-scientific/references/translation-policy.md) — translator and reviewer briefs
- [Extraction](skills/revayat-scientific/references/extraction.md) — source inventory and figure handling
- [Source languages](skills/revayat-scientific/references/source-languages.md) — direct translation, language profiles and research
- [Page and image fidelity](skills/revayat-scientific/references/layout-and-images.md) — source dimensions, resolution and faithful enhancement
- [Terminology](skills/revayat-scientific/references/terminology.md) — concept decisions and terminology levels
- [Evidence and terminology](skills/revayat-scientific/references/evidence-and-terminology.md) — local term briefs and source-bound scientific review
- [Scientific style](skills/revayat-scientific/references/scientific-style.md) — clear scholarly Persian
- [RTL and bidi](skills/revayat-scientific/references/rtl-bidi.md) — complete LTR isolates
- [Review](skills/revayat-scientific/references/review.md) — fidelity, fluency and completeness
- [PDF output](skills/revayat-scientific/references/pdf-output.md) — engines, fonts and verification
- [Troubleshooting](skills/revayat-scientific/references/troubleshooting.md) — failures and recovery actions
- [Research evidence](skills/revayat-scientific/references/research-sources.md) — inspected repositories, adopted lessons and limits

## Development

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
bash tests/upstream.sh
python tools/validate.py
python tools/package.py
```

[CI](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml)
covers Python 3.10/Linux, 3.14/macOS and 3.13/Windows, native Windows
rendering, inherited checker regressions, isolated TeX, WeasyPrint and OCR.
Workflow lint/security and Python audits run in CI. CodeQL and dependency review
are configured; Dependabot covers Python packages, Actions and the container base.
The generated `dist/revayat-scientific.skill` is an uploadable ZIP
with its license notices; runtime dependencies stay outside the package.

### Logs

Every agent using the skill must maintain a translation log **beside the translation
file**. It records the stages, terminology decisions, review findings, corrections
and their reasons, check results, errors and final delivery. The agent writes it
with its normal file tools throughout the job, even when no helper script runs.
Each run creates `<translation-stem>_YYYY-MM-DD_HH-mm-ss_UTC.log`; the log accompanies
the delivered translation. See the required logging rule in `SKILL.md`.

The following helper diagnostics are separate from that translation log.
The dispatcher writes UTF-8 logs under the skill's `logs/`; installation and
packaging use the repository's `logs/`. Each run has a new
`<command>_YYYY-MM-DD_HH-mm-ss_UTC.log`, with a unique suffix on collision.
Entries contain UTC time, level, operation, duration and exit code. Document
text, arguments and tool output are not copied into these logs. Initialization
failure falls back to stderr. Logs remain local until removed. Container TeX
scratch files are removed after confirmed cleanup; unresolved cleanup retains
its local recovery evidence and blocks publication.

Native document, figure, font and render helpers write diagnostics under
`scripts/logs/`. `REVAYAT_LOG_LEVEL` selects `DEBUG`, `INFO` (default), `WARNING`
or `ERROR`. Diagnostic decoding tolerates malformed tool output; source documents
and structured reports retain strict format/encoding validation.

## Donate

If this project helps you, donations are appreciated.

| Currency | Network | Address |
| --- | --- | --- |
| Bitcoin (BTC) | Bitcoin | `bc1qmth5m03pu5hujw5xw5jmywam3jj3sqwqupesdt` |
| USDT, BNB, USDC, etc. | BEP20 | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
| USDT, TRX, USDC, etc. | TRC20 | `TWBA3xFTqgZAeAYMxqo85xWnzvty3DcAhw` |
| Ethereum (ETH) | ERC20 | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
| TON | TON | `UQCN8Umo_OfOWqImZetQsrNStPcmLkMAKajFyiCOhso23NDb` |
| Litecoin (LTC) | LTC | `ltc1qntqnnrunadurnw4cshv3qgspywrueyyeyngwuy` |
| Solana (SOL) | Solana | `7B2wkczUjmkDhETwQuknBL8sUsbuV7nErxc317TmQuwR` |
| Polygon (POL) | Polygon | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |

## Author

Author: Kiaro Sama  
GitHub: [KiaroSama](https://github.com/KiaroSama)

## License

[GNU General Public License v3.0 or later](LICENSE). Optional dependencies and
source documents keep their own licenses.
