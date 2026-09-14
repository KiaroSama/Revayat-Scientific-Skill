# Revayat Scientific — روایت علمی

**Translate a scientific paper into accurate Persian, and receive an editable source and a verified, printable PDF.**

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
| **Figures remain source artwork** | Crop and prepare original figures, compare them with source pages, and check the figure manifest before delivery. |
| **Real right-to-left typesetting** | Persian stays in logical order. Complete English, formula and number clusters stay in LTR isolates. |
| **Mechanical quality gates** | Check orthography, terminology, isolates, missing images, embedded fonts, page count and sampled rasters. |
| **Text extraction is measured** | Compare normalized Persian source phrases with PyMuPDF extraction; record limits instead of promising every viewer's clipboard behavior. |
| **One portable entry point** | The same Python command chooses PowerShell on Windows and Bash on Linux/macOS, using the current host model for translation. |

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
| XeLaTeX / xepersian | Preferred TeX build path |
| Edge, Chrome or WeasyPrint | HTML build path when selected |
| Persian font | A readable Persian page; Vazirmatn is the preferred face |
| Poppler and PyMuPDF | PDF page/font/raster inspection and extraction checks |
| Pillow | Figure preparation |

Missing optional tools affect only their stages. Install prerequisites with the
user's approval; the installer and doctor do not install them automatically.

## Use

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

**Source language:** English by default. **Target:** scientific Persian.

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
- [Terminology](skills/revayat-scientific/references/terminology.md) — concept decisions and terminology levels
- [Scientific style](skills/revayat-scientific/references/scientific-style.md) — clear scholarly Persian
- [RTL and bidi](skills/revayat-scientific/references/rtl-bidi.md) — complete LTR isolates
- [Review](skills/revayat-scientific/references/review.md) — fidelity, fluency and completeness
- [PDF output](skills/revayat-scientific/references/pdf-output.md) — engines, fonts and verification
- [Troubleshooting](skills/revayat-scientific/references/troubleshooting.md) — failures and recovery actions

## Development

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
bash tests/upstream.sh
python tools/validate.py
python tools/package.py
```

[CI](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml)
covers Python 3.10/Linux, 3.14/macOS and 3.13/Windows, native Windows
rendering, inherited checker regressions and a real Linux XeLaTeX build.
CodeQL and dependency review are configured; Dependabot covers Python packages
and Actions. The generated `dist/revayat-scientific.skill` is an uploadable ZIP
with its license and attribution; runtime dependencies stay outside the package.

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
failure falls back to stderr. Logs remain local until removed. TeX also keeps
its document log beside the source.

## Credits

Based on [isArman's scientific Persian translation skill](https://github.com/isArman/scientific-fa-translation-skill),
with its original MIT attribution retained in [NOTICE](skills/revayat-scientific/NOTICE.md).
[Revayat Comic](https://github.com/KiaroSama/Revayat-Comic-Skill) and
[Revayat Novel](https://github.com/KiaroSama/Revayat-Novel-Skill) supply the family
structure and presentation conventions.

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

[GNU General Public License v3.0 or later](LICENSE). Original scientific
upstream MIT attribution is retained. Optional dependencies and source documents
keep their own licenses.
