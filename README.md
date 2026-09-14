# Revayat Scientific — روایت علمی

[فارسی](README.fa.md) · [Skill](skills/revayat-scientific/SKILL.md)

[![CI](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml/badge.svg)](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-green.svg)](LICENSE)

An agent skill that translates scientific papers, theses, technical books and documentation into accurate Persian and prepares reviewed RTL PDFs. It follows the Revayat family layout: one self-contained skill, plugin metadata, native installers and English/Persian documentation.

## What it does

| Capability | Behavior |
| --- | --- |
| Scientific fidelity | Preserve claims, uncertainty, units, equations, citations and references |
| Terminology | Record one preferred form per concept; distinguish papers from operational documentation |
| Persian quality | Formal readable prose, with explicit fidelity and fluency review |
| Print output | XeLaTeX first; HTML fallback; check visual layout and extraction order separately |
| Portability | Windows, macOS and Linux; current host model, no fixed provider or API key |

## Install

Python 3.10+ is required for executable helpers. Installation itself and mechanical checks use the standard library. Optional figure/PDF extraction dependencies are pinned separately.

```bash
git clone https://github.com/KiaroSama/Revayat-Scientific-Skill.git
cd Revayat-Scientific-Skill
python -m pip install -r skills/revayat-scientific/requirements.txt

# Linux / macOS
bash install/install.sh
```

```powershell
# Windows: PowerShell 5.1 or 7
powershell -NoProfile -ExecutionPolicy Bypass -File ./install/install.ps1
```

Both installers accept identical arguments. The default installs into detected agents. Select `--agent codex`, `--agent claude`, or another supported host. Project installation is explicit:

```bash
python install/install.py --agent codex --scope project --path "/path/to/project"
```

Existing copies require `--force`; replacement stages a complete new copy and retains the old directory as a backup. No dependencies or agent configuration are changed automatically. [Host paths and packaging](docs/installation.md).

### As a plugin

```text
/plugin marketplace add KiaroSama/Revayat-Scientific-Skill
/plugin install revayat-scientific@revayat-scientific-skill
```

The repository carries Claude Code, Cursor and Codex plugin manifests. Hosts that read `SKILL.md` can also install the payload directly. Claude Desktop or another upload-based host can use the `.skill` package produced by `python tools/package.py`. Host UI discovery is separate from the tested package layout.

## Use

Ask your agent:

> Use revayat-scientific to translate this paper into Persian, preserve its equations and figures, and give me a verified PDF.

Explicit invocation in Codex is `$revayat-scientific`; other hosts may use `/revayat-scientific`. Sources can be local files, attachments or accessible URLs. The agent translates and reviews; scripts do mechanical work. No cloud translation provider is required.

### Drive the helpers

```bash
python skills/revayat-scientific/scripts/revayat-scientific.py doctor
python skills/revayat-scientific/scripts/revayat-scientific.py lint work/doc.tex --level journal --terms work/terms.tsv --manifest work/manifest.txt --strict
python skills/revayat-scientific/scripts/revayat-scientific.py build work/doc.tex article --level journal --verify --output-dir work/output
```

The same arguments work on all three operating systems. `build --help` explains options; `crop`, `figures`, `pages`, `fonts` and `text-order` expose the underlying helpers. Use a separate job directory and preserve original sources. `terms.tsv` and `manifest.txt` are required by strict checking. A figure-free document uses a comment-only manifest.

## How it works

Source inventory → terminology → figures → section translation → fidelity/fluency review → strict checks → PDF build → visual inspection → delivery.

The skill supplies TeX/HTML templates, terminology rules and review briefs. For long documents it keeps a section ledger and unresolved questions. It records whether review was independent or a separate pass by the same model.

PDF output defaults to `$HOME/Documents/books`; `--output-dir` overrides it. A failed lint, build or requested verification preserves the previous delivered PDF. `--verify` needs Poppler and PyMuPDF and produces first/middle/last samples. The agent must actually inspect those images.

## Limits

- A green checker does not prove scientific accuracy; translation and semantic review are model work.
- Scanned or complex multi-column PDFs need an available visual reader/OCR and comparison with original pages. Figure cropping is a heuristic that requires visual confirmation.
- HTML renderers can show correct RTL while storing reversed copy-paste text. XeLaTeX is preferred; text-order checks report what PyMuPDF extracted, not every viewer's clipboard behavior.
- No exact recreation of a publisher's page layout is promised. Preserve scientific content and readable typesetting.
- CI fixtures exercise the tools, not translation quality on an arbitrary research paper. Individual host UI activation is not automated.

## Logs

The dispatcher writes UTF-8 logs under `skills/revayat-scientific/logs/`; installation and packaging write under root `logs/`. Names are `<command>_YYYY-MM-DD_HH-mm-ss_UTC.log`, with a unique suffix on a collision. Entries use UTC time, level and component. Logs contain operation names, duration and exit codes; source text, command arguments and tool output are not copied into them. A logging initialization failure falls back to stderr. Logs are local and retained until you remove them. TeX also writes its own document log beside the source.

## Documentation

- [Skill workflow](skills/revayat-scientific/SKILL.md) and [architecture](docs/architecture.md)
- [Installation](docs/installation.md)
- [Terminology](skills/revayat-scientific/references/terminology.md)
- [Scientific style](skills/revayat-scientific/references/scientific-style.md)
- [Review and PDF verification](skills/revayat-scientific/references/review.md)

## Development

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
bash tests/upstream.sh
python tools/validate.py
python tools/package.py
```

CI covers Python 3.10/Linux, 3.14/macOS and 3.13/Windows, native Windows rendering, inherited checker regressions and a real Linux XeLaTeX build. Tests use disposable job directories, explicit timeouts and synthetic fixtures. Runtime dependencies remain outside the skill archive. The package includes GPL-3.0 and the original MIT attribution.

## Credits

Based on [isArman/scientific-fa-translation-skill](https://github.com/isArman/scientific-fa-translation-skill), retaining its scientific policies, deterministic helpers and MIT attribution. See [NOTICE](skills/revayat-scientific/NOTICE.md). [Revayat Comic](https://github.com/KiaroSama/Revayat-Comic-Skill) and [Revayat Novel](https://github.com/KiaroSama/Revayat-Novel-Skill) provide the family packaging conventions.

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

Kiaro Sama - [GitHub](https://github.com/KiaroSama)

## License

[GPL-3.0-or-later](LICENSE), with the scientific upstream MIT notice retained. Optional dependencies and source documents retain their own licenses.
