# Revayat Scientific — روایت علمی

<div align="center">

[![CI status on main](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml)
[![CodeQL status on main](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/codeql.yml)
[![GPL-3.0-or-later license](https://img.shields.io/badge/License-GPL--3.0--or--later-blue?style=flat-square)](LICENSE)
[![Plugin version 2.0.0](https://img.shields.io/badge/Plugin-2.0.0-blue?style=flat-square)](.codex-plugin/plugin.json)
<br>
[![Rust 1.99.1](https://img.shields.io/badge/Rust-1.99.1-dea584?style=flat-square&logo=rust)](rust-toolchain.toml)
[![Windows, macOS and Linux](https://img.shields.io/badge/Platforms-Windows%20%7C%20macOS%20%7C%20Linux-287c91?style=flat-square)](.github/workflows/ci.yml)
[![English and Persian docs](https://img.shields.io/badge/Docs-EN%20%7C%20FA-6f42c1?style=flat-square)](README.fa.md)
[![Agent Skills format](https://img.shields.io/badge/Format-Agent%20Skills-6f42c1?style=flat-square)](skills/revayat-scientific/SKILL.md)
<br>
[![Installable skill ZIP](https://img.shields.io/badge/Package-.skill%20ZIP-6f42c1?style=flat-square)](docs/installation.md)
[![Any source language to Persian](https://img.shields.io/badge/Languages-Any%20source%20to%20Persian-287c91?style=flat-square)](skills/revayat-scientific/references/source-languages.md)
[![Native DOCX and PDF tools](https://img.shields.io/badge/Documents-DOCX%20%7C%20PDF-287c91?style=flat-square)](docs/architecture.md)
[![Isolated Docker or Podman TeX](https://img.shields.io/badge/TeX-Docker%20%7C%20Podman-287c91?style=flat-square)](skills/revayat-scientific/references/pdf-output.md)
<br>
[![Codex, Claude Code and Cursor support](https://img.shields.io/badge/Agents-Codex%20%7C%20Claude%20Code%20%7C%20Cursor-287c91?style=flat-square)](docs/installation.md)
[![GitHub stars](https://img.shields.io/github/stars/KiaroSama/Revayat-Scientific-Skill?style=flat-square)](https://github.com/KiaroSama/Revayat-Scientific-Skill/stargazers)
[![Support donations](https://img.shields.io/badge/Support-donations-d04a9a)](#donate)

</div>

**Translate scientific sources from any language into accurate Persian with editable sources, preserved document objects and a verified PDF.**

Revayat is an agent skill and a native Rust executable. The host agent performs translation and scientific review; the executable handles document integrity, terminology, figures, typesetting and delivery. It supports Codex, Claude Code, Cursor, Kiro, Cline, Hermes, OpenCode, Antigravity and hosts that can read `SKILL.md`.

[فارسی](README.fa.md)

## What it does that a generic translator does not

| Contract | Behavior |
| --- | --- |
| Scientific fidelity | Inventory claims, uncertainty, negation, quantities, equations, figures and references before drafting. |
| Consistent terminology | Use a job-local TSV ledger and source-located term briefs; select `journal` or `system-docs`. |
| Persian typography | Preserve logical Unicode order, RTL paragraphs and complete LTR isolates. |
| Native document operations | Inspect and edit bounded DOCX/OPC packages and PDF objects while checking untouched structures. |
| Figures and geometry | Preserve original artwork, page boxes, pixels, aspect ratio and crop density. |
| Verified delivery | Run source lint, font/page checks, text-order checks and real raster/render comparisons. |
| Recoverable publication | Stage all outputs or installations, retain exact previous editions and preserve recovery evidence on unresolved failure. |

## Preparation snapshot status

This `rewrite/rust-native` snapshot adds hosted lock/notices preparation, not a completed migration or verified release. The badges describe `main`, not this revision. Full native parity and final exact-head CI remain unverified.

Linux/macOS tool invocations require `revayat-process-owner` beside the executable, from the same build/revision. Build all binaries with `cargo build --locked --release --workspace --bins`; `cargo run --bin revayat-scientific` alone does not rebuild its sibling. Windows retains native Job ownership. Companion-aware package/install changes are not included in this preparation snapshot; do not assume its `.skill` archive is a complete Unix runtime payload. External document engines remain separate.

For approved hosted preparation, select the existing CI workflow on the reviewed rewrite revision, provide full `base_ref` and set `prepare_artifacts=true` (default `false`). Artifact `prepared-lock-notices-<sha>-<run_id>-<attempt>` contains only `Cargo.lock` and `skills/revayat-scientific/references/third-party-licenses.txt`. Verify exact membership and run/revision/attempt before import. Ordinary validation/status jobs do not run in this mode; preparation success is not full CI or migration acceptance. See [installation](docs/installation.md).

## Install

Install the [pinned Rust toolchain](https://rustup.rs/) to build from source:

```console
git clone https://github.com/KiaroSama/Revayat-Scientific-Skill.git
cd Revayat-Scientific-Skill
cargo build --locked --release --workspace --bins
cargo run --locked --release --bin revayat-scientific -- install --agent codex
```

Use `--agent all` for detected hosts, `--scope project --path <directory>` for a project, or `--dest <final-skill-directory>` for another host. Existing installations require `--force` and an unambiguous Revayat identity. All targets are staged before activation; previous copies remain in `skill-backups`. See [installation](docs/installation.md).

The executable and `.skill` archive are CI artifacts for Linux, macOS and Windows. A native archive contains the executable, `SKILL.md`, references, templates, license and notices. Rust is needed to compile from source; an installed executable needs no language interpreter.

Claude Code plugin installation:

```text
/plugin marketplace add KiaroSama/Revayat-Scientific-Skill
/plugin install revayat-scientific@revayat-scientific-skill
```

The plugin exposes `/translate-paper`, `/revayat-scientific-resume` and `/revayat-scientific-qa`. Invoke `$revayat-scientific` in Codex. A source plugin checkout must first build the executable or use a matching CI artifact.

## Use

From the repository, prefix commands with `cargo run --locked --release --bin revayat-scientific --`. In an installed skill, use `bin/revayat-scientific` (`bin/revayat-scientific.exe` on Windows).

```console
revayat-scientific doctor
revayat-scientific fonts job/fonts
revayat-scientific term-brief job/source.txt --terms job/terms.tsv --language en
revayat-scientific lint job/doc.tex --level journal --terms job/terms.tsv --manifest job/manifest.txt --strict
revayat-scientific build job/doc.tex --out delivery/article.pdf --engine tex --level journal --verify
revayat-scientific text-order delivery/article.pdf --source job/doc.tex
revayat-scientific docx --help
revayat-scientific pdf --help
```

Use `--help` on each command for its exact schema. Keep job sources, ledgers, figures and translation logs outside the installed skill. Obtain consent before delegating translation to additional agents. Record source language, intended readership, selected terminology level and actual checks in the job log.

| Optional native tool | Required use |
| --- | --- |
| Sandboxed Chrome/Chromium/Edge | HTML rendering through the native DevTools client |
| Docker or Podman with effective limits | Isolated TeX builds; native host XeLaTeX does not replace this boundary |
| Poppler | PDF text/font/raster verification and supported extraction |
| Tesseract with selected language data | Optional OCR |
| LibreOffice Writer | Independent DOCX rendering in scientific CI |

## Without a shell

Give the host agent this repository or the generated `.skill` archive, then ask it to follow all nine stages in [SKILL.md](skills/revayat-scientific/SKILL.md). A host with file tools can translate and maintain ledgers; executable checks require an available native executable and their listed external tools. Report unavailable checks accurately.

## How it works

The nine stages are tool readiness, extraction, terminology, object preparation, translation, scientific/fluency review, typography/lint, build/verification and inspection/delivery. Translation uses the host model. Rust modules provide the common source model, bounded parsers, CLI, process ownership, DOCX/PDF operations, renderer controls, installers and CI tools. See [architecture](docs/architecture.md).

## What it is honest about

Mechanical checks do not certify scientific accuracy, every PDF viewer, arbitrary OOXML/PDF extensions or hostile kernel isolation. Unsupported/encrypted/signed structures may be refused before transformation. Source-preserving checks and cooperative locks detect specific races; a directory transaction is recoverable rather than globally atomic. A failed or unavailable containment prerequisite must fail its required CI tier.

## Documentation

- [Installation and native packaging](docs/installation.md)
- [Architecture](docs/architecture.md)
- [Installation integrity](docs/installation-integrity.md)
- [Security testing](docs/security-testing.md)
- [Nine-stage skill](skills/revayat-scientific/SKILL.md)
- [PDF output](skills/revayat-scientific/references/pdf-output.md)
- [DOCX](skills/revayat-scientific/references/docx.md) and [PDF operations](skills/revayat-scientific/references/pdf-processing.md)

## Development

```console
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --workspace --all-targets
cargo test --locked --workspace --all-targets -- --test-threads=1
cargo run --locked --bin revayat-scientific -- migration-check
cargo run --locked --bin revayat-scientific -- validate
cargo run --locked --release --bin revayat-scientific -- package
```

The migration inventory maps all 583 original public tests to registered Rust scenarios. Separate censuses also preserve all 37 standalone upstream scientific checks and 41 standalone security cases, including the independent Windows OPC consumer and real junction callers. Native rendering tests carry explicit prerequisite descriptions and are executed with `--include-ignored` in the equipped scientific tier. CI retains the Linux and Windows security tiers, CodeQL, dependency review, all three portable jobs, scientific rendering, quality and truthful aggregate reporting. Every portable job also builds a release executable and uploads its native archive. Dependabot tracks Cargo, Actions and the TeX container base; strict Cargo audit, rustfmt, Clippy, actionlint and zizmor remain required.

Keep a translation log beside each document throughout all nine stages. The CLI separately writes content-free UTC operation logs to `./logs` (`REVAYAT_LOG_DIR` overrides the location; `REVAYAT_LOG_LEVEL` accepts `DEBUG`, `INFO`, `WARNING`, `ERROR`). Records contain only the command category, exit category/code and duration, without arguments, tool output or private paths. Diagnostics and unresolved recovery journals stay local. See the skill for required delivery records.

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
