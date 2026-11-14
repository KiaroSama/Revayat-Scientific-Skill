# Installation

These native instructions apply to `rewrite/rust-complete`; the default `main` checkout is not yet the completed Rust rewrite. Use the exact reviewed rewrite revision and matching successful hosted CI artifacts for your operating system. Current rewrite package/install acceptance is still being verified; historical or partial CI results do not certify a new revision. CI artifacts are intermediate build outputs, not automatically published or signed final releases.

```console
git clone --branch rewrite/rust-complete https://github.com/KiaroSama/Revayat-Scientific-Skill.git
cd Revayat-Scientific-Skill
cargo build --locked --release --workspace --bins
cargo run --locked --release --bin revayat-scientific -- install --agent codex
cargo run --locked --release --bin revayat-scientific -- install --scope project --path /path/to/project
cargo run --locked --release --bin revayat-scientific -- install --dest /path/to/final/revayat-scientific
```

Installed commands reside in `bin/revayat-scientific`, or `bin/revayat-scientific.exe` on Windows. Linux/macOS also require executable `bin/revayat-process-owner` beside the main program. Windows packages require adjacent `bin/revayat-quota-worker.exe`, the fixed native quota and kernel-control worker. Keep each platform's files together from the same build and revision; do not copy only the main program or mix artifacts. Rust dependencies are compiled into these binaries; external document/rendering tools are separate.

Build with `--workspace --bins` before using a source checkout or plugin. `cargo run --bin revayat-scientific` selects the main binary, not a rebuild of every sibling. The Unix companion has a private runtime protocol, not a user document-processing command. Missing, linked or nonregular companion files cause refusal before install/package publication; runtime also refuses an absent companion rather than spawning an unowned fallback. These checks do not authenticate a signed release or enforce a same-version handshake.

| Host | User skill directory | Project skill directory |
| --- | --- | --- |
| Claude Code | `~/.claude/skills` | `.claude/skills` |
| Codex | `~/.agents/skills` | `.agents/skills` |
| Cursor | `~/.cursor/skills` | `.cursor/skills` |
| Kiro | `~/.kiro/skills` | `.kiro/skills` |
| Cline | `~/.cline/skills` | `.cline/skills` |
| Hermes | `~/.hermes/skills` | `.hermes/skills` |
| OpenCode | `~/.config/opencode/skills` | `.opencode/skills` |
| Antigravity | `~/.gemini/config/skills` | `.agents/skills` |

`--agent all` is the default and installs only into detected host configuration roots; explicit `--agent` may create its directory. A Codex `.codex` configuration also counts as detection. Shared destinations are deduplicated. Project scope requires `--path`. `--dest` names the final skill directory, not its parent. Installation does not edit host configuration or install system dependencies.

Existing destinations are refused without `--force`. Force replacement requires an empty directory or a simple, unambiguous `name: revayat-scientific` frontmatter identity. Duplicate keys, ambiguous continuations, foreign contents, linked trees and reserved recovery/backup locations are refused. Every target is staged and checked before activation. Old editions remain in `skill-backups` outside ordinary skill discovery. See [installation integrity](installation-integrity.md).

## Plugin hosts

```text
/plugin marketplace add KiaroSama/Revayat-Scientific-Skill
/plugin install revayat-scientific@revayat-scientific-skill
```

The Claude Code plugin exposes `/translate-paper`, `/revayat-scientific-resume` and `/revayat-scientific-qa`. Codex and Cursor manifests use the same Rust-oriented skill instructions. In Codex invoke `$revayat-scientific`.

## Complete archive

```console
cargo run --locked --release --bin revayat-scientific -- package --output dist/revayat-scientific.skill
```

The ZIP root is `revayat-scientific/`. It includes the collected native main executable and its required platform sibling: `bin/revayat-process-owner` on Linux/macOS or `bin/revayat-quota-worker.exe` on Windows. It also contains skill instructions, eligible references/assets/agent metadata, `LICENSE` and `NOTICE.md`. ZIP entries use Unix creator metadata, `0755` for `bin/` and `0644` for data; use an extractor that preserves executable bits. Choose the archive for the target operating system and architecture. Collection refuses payloads above 64 MiB and bounds source-tree entries/files; the staged archive is reopened and checked against exact collected members, sizes and hashes before recoverable publication.

Packaging does not bundle external engines, installed fonts, job data, logs, credentials, hidden files or build caches. Font delivery is a separate licensed/provenance-checked operation. HTML rendering uses a sandboxed Chromium-family browser or the actual optional WeasyPrint engine inside the supported Linux Docker/Podman image. TeX uses that image with effective resource controls and a finite aggregate output tmpfs. External WeasyPrint/Python image packages do not require host Python or owned Python scripts. Poppler provides required PDF verification/extraction; OCR needs Tesseract language data and independent DOCX rendering needs LibreOffice. Installers do not provision these tools.

The WeasyPrint adapter admits a closed static resource view. It refuses `srcset`
and `imagesrcset`, XML stylesheet processing instructions, ambiguous SVG style
markup/entities, incompatible text encodings and CSS expressions that synthesize
external resource URLs. Ordinary local HTML, CSS, fonts, images, SVG references
and bounded data resources pass through the same checked resource policy. Resolve
unsupported resource syntax in the source before selecting this backend.

Installed/extracted CLI, companion byte/mode/version and real-document regressions are authored but remain unexecuted in this source checkpoint. Neither archive construction nor `doctor` discovery establishes successful document output, effective containment or signed-release trust.

Do not install or publish over source, implementation or Git administration. Failed publication preserves the previous approved archive; unresolved installation recovery names the complete local journal and retains evidence for deliberate recovery.
