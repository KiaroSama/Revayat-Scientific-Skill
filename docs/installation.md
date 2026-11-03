# Installation

Build the native executable with the pinned toolchain, or obtain the artifact for your operating system from the CI run of the revision you reviewed. CI artifacts are build outputs, not automatically published releases.

```console
cargo build --locked --release --workspace --bins
cargo run --locked --release --bin revayat-scientific -- install --agent codex
cargo run --locked --release --bin revayat-scientific -- install --scope project --path /path/to/project
cargo run --locked --release --bin revayat-scientific -- install --dest /path/to/final/revayat-scientific
```

Installed commands reside in `bin/revayat-scientific`, or `bin/revayat-scientific.exe` on Windows. The executable is self-contained with its Rust dependencies; Windows CI also links the C runtime statically. Optional native document/rendering tools are separate. A source plugin checkout needs a compiled executable before command checks can run.

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

The ZIP root is `revayat-scientific/`. It includes the exact native executable, skill instructions, references, allowed assets, agent metadata, GPL license and notices. Executable ZIP permission bits are retained for Unix extraction; use an extractor that preserves them. Choose the archive built on the target operating system. Fonts, job data, logs, credentials, hidden files and build caches are excluded. Font delivery is a separate licensed/provenance-checked operation.

Do not install or publish over source, implementation or Git administration. Failed publication preserves the previous approved archive; unresolved installation recovery names the complete local journal and retains evidence for deliberate recovery.
