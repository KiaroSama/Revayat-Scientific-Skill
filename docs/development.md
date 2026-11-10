# Rust development and migration verification

The migration continues `rewrite/rust-native` at commit
`8801758f1bf857e750e15c64635281973986ad39` on `rewrite/rust-complete`.
The default branch remains unchanged until the migration PR is reviewed and merged.

## Local checks

Install the toolchain selected by `rust-toolchain.toml`, then run from the repository:

```console
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --workspace --all-targets
cargo test --locked --workspace --all-targets --no-fail-fast -- --test-threads=1
cargo build --locked --release --workspace --bins
cargo run --locked --bin revayat-scientific -- migration-check
cargo run --locked --bin revayat-scientific -- validate
```

Build all binaries before invoking development commands: Unix commands require
the adjacent `revayat-process-owner`. Building only the CLI with `cargo run`
does not build that companion. The status-publishing CI jobs explicitly build
both binaries for this reason. Development and test profiles use level-one
optimization for bounded parsing and repeated payload hashing, and strip symbols
so the combined native payload remains under its unchanged 64 MiB admission
limit. To debug with symbols, use a separate Cargo profile; that executable
may exceed the installable payload limit.

## Hosted checks

CI runs for pushes, pull requests and manual dispatch. No path filter exempts
documentation changes from builds. The portable matrix builds every debug target
and every release binary on Linux, macOS and Windows. It retains separate debug
and release execution reports and native executable/skill artifacts. Scientific,
Linux/Windows security, Rust CodeQL, dependency review and quality jobs remain
required. Report aggregation must refuse missing, failed or contradictory evidence.

For pull requests, execution reports describe the checked-out GitHub merge
revision, while commit statuses target the PR head revision reported by the
Actions run. Base selection uses the PR base SHA, the push's previous SHA or
the explicitly supplied manual base. New-branch pushes resolve their zero base
against the default branch. Executable arguments use environment variables
instead of interpolating event text into shell commands.

The historical public census retains 583 IDs; separate inventories retain 37
upstream cases, 41 standalone security leaves and 14 verifier cases. Changing a
trigger or fixing a fixture does not remove a baseline case. The migration maps
are a registration audit, and the execution aggregate is a separate acceptance
gate. A passing build alone does not establish behavioral parity.

## Outstanding acceptance gates

The native collector executes the Windows native and standalone harnesses with
exact, nonignored case selection. On Linux it runs the production containment
probe and isolated worker, then records every actual worker outcome only after
the fixed preflight and owned cleanup succeed. Missing, duplicate, reordered or
failed case results cannot be replaced by a successful summary. These are flat
case reports, not fabricated bootstrap markers. The native-stage,
runtime-preparation, engine and coverage censuses still contain unresolved
source/evidence contracts.
Those gaps must be implemented and actually run before claiming complete parity
or an all-green migration. The aggregate is kept blocking; it is not replaced by
registration counts or fabricated successful events.

Upstream discovery and the documents actually reviewed are recorded in
[research sources](../skills/revayat-scientific/references/research-sources.md)
and its linked revision inventory. External document engines retain their own
implementations and licenses. This checkout contains no separate web application
or Cloudflare Worker source tree; HTML document templates remain document assets.
