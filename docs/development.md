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

Build all binaries with `cargo build --locked --workspace --bins` before invoking
development commands: Unix commands require adjacent `revayat-process-owner`, and
Windows packages require adjacent `revayat-quota-worker.exe` for the fixed native
quota and kernel-control roles. Building only the CLI with `cargo run` does not build its platform
sibling. The status-publishing CI jobs explicitly build workspace binaries.
Development and test profiles use level-one
optimization for bounded parsing and repeated payload hashing, and strip symbols
so the combined native payload remains under its unchanged 64 MiB admission
limit. To debug with symbols, use a separate Cargo profile; that executable
may exceed the installable payload limit.

CI executes those built binaries directly. Repeated `cargo run` invocations
can select a different dependency feature union from `--all-targets` and trigger
unnecessary recompilation, including during cancellation cleanup. Release test
collection uses the release runner and adjacent release process owner, so a debug
build failure cannot make it borrow a missing debug companion.
Release harnesses use ordinary optimized linking without per-harness LTO. This
keeps compilation of the complete frozen inventory inside the collection deadline;
the release binaries and release tests still use the same release profile.

The pinned Rust 1.100 toolchain places test harnesses under
`target/<profile>/build/<package>/<hash>/out`. Discovery uses Cargo's actual
compiler-artifact JSON and verifies the requested profile and workspace manifest.
The legacy `deps`/`examples` layout remains recognized explicitly. Final executable
paths stay at `target/<profile>`; fixed companions resolve to that same profile,
without searching arbitrary ancestors. Separate custom intermediate build roots
are refused by this collector rather than admitted as unrelated target artifacts.
Path-adversarial fixtures resolve only their newly created, empty temporary root
before creating test inputs. This supports macOS's system temporary-directory
alias while retaining production rejection of linked inputs and linked ancestors.

The Gitleaks workflow added on main is retained with a Rust controller and native
Git adapter. It verifies the pinned scanner archive, captures scanner output
privately, checks the actual Git history child's completion receipt, and publishes
location-only findings. PR ranges and complete fetched history remain distinct;
missing receipts, scanner errors and inconsistent reports cannot become clean scans.

## Hosted checks

CI runs for pushes, pull requests and manual dispatch. No path filter exempts
documentation changes from builds. The portable matrix builds every debug target
and every release binary on Linux, macOS and Windows. It retains separate debug
and release execution reports and native executable/skill artifacts. Scientific,
Linux/Windows security, Rust CodeQL, dependency review and quality jobs remain
required. Report aggregation must refuse missing, failed or contradictory evidence.
The obsolete artifact-only dispatch mode is removed, so manual runs also execute
the three-platform build matrix, execution reports and final statuses.

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
Native collector regressions extend the existing collector contract test, keeping
the reference branch's test registration count while exercising the added checks.

## Outstanding acceptance gates

The native collector executes the Windows native and standalone harnesses with
exact, nonignored case selection. On Linux it runs the production containment
probe and isolated worker, then records every actual worker outcome only after
the fixed preflight and owned cleanup succeed. Missing, duplicate, reordered or
failed case results cannot be replaced by a successful summary. These are flat
case reports. Engine discovery and runtime preparation now execute their original
six cases and nineteen requirement sites in existing carrier registrations. Like
the registry oracle, each writes observations only after its assertions complete;
the supervisor binds them to the actual passing carrier, run, census digest and
completed outer cleanup. Debug and release reports remain separate on each OS.
The native-stage and coverage censuses still contain unresolved source/evidence
contracts, including the full ordered Windows diagnostic bootstrap. Implemented
stage helpers remain explicitly unverified until their required native execution
and relationships have been observed.
Those gaps must be implemented and actually run before claiming complete parity
or an all-green migration. The aggregate is kept blocking; it is not replaced by
registration counts or fabricated successful events.

Upstream discovery and the documents actually reviewed are recorded in
[research sources](../skills/revayat-scientific/references/research-sources.md)
and its linked revision inventory. External document engines retain their own
implementations and licenses. This checkout contains no separate web application
or Cloudflare Worker source tree; HTML document templates remain document assets.
