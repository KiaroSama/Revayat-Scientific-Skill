# Native security regression tiers

Security observations use the Rust production boundary and finite disposable fixtures. They are not a certification of arbitrary documents, operating systems or hostile kernels. Required native controls must be observed before dependent scenarios; unavailable containment is failure, not a passing skipped body.

## Linux

The `security / linux-security` job builds the Rust-supervised TeX image and invokes `revayat-scientific security-linux`. It verifies the production TeX boundary, then uses a separate helper boundary with a read-only public worker view, 128 MiB scratch, a 64 MiB file limit, exact environment, read-only device storage and effective kernel controls. The image-owned trusted helper must pass before it executes `/target/security-worker` with no arguments. The worker needs no repository checkout or interpreter inside the boundary.

The fixed worker runs all 30 authored admissions and six TeX output checks, including HTML work-budget refusal through every caller, source/delivery preservation, restricted relationship aliases and a real harmless XeLaTeX producer with two output files. Native stdout and lint children have strict byte and time limits; worker logs and caches remain in scratch. Missing evidence, unavailable prerequisites or ineffective isolation fails the gate. The helper's aggregate scratch quota is not claimed for the production writable output bind: its aggregate output quota remains explicitly **unresolved**.

The native owner must enforce process-tree cleanup, memory/process limits, filesystem admission and network restrictions. Rootless engines with ineffective limits fail. Browser tests retain the normal Chromium sandbox and reject unavailable sandbox prerequisites.

## Windows

The Windows security job builds every workspace target first, invokes the fixed authority gate, then runs the native contracts and independent Rust registry oracle:

```console
cargo build --locked --workspace --all-targets
target/debug/revayat-scientific.exe security-windows --authority-image target/debug/registry-authority.exe
cargo test --locked --workspace --all-targets -- --test-threads=1
```

Normal native tool execution uses its process ownership/job controls. The separate registry authority gate requires actual restricted primary and descendant LPAC evidence for its fixed fixture. Its scope includes private scratch read/write, foreign-file denial, read-only root/private-child policy, registry/token/job observations and native reparse/junction contracts. It does not make normal user tools run under an undocumented universal LPAC wrapper.

See [the Windows migration and scope record](windows/MIGRATION.md) for the exact native authority fixture and the explicitly retired exploratory implementations. Previous machine ACL, SideBySide/VHD/ETW/CSR experiments are not claimed as current executable coverage. No interpreter bootstrap, ordinary unrestricted fallback or missing-proof admission may substitute for the actual native gate.

## Scientific evidence and inventory

The equipped scientific tier executes all required rendering/OCR/TeX/browser/LibreOffice test bodies with `--include-ignored`. Portable CI alone does not claim those prerequisites ran. [The migration baseline](../migration-baseline.json) and [Rust mappings](../rust-migration-map.json) retain the original public scenario inventory. The [standalone security baseline](../security-baseline.json) and [security Rust mappings](../security-rust-migration-map.json) separately retain 36 fixed helper checks and five native Windows standalone caller/oracle checks which were outside both the 583-method and 37-shell-check censuses. Thirty-three shared helper contract tests run portably; the three real XeLaTeX test bodies run in the equipped tier, and the mandatory isolated worker executes all 36 without a skipped body. The five Windows leaves use the native OPC consumer and real NTFS junction/public caller fixtures in the required Windows job. Portable admission results alone do not attest native containment. Tests observe supported behavior, failure preservation and bounded resource policies; meaningful coverage must not disappear when implementation experiments are removed.

Keep source text, private paths, tokens and raw credential-bearing diagnostics out of published evidence. Unresolved local recovery journals retain the paths and identities needed for deliberate recovery and must not be uploaded as release artifacts.
