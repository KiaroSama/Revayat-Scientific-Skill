# Native security testing

Security checks are required observations of the production boundary. A missing control, unavailable native prerequisite, failed ordinary control or interrupted cleanup must fail its required tier. A finite scenario ledger is not a security certification.

## Linux

The Linux security job builds the production TeX image and executes the native `security-linux` gate. It must observe effective memory, process, network, filesystem and process-tree controls before accepting the corresponding scenarios. The Rust container entrypoint uses fixed XeLaTeX arguments and bounded output; native host TeX is not an isolation fallback. Rootless Docker with ineffective limits must be reported as unavailable containment.

Browser rendering uses the normal Chromium sandbox. A broken setuid helper or unsupported user namespace is a prerequisite failure. Do not add `--no-sandbox` to turn a required browser test green. Native renderer tests exercise actual resource denials and actual output, rather than declaring success from a simulated request fixture alone.

## Windows

Windows builds the complete native workspace before running its security tests and authority gate:

```console
cargo build --locked --workspace --all-targets
cargo test --locked --workspace --all-targets -- --test-threads=1
revayat-scientific security-windows --authority-image target/debug/registry-authority.exe
```

The Rust registry authority and its independent Rust source oracle replace interpreter bootstrap and experimental diagnostic implementations. Actual primary/descendant registry proofs, restricted native token/job controls, ACL/private storage and reparse/junction checks remain required. The authority must not fall back to an ordinary unrestricted process or accept missing evidence. These observations do not certify arbitrary Microsoft Word/OPC behavior or kernel policy.

## Scientific and portable tiers

Portable tests run on Linux, macOS and Windows. Tests that require real XeLaTeX/Poppler, a sandboxed browser, OCR or LibreOffice carry explicit prerequisite descriptions. Equipped scientific CI executes the required cases with `--include-ignored`; a passing portable run alone does not claim those bodies executed.

The one-to-one migration inventory preserves all 583 original public test scenarios. [CI](../.github/workflows/ci.yml) additionally retains Rust CodeQL security/quality analysis, moderate-or-higher dependency review, strict Cargo audit, actionlint and zizmor. `ci-status final` derives each result from a verified job/revision/run attempt and exits unsuccessfully for any non-success aggregate. Missing, retired, cancelled, skipped or timed-out jobs cannot create green status.

Keep evidence local and content-free where practical. Never publish source text, environment secrets, private absolute paths, token values or raw credential-bearing HTTP errors. Persistent recovery journals contain local paths needed for deliberate recovery and are not release artifacts.
