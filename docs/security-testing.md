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

The Rust registry authority and its Rust oracle remove the interpreter dependency, not the original diagnostic obligations. Ordered bootstrap, token/DACL, image/activation/CSR/loader, SxS, scratch/quota, private-creation and recovery behavior still require source-reviewed Rust counterparts and actual appropriate hosted evidence. Actual primary/descendant registry proofs, restricted native token/job controls, ACL/private storage and reparse/junction checks remain required. The authority must not fall back to an ordinary unrestricted process or accept missing evidence. These observations do not certify arbitrary Microsoft Word/OPC behavior or kernel policy.

## Scientific and portable tiers

The source-authored collector runs portable harnesses on Linux, macOS and Windows in debug and release, preserving ignored cases as skipped rather than claiming execution. Scientific selection runs exact reviewed ignored cases: the full Linux scientific set, three macOS crop cases, and three Windows crop cases plus the original actual renderer case. It checks expected registration and refuses missing/unknown cases rather than using a broad `--include-ignored` substitute. Two equipped workflow-lint cases remain quality checks. Real XeLaTeX/Poppler, sandboxed browser, OCR and LibreOffice prerequisites apply to their specific scenarios; none is inferred from portable success.

The intended execution-report matrix has eleven scopes: six portable, three scientific, and Linux/Windows native debug. The current native collector explicitly fails with `native instrumented execution adapter unavailable`; it does not fabricate stage/parent witnesses or replace the existing production security entries. Native53-stage evidence and full aggregate acceptance remain incomplete. Collector/workflow source review and exact-head hosted execution are still required.

The maps retain 583 original public test IDs, 37 upstream checks, 41 standalone security leaves and 14 original Rust verifier tests. Their distinct kinds and assertion obligations remain mandatory; registration is not execution. Source censuses separately retain 41 nested registry-oracle rows, six engine-discovery checks, nineteen runtime-preparation requirement sites and six coverage scenarios, including exact unmapped or unverified obligations. A carrier test pass cannot become synthetic row/site/scenario evidence. The original Windows profile, diagnostic, creator-owner and physical/enforced-quota checks remain required rather than retired because the implementation language changed. These inventories do not yet prove all original assertions, helper/stage relationships or real native cases executed. The intermediate migration audit explicitly reports registration-only or scoped execution evidence, never complete final parity. Required trusted execution-result integration is still being completed. [CI](../.github/workflows/ci.yml) must also retain Rust CodeQL security/quality analysis, moderate-or-higher dependency review, strict Cargo audit, actionlint and zizmor. Current workflow/status changes need their own exact-head hosted verification; no successful run is claimed by this document. Missing, retired, cancelled, skipped or timed-out required jobs must not create green status.

Portable registry-authority collection now has source-authored raw oracle capture: only the actual registry library carrier receives an owned journal directory. The collector accepts its 41 post-assertion observations only after successful harness execution, the carrier's Passed outcome and owned process cleanup, then binds the same-run identity and census digest. It publishes `oracle-debug.json` or `oracle-release.json` beside the execution report. The public aggregate accepts repeated `--event-report PATH` inputs for all required operation populations; missing reports or unclosed contracts fail naturally. No hosted oracle journal/report has yet been verified, and the remaining operation populations are not complete.

The source-authored Windows recovery path keeps native run state outside the controller worker. An opaque runtime capability permits profile recovery only after actual owned-job accounting reaches zero, the direct child is waited and capture threads join. Exit status alone is not recovery authority. Failed or uncertain finalization retains durable state and fails; profile recovery does not certify complete lease, trace, volume or full native-suite cleanup. These paths and their Windows regressions still require hosted execution.

Keep evidence local and content-free where practical. Never publish source text, environment secrets, private absolute paths, token values or raw credential-bearing HTTP errors. Persistent recovery journals contain local paths needed for deliberate recovery and are not release artifacts.
