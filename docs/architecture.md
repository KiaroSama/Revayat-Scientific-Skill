# Architecture

Revayat contains one Rust workspace, a native command-line executable, a separate native Windows registry authority, an agent skill, document templates and reference material. The host agent owns translation, scientific meaning, linguistic research and visual review. Helpers report observed mechanical facts.

## Native implementation

| Rust module | Responsibility |
| --- | --- |
| `source`, `tex`, `html`, `html_scopes` | Bounded source closure, original source locations, literal regions and scoped prose |
| `ledger`, `terms`, `lint` | Exact ledger contracts, source-located terminology and Persian/document rules |
| `identity`, `publication` | Counted byte fingerprints, native file identity, protected destinations and recoverable publication |
| `docx`, `docx_package`, `docx_features` | Bounded OOXML/OPC inventory, creation, targeted edits and untouched-member checks |
| `pdf`, `pdf_forms`, `pdf_outlines`, `pdf_ocr` | Native PDF admission and transformations, precise supported targets and optional OCR |
| `images`, `fonts` | Figure preparation, exact-asset reviews and complete licensed font bundles |
| `runtime`, `build`, `render`, `tex_container` | Owned process trees, deadlines, browser resource policy, isolated TeX and verified delivery |
| `windows_security` and `registry-authority` | Native Windows job/token/ACL/registry containment evidence |
| `distribution`, `distribution_paths`, `distribution_package` | Complete native payloads, installation and source/Git-safe archives |
| `ci`, `ci_tools`, `validation`, `migration` | Truthful status reporting, workflow/history validation and complete test migration inventory |

Modules are under [crates/revayat-scientific/src](../crates/revayat-scientific/src). Rust source files remain bounded to 800 lines. Cargo owns dependencies and the lockfile; product execution does not dispatch through another language interpreter.

## Source and document boundaries

Source closure retains byte snapshots, CR/LF positions and included-file attribution. A shared lexical model masks comments and supported literal constructs before interpreting includes or lint rules. It does not evaluate arbitrary TeX macro/category-code programs. HTML parsing retains original positions and enforces explicit resource, scope and inline-prose barriers.

DOCX edits target original story offsets, inspect package identity and preserve untouched members. Supported secondary stories resolve through declared content types and relationships. PDF transformations share admission checks for byte/object/page limits, encryption and unsupported signature/XFA structures. Exact format support is documented in the [DOCX](../skills/revayat-scientific/references/docx.md) and [PDF](../skills/revayat-scientific/references/pdf-processing.md) references.

## Rendering and delivery

The Rust DevTools client renders HTML using a real sandboxed Chromium-family browser and a restricted job-resource policy. TeX runs inside a Linux Docker/Podman image with a Rust entrypoint, fixed compiler arguments and observed containment controls. A native host compiler is not a production fallback. Poppler, Tesseract and LibreOffice are optional external native tools for their documented verification or conversion operations.

Source revisions, expected outputs and resource decisions are checked across destructive boundaries. Outputs are staged before a complete delivery is published. Cooperative locks and snapshots detect bounded classes of concurrent changes; this is not a globally atomic transaction or a hostile-kernel security proof. Unresolved restoration preserves journals, previous bytes, stages and locks.

## Skill and installation

The distributable skill contains `SKILL.md`, references, assets, agent metadata, GPL notices and a native executable in `bin/`. Packaging and installation share the same bounded payload. They refuse linked source entries, implementation/source overlap, Git administration, case collisions and known hardlink aliases. Whole-target installations stage every selected host before activation and retain previous editions outside skill discovery.

Original documents, terms, inventories, figure manifests, translation logs and deliverables belong to a job directory outside the installed skill. Translation logging remains required even when no helper command runs.
## Preparation runtime and notice bounds

Source-built Unix tools require adjacent same-build `revayat-process-owner` and private lifeline/accounting for cooperative nested cleanup; Windows retains native Job ownership. Generic ownership records use private temporary storage rather than requiring writable CWD. Descendants deliberately escaping into new sessions are outside this cooperative process-group contract. Companion-aware package/install integration is outside this preparation snapshot and remains unverified.

Explicit approved manual preparation defaults off and generates/checks only lock/notices inputs, publishing exactly two files with revision/run/attempt artifact provenance. Ordinary validation/status jobs are excluded, never replaced with fabricated green results; complete locked final verification remains mandatory. Notice processing bounds logical occurrence material at256MiB, unique shared bodies at64MiB and rendered output at64MiB before admitted growth/retention, not allocator RSS. Exact legal bytes/provenance survive deduplication; overflow fails without partial bundle publication.


## Verification

The migration inventory binds every one of the 583 original public test IDs to a registered Rust test; a separate 37-check inventory retains the standalone upstream tier. Portable CI runs the native suite on Linux, macOS and Windows. Required rendering tests explicitly declare native prerequisites and are executed in the equipped scientific tier with `--include-ignored`. Separate Linux/Windows security jobs, Rust CodeQL analysis, dependency review, workflow security and strict Cargo audit remain required. A missing or failed job cannot produce a green aggregate status.

Commit identity checks inspect stored author/committer addresses with replacements disabled, reject shallow/grafted ancestry and permit only exact documented service identities. A base restricts inspection to introduced commits and does not certify earlier history. Display mailmaps do not alter the checked values.
