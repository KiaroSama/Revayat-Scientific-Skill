# Architecture

Revayat contains one Rust workspace, a native command-line executable with a required Unix process-owner companion, a separate native Windows registry authority, an agent skill, document templates and reference material. The host agent owns translation, scientific meaning, linguistic research and visual review. Helpers report observed mechanical facts.

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

Modules are under [crates/revayat-scientific/src](../crates/revayat-scientific/src). Each source/test file must remain strictly below 800 lines (at most 799); a necessary addition to a near-700-line file requires cohesive extraction first. Source audit reports comparable historical/current physical source/test lines without a total-size quota. Proven dead/duplicate removal needs separate caller and behavior-preservation review plus actual tests; line counts alone are not quality proof. Cargo owns dependencies and the lockfile; product execution does not dispatch through another language interpreter.

## Source and document boundaries

Source closure retains byte snapshots, CR/LF positions and included-file attribution. A shared lexical model masks comments and supported literal constructs before interpreting includes or lint rules. It does not evaluate arbitrary TeX macro/category-code programs. HTML parsing retains original positions and enforces explicit resource, scope and inline-prose barriers.

DOCX edits target original story offsets, inspect package identity and preserve untouched members. Supported secondary stories resolve through declared content types and relationships. PDF transformations share admission checks for byte/object/page limits, encryption and unsupported signature/XFA structures. Exact format support is documented in the [DOCX](../skills/revayat-scientific/references/docx.md) and [PDF](../skills/revayat-scientific/references/pdf-processing.md) references.

## Rendering and delivery

The Rust DevTools client renders HTML using a real sandboxed Chromium-family browser and a restricted job-resource policy. The separate WeasyPrint adapter runs the actual external engine inside the Linux Docker/Podman image. It stages checked HTML/CSS/SVG and binary resources into a closed input view, rewrites typed resource references and rechecks original hashes before publication. Unsupported dynamic resource syntax fails admission. TeX uses the same image with a Rust entrypoint and fixed compiler arguments. Both container paths use read-only input, a finite aggregate output tmpfs, bounded chunk delivery with manifest hashes, and verified owned cleanup. A host compiler is not a production fallback. WeasyPrint's external Python packages stay inside the image. Poppler, Tesseract and LibreOffice provide their documented verification or conversion operations.

The Unix runtime uses the dedicated companion and a private lifeline/accounting protocol for cooperative nested ownership. It holds the unreaped direct-child identity until owned process-group cleanup, waits for registered descendants before container receipt cleanup, and preserves cleanup uncertainty as failure. Generic ownership records use a private temporary root rather than requiring a writable working directory; explicit inherited container scopes retain their hierarchy. Descendants that deliberately escape with a new session are outside this cooperative contract. Source review is complete for the narrow correction batch; actual hosted IPC/timeout/descendant/container proof remains unrun.

The Windows native entry now has source-authored outer-owned durable run state and profile intent. The worker receives validated state locators, not a reaped/gate certificate. Runtime issues a nonconstructible recovery capability only after owned-job termination/accounting, direct-child wait and capture joins; the surviving owner performs profile recovery afterward. Unknown finalization retains state, and this partial profile path is not full LPAC suite, lease or trace cleanup proof. Hosted verification is still pending.

Source revisions, expected outputs and resource decisions are checked across destructive boundaries. Outputs are staged before a complete delivery is published. Cooperative locks and snapshots detect bounded classes of concurrent changes; this is not a globally atomic transaction or a hostile-kernel security proof. Unresolved restoration preserves journals, previous bytes, stages and locks.

## Skill and installation

The distributable skill contains `SKILL.md`, eligible references/assets, agent metadata, GPL notices and the native executable in `bin/`. Linux/macOS also require adjacent `revayat-process-owner`; Windows packages require `revayat-quota-worker.exe` for the fixed native quota and kernel-control roles. Build all binaries with `cargo build --locked --release --workspace --bins` and keep each platform's files from the same build/revision. Adjacency/type/byte checks do not provide a signed version handshake. Packaging and installation share the same bounded payload. They refuse linked source entries, implementation/source overlap, Git administration, case collisions and known hardlink aliases. Whole-target installations stage every selected host before activation and retain previous editions outside skill discovery.

Original documents, terms, inventories, figure manifests, translation logs and deliverables belong to a job directory outside the installed skill. Translation logging remains required even when no helper command runs.

## Verification

The current maps retain 583 original public test IDs and Rust registration counterparts; separate strict censuses record 37 upstream checks, 41 standalone security leaves and 14 original Rust verifier tests. Additional source censuses retain 53 ordered managed stage invocations plus three direct post-bootstrap checks, 41 nested oracle rows, six discovery checks, nineteen runtime-preparation requirement sites and six coverage scenarios. The latter censuses explicitly record missing counterpart or witness-producer evidence rather than inventing independent test registrations. Registration is not behavioral equivalence or execution. Windows ordered bootstrap invocations, overlapping check/helper declarations and separate registry-oracle input cases retain their own obligation and execution relationships; native diagnostic contracts are still being restored and reviewed, not declared obsolete.

The migration command distinguishes registration-only from scoped execution evidence. Its intermediate evidence validation does not certify complete parity across every inventory, platform and equipped tier. Full trusted runner/result integration and final hosted acceptance remain unfinished. CI must cover Linux/macOS/Windows debug/release and portable cases, required equipped rendering, native Linux/Windows security, CodeQL, dependency/workflow checks and strict Cargo audit. Actual current-head reports, not this architecture description or an ancestor's badge, establish which checks executed and passed.

Commit identity checks inspect stored author/committer addresses with replacements disabled, reject shallow/grafted ancestry and permit only exact documented service identities. A base restricts inspection to introduced commits and does not certify earlier history. Display mailmaps do not alter the checked values.
