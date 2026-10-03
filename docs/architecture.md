# Architecture

`document_context.py`, `tex_source.py`, `html_source.py` and `source_model.py`
bind checks to the actual job and included source locations. `publication.py`
validates staged destination sets and rolls back failed publication; if recovery
fails, it retains previous bytes and names a recovery manifest. `build-support.py`
shares source selection, required-asset checks and delivery across native adapters.
`render-html.py` owns bounded renderer workers; `resource_policy.py` restricts
browser requests and WeasyPrint fetching to approved local resources.

`tex_ignored_regions()` supplies the shared, escape-aware comment/literal subset
for source closure and lint. Offsets and CR/LF survive masking; an included file's
final logical line boundary is mapped to its EOF, leaving resumed parent locations
intact. Literal examples cannot grant waivers or become assets; genuine listing
openers remain available to direction checks. This does not interpret arbitrary
macro expansion or category-code programs. Completed source closures also preindex
segment starts and each original text snapshot's line breaks for binary-search
location queries. Compact numeric arrays keep the newline index bounded without
repeated prefix scans; original source bytes and EOF attribution do not change.

`document-docx.py` and `docx_package.py` provide native creation and targeted OOXML
edits. Batch edits index each addressed story once, sort original byte offsets and
join edited slices once after checking output size. Untouched member bytes and
archive comments survive; staged packages are reopened before publication. Secondary
DOCX story discovery and edit authorization share declared-content-type resolution,
including valid noncanonical part names and suffixes. OCR layers are checked for
all painting operations before overlay, not only for image or visible-text objects. `document-pdf.py`, `pdf_forms.py` and `pdf_outlines.py` reuse PyMuPDF for
extraction, forms, merging with supported precise outline targets and optional
Tesseract OCR. `image_review.py` validates exact-asset records only for
legitimate darkness; other image safety checks remain mandatory.
`font-fetch.py` validates font identity, weight
and licensing before delivering the pair and provenance together. Structural
validation does not certify rendered layout or scientific translation accuracy.
`term-brief.py` reads reviewed source text and the job's approved ledger to emit
source-located terminology candidates with input hashes. It cannot infer a concept,
translate or verify a scholarly claim; the agent applies the evidence reference.

Optional parallel translation/editing requires explicit job consent. Workers own
separate drafts/patches and logs; the coordinator owns canonical documents,
glossary updates, integration and final quality gates.

`skills/revayat-scientific/` is the entire distributable payload. Its entrypoint routes an agent through source inventory, concept decisions, translation, review and verification; references own their detailed policies.

`scripts/revayat-scientific.py` maps portable commands to the existing Python helpers or OS-native build scripts. `runtime.py` owns per-run logging, subprocess deadlines and termination. The scientific checker remains the owner of mechanical rules. The agent owns translation, semantic review and visual inspection; no script simulates these decisions.

`install/install.py` stages allowlisted payload files before replacing an installation, retaining its previous copy. Shell entrypoints share this implementation. `tools/package.py` uses the same payload selection. Tests exercise public commands, installed packages and scientific fixtures; CI adds actual renderer checks.

Job data stays outside the installed skill: preserved sources, inventory, terms, figure manifest, progress, editable document and delivered PDF. A failed build or requested verification preserves the previous delivered PDF. Logs contain operation names, durations and exit codes, not document text.

Source-language profiles guide direct translation and scoped linguistic research;
they are agent instructions, not installed translation models or accuracy claims.
The coverage map binds source locations/languages to target anchors and review
state. The agent compares source/output page geometry and image fidelity; generic
build verification does not perform those comparisons automatically. Raster crops
use a requested minimum DPI and preserve higher embedded-image sampling, with a
pixel-allocation limit instead of silent downsampling. Research references record
adopted lessons without bundling third-party code, corpora or model weights.

`tools/check-commit-identity.py` verifies stored author and committer emails. PR CI
checks only commits introduced relative to its base; this cannot certify excluded
history. Run the tool without `--base` to check all history reachable from `--head`
when performing the owner-required, backed-up identity normalization. A mailmap
display change does not satisfy the stored-identity policy.


## Cross-entry-point admission and publication

`pdf_input.py` supplies the shared admission implementation for contiguous page extraction and
the existing document operations. It retains the existing byte/page/object limits,
encryption and parser-repair refusals, and transformation-only signature/XFA
checks. Extraction must not silently bypass the policies enforced for merge, fill
or OCR. Inspection is not signature authentication, and extraction still copies
one contiguous range rather than rasterizing or duplicating shared resources.

Package builds stage the entire allowlisted payload and publish through
`publication.py`. The packager protects payload files, known build inputs and
tracked checkout paths, rejects linked/aliased/case-colliding outputs and refuses
outputs inside implementation directories. A custom output is not permission to
replace the skill's source, installer or repository documentation.

The commit-identity checker disables replacement-object interpretation and rejects
shallow or nonempty legacy-graft history views. A range check still covers only
that range; obtain a complete, ungrafted clone before claiming full-history
compliance. This is a metadata check, not cryptographic signature verification.

Detailed supported inputs and limits: [input and publication contracts](../skills/revayat-scientific/references/input-boundaries.md).

## Semantic identities and internal metadata

`pdf_button_states.py` separates serialized PDF appearance keys from decoded form
labels and resolves stored/inherited field values for verification. DOCX restricted
feature detection uses effective content types and relationships as well as legacy
filename guards. Package publication protects actual private/shared/relocated Git
metadata, not only tracked worktree files. Supported subsets and research decisions
are in [format identity and preservation boundaries](../skills/revayat-scientific/references/format-identity.md).

`html_source.py` distinguishes actual markup from literal raw/RCDATA content,
retaining once-decoded entity locations and printed isolate text. Supported foreign
breakout and integration-point handling do not turn HTML nonvoid slashes into
closures. Unsupported templates/plaintext and unterminated literal contexts fail
before validation or rendering. The package destination plan also protects parent,
configured-hook and split-index metadata, then resolves it again after staging.
See [literal contexts and protected metadata](../skills/revayat-scientific/references/context-and-metadata-integrity.md)
for the bounded input policy; this is not a universal HTML DOM or trust verifier.
