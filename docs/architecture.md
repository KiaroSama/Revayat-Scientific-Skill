# Architecture

`document_context.py`, `tex_source.py`, `html_source.py` and `source_model.py`
bind checks to the actual job and included source locations. `publication.py`
validates staged destination sets and rolls back failed publication; if recovery
fails, it retains previous bytes and names a recovery manifest. `build-support.py`
shares source selection, required-asset checks and delivery across native adapters.
`render-html.py` owns bounded renderer workers; `resource_policy.py` restricts
browser requests and WeasyPrint fetching to approved local resources.

`document-docx.py` and `docx_package.py` provide native creation and targeted OOXML
edits. `document-pdf.py` and `pdf_forms.py` reuse PyMuPDF for extraction, forms,
merging and optional Tesseract OCR. `font-fetch.py` validates font identity, weight
and licensing before delivering the pair and provenance together. Structural
validation does not certify rendered layout or scientific translation accuracy.

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
