# Selected upstream changes — 2026-11-13 UTC

This follows the historical [November 10 review](upstream-review-2026-11-10.md).
All 33 default-branch HEADs were rechecked through GitHub between
`2026-11-13T20:22:44Z` and `2026-11-13T20:22:49Z`;
[the inventory](upstream-revisions.json) retains each batch's exact UTC bounds.
Twenty-eight HEADs are unchanged and their documents were not reread.
The five comparisons below contain four substantive deltas and one generated
asset update. Selected immutable diff excerpts were rechecked for integration
between `2026-11-13T20:23:14Z` and
`2026-11-13T20:24:05Z`, after the initial source reads
during this November 13 session. These are observation times, not commit dates.

| Repository | November 10 base | November 13 HEAD | Scope actually inspected |
| --- | --- | --- | --- |
| QuantEcon/action-translation | `80d4ae6a8eececa5395067dc1647b4f9594c52ef` | `805dc1146a64ed71b3a1b93231a8e877daf01998` | Three-commit comparison; changelog and action/CLI/FAQ changes about revision premises, recovery, existing targets and rename scope |
| docling-project/docling | `1ae470a1f4580881ed73853f64e0bf178f623c5e` | `31d14a74b7bddc850541ab8363b8585085845313` | Sixteen-commit comparison; relevant Word/OMML/JATS/Markdown/image changes and outline/nested-table tests |
| github/spec-kit | `f29319d550d1f05404f7184b92e995600ca2293f` | `2ee2b1e8005905db05f5717300a469b3068b908f` | Eleven-commit comparison; file-helper design, workflow verdict documentation and literal-path PowerShell fix |
| Mohammad-Hasan-Kaman/kaman-ai-translator | `2b9967fb422790304d1daffaa71a513b6ca899ff` | `8ce6dd03f0d5335a2cac60ceb4e21d699da8ab1b` | Eleven-commit comparison; README and changelog, including the final capability-policy correction |
| PDFMathTranslate/PDFMathTranslate | `38401fb95858b02918846837bbb61ca6e9eb4d41` | `9ec3d0a5d2ce22cfb588738f669ddb278d13e696` | Complete comparison: 66 star-history commits change only four files under `assets/star-history/` |

## Revision recovery

QuantEcon's [action reference](https://github.com/QuantEcon/action-translation/blob/805dc1146a64ed71b3a1b93231a8e877daf01998/docs/user/action-reference.md),
[CLI reference](https://github.com/QuantEcon/action-translation/blob/805dc1146a64ed71b3a1b93231a8e877daf01998/docs/user/cli-reference.md)
and [changelog](https://github.com/QuantEcon/action-translation/blob/805dc1146a64ed71b3a1b93231a8e877daf01998/CHANGELOG.md)
now distinguish a translation behind the assumed source, one already ahead,
and an earlier still-open translation PR. A stale PR rerun can overwrite later
source changes; an unreadable state file must not make an existing target
eligible for regeneration. Conversely, an orphan state file is not target content.
Both sides of a rename must belong to the intended document scope.

Adopted in [long documents](long-documents.md): preserve accepted snapshots,
recover the actual source/target relationship, select the same parts in previews
and execution, and re-review affected editable spans. Missing state remains
unknown; upstream's fallback does not establish alignment. No automatic source
sync, provider client or upstream recovery command is added.

## Structured content

Docling's [Word backend](https://github.com/docling-project/docling/blob/31d14a74b7bddc850541ab8363b8585085845313/docling/backend/msword_backend.py),
[outline tests](https://github.com/docling-project/docling/blob/31d14a74b7bddc850541ab8363b8585085845313/tests/test_backend_msword_outline.py)
and [nested-table tests](https://github.com/docling-project/docling/blob/31d14a74b7bddc850541ab8363b8585085845313/tests/test_backend_msword_nested_tables.py)
demonstrate distinct preservation failures: separately stored link fragments,
note-local relationships, direct paragraph outline levels, list/table boundaries,
and a single-cell table's position inside its containing cell.
Its [OMML change](https://github.com/docling-project/docling/blob/31d14a74b7bddc850541ab8363b8585085845313/docling/backend/docx/latex/omml.py)
applies defaults when optional property nodes are absent.
[JATS changes](https://github.com/docling-project/docling/blob/31d14a74b7bddc850541ab8363b8585085845313/docling/backend/xml/jats_backend.py)
retain code whitespace, heading labels/titles and footnote links;
[Markdown changes](https://github.com/docling-project/docling/blob/31d14a74b7bddc850541ab8363b8585085845313/docling/backend/md_backend.py)
keep captions attached to their picture.

Adopted in [extraction](extraction.md): inspect relationships, story identity,
nesting, math defaults and code whitespace alongside text coverage. These fixes
belong to an external converter; they do not demonstrate the same defects in
Revayat's package-preserving OOXML edits or expand its admitted subset.

## Cleanup authority

SpecKit's [file-helper design](https://github.com/github/spec-kit/blob/2ee2b1e8005905db05f5717300a469b3068b908f/design/file-helper.md)
now retains the original root handle through deletion, anchors classification,
enumeration and removal to native objects, closes handles deterministically and
bounds traversal descriptors. Stored identity numbers alone do not retain an
object. Preflight is not transactional; partial cleanup and access failures remain
possible. Native Windows replacement and handle-sharing tests remain necessary.

Adopted in [review](review.md): demand those observations when auditing a cleanup
race-resistance claim. This is a review criterion, not an assertion that all
Revayat cleanup paths already have this property or that a defect was reproduced.
The [literal-path fix](https://github.com/github/spec-kit/blob/2ee2b1e8005905db05f5717300a469b3068b908f/scripts/powershell/create-new-feature.ps1)
is useful regression intent for bracketed paths; no PowerShell helper is imported.
[Workflow verdict inputs](https://github.com/github/spec-kit/blob/2ee2b1e8005905db05f5717300a469b3068b908f/docs/workflows/overview.md)
remain gate-specific and existing runs retain their saved definition; their
approval workflow is not added to this skill.

## Readiness and export

Kaman's [README](https://github.com/Mohammad-Hasan-Kaman/kaman-ai-translator/blob/8ce6dd03f0d5335a2cac60ceb4e21d699da8ab1b/README.md)
distinguishes optional advertised chat metadata, explicit model selection and
metadata-free catalogs. Chat support does not prove structured output, vision,
translation quality or readiness; no capability is inferred from a model name.
The final policy retains a first-entry fallback only for catalogs without any
capability metadata. Its [changelog](https://github.com/Mohammad-Hasan-Kaman/kaman-ai-translator/blob/8ce6dd03f0d5335a2cac60ceb4e21d699da8ab1b/CHANGELOG.md)
makes HTML export portable by embedding compressed JPEG page images.

Adopted in [review](review.md): state exactly what a readiness observation proves
and inspect the actual job artifact. Adopted in [extraction](extraction.md):
a self-contained export is not proof of unchanged image information. Docling's
[16-bit image conversion](https://github.com/docling-project/docling/blob/31d14a74b7bddc850541ab8363b8585085845313/docling/utils/image_utils.py)
also separates preview conversion from original samples. Preserve originals and
record derivatives; do not adopt universal JPEG recompression or provider discovery.

## Metadata and release observations

The PDFMathTranslate [complete comparison](https://github.com/PDFMathTranslate/PDFMathTranslate/compare/38401fb95858b02918846837bbb61ca6e9eb4d41...9ec3d0a5d2ce22cfb588738f669ddb278d13e696)
changes star-history assets only. Inventory refresh suffices; no new fidelity
guidance follows. The same applies to SpecKit community catalog updates.

Official [Rust 1.100.0](https://github.com/rust-lang/rust/releases/tag/1.100.0)
was released November 12; [Cargo's layout change](https://github.com/rust-lang/cargo/pull/17354)
moves test harnesses into the intermediate build tree while final binaries keep
their documented profile-level paths. Toolchain adaptation and fresh native
verification are separate implementation work, not established by this review.
Official latest scanner releases still match the reviewed pins:
[cargo-audit 0.23.0](https://github.com/rustsec/rustsec/releases/tag/cargo-audit%2Fv0.23.0),
[zizmor 1.32.0](https://github.com/zizmorcore/zizmor/releases/tag/v1.32.0) and
[actionlint 1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12).
A focused 12-crate release check found compatible [ZIP 9.5.1](https://github.com/zip-rs/zip2/releases/tag/v9.5.1)
and a meaningful but breaking [HarfRust 0.16/read-fonts 0.47 pair](https://github.com/harfbuzz/harfrust/releases/tag/0.16.0).
These observations do not claim a dependency upgrade, successful audit or tested
API migration. The guessed Fontations changelog path returned 404; its standalone
API delta was not reviewed.

No GitHub service/rate-limit block occurred. ZIP registry old-history extraction
was trimmed; the new release was cross-checked against its official release/tag
and actual patch. No external runtime code, model, corpus, fonts or test data was
imported. This is selected-source review and guidance adoption, not a complete
history, security or translation-quality certification.
