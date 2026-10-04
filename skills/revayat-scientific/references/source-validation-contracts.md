# Source interpretation and terminology admission

## HTML scopes and source text

`html_source.py` and `html_scopes.py` share the interpretation used by lint,
asset/resource admission and PDF text-order source evidence. Ordinary omitted
paragraph, list-item, definition-item, heading, option and table boundaries close
the prior scope before inheriting language, hidden, direction or identity state.
Nested list/table boundaries remain scoped. Body/html end tags do not erase the
scope of tail text that HTML renderers reprocess within the existing body.

This is a deliberately bounded source model, not a complete HTML5 DOM engine.
Active-formatting reconstruction/adoption, nested interactive elements, fostered
table text or misplaced table parts, ambiguous select children/separators and
duplicate document containers require an explicitly normalized static source.
They fail before a lint or resource decision instead of silently borrowing a
renderer-inconsistent tree. Existing raw-text/RCDATA, comment, foreign-namespace
and self-closing-token rules remain in force. The independent HTML5 integration
matrix checks accepted cases and explicit refusals, not universal conformance.

Text-order evidence uses actual text tokens from that same model. Attributes,
comments, script/style/head/title contents and explicitly hidden subtrees do not
become evidence. RCDATA literal markup is retained, character references decode
once, inline formatting does not split a word, and block boundaries separate
words. This does not compute external CSS, clipping, generated content, form
appearances or every viewer's layout. Source-to-render visual review is separate.

Probe generation preserves the prior default window/classification semantics
without repeated whole-suffix copies. `--min-letters` accepts 1..4096; probe work
is capped at 2000000 word visits/materialized window entries. Excessive requests
fail explicitly; use reviewed bounded parts rather than accepting a partial
probe set as a complete check. JSON outcomes remain passed/logical, failed/visual
and inconclusive. A logical-order result is not translation-completeness evidence.

## One located terminology ledger

`term_ledger.py` is the standard-library TSV reader used by both job lint and
`term-brief`. It accepts a UTF-8 BOM, leading comments/blank lines, LF/CRLF and
quoted fields (including multiline evidence notes). Headers are case-normalized,
unique and authoritative; `source` or `english` after the header is ordinary data.
Every non-comment record must have exactly the header's width, including empty
trailing cells. Invalid late records do not yield a partial ban list.

The brief keeps its minimal `source, output` schema and 512-approved-row limit.
Lint requires `source, output, step, count, forbidden_fa`. Additional columns
remain available for the job. Both consumers apply only `preferred`/`approved`
rows when `status` is present; other or empty statuses are not approvals. Legacy
ledgers without `status` retain their previous eligibility. Approved retained
Latin terms require a counterform; deprecated forms remain additional bans.
Persian output is not a calque pair, but its row must still be structurally valid.

The shared limit is 1 MiB and 10000 records; source/output fields are at most
256 characters and cannot contain controls. `ledger_line` is the physical start
of a TSV record, even after multiline notes. Input bytes and recorded input
hashes are unchanged. CSV failures, duplicate/missing headers and incomplete rows
are failed prerequisites, not a clean linguistic verdict. House `--pairs` files
retain their separate three/four-column format; a literal `english` term is not a
header, while an actual duplicate header fails.

## Research and adoption (2026-10-04)

- [WHATWG tree construction](https://html.spec.whatwg.org/multipage/parsing.html):
  in-scope optional closures and explicit boundaries around unsupported repair.
- [tinyhtml5](https://github.com/CourtBouillon/tinyhtml5): independent tree oracle
  in the existing development renderer tier, not a new lint/runtime dependency.
- [WeasyPrint](https://github.com/Kozea/WeasyPrint): actual PDF extraction/raster
  controls; output creation alone does not prove source coverage.
- [Python CSV reader](https://docs.python.org/3/library/csv.html): strict quoted
  record parsing, physical `line_num` and explicit newline handling.
- [QuantEcon translation tooling](https://github.com/QuantEcon/action-translation):
  separate glossary state, structural diagnostics and human review. No provider
  coupling or automatic glossary approval is imported.
- [Spec Kit workflows](https://github.github.com/spec-kit/reference/workflows.html):
  carry these requirements and acceptance evidence through the owner's configured
  local chain. Do not replace private Rules or treat a review gate as auto-approved.
