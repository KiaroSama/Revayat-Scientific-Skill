# Unicode isolate lint

The `bidi-isolate` rule checks explicit LRI (`U+2066`), RLI (`U+2067`),
FSI (`U+2068`) and PDI (`U+2069`) controls in supported HTML and TeX prose.
It reports an unpaired closer or an unclosed opener in a prose paragraph.
Balanced nesting remains valid. Findings retain original file and line locations,
including decoded HTML entities and included TeX files.

## Paragraphs and protected content

| Source | Boundary behavior |
| --- | --- |
| Ordinary HTML inline elements | A prose isolate can span an inline element; excluding its English/code content from lexical checks does not by itself end the paragraph. |
| HTML block elements and explicit breaks | Block elements, including `search`, `listing`, `menu`, and `details`, and explicit breaks end the static prose paragraph. A closer in a later block cannot repair an opener in an earlier block. |
| Ordinary HTML source CR/LF | Collapsible formatting whitespace does not end a rendered prose paragraph. |
| HTML preserved-newline contexts | `pre`, `textarea`, `xmp`, and `listing` preserve newlines by default. Recognized literal inline `white-space` declarations can preserve or collapse newlines, and their settings can be inherited. Visible protected inline text can still contain a paragraph break. |
| Hidden HTML content | Hidden content and fallback text in `iframe`, `noembed`, and `noframes` can neither end a prose paragraph nor close a visible isolate. |
| TeX prose | Explicit `\par`, list-item boundaries and blank physical source lines end the paragraph. Ordinary wrapped source lines do not. Original per-file line indexes distinguish actual blank lines from adjacent newline bytes created by include expansion. CRLF pairing belongs to its original file; a nonempty whitespace-only final line retains its implicit EOF paragraph. |
| TeX protected content | Comments, escaped commands, math/code and protected arguments do not create prose boundaries. For `\newcommand` and `\renewcommand`, including their starred forms, the linter protects the braced or unbraced command name, optional arguments, and complete replacement argument: a balanced group or one unexpanded token. A braced name must contain exactly one control word or control symbol. Spaces and comments between definition tokens are supported; a blank line contributes a paragraph token rather than ordinary whitespace. Complete definitions are excluded before document-boundary and prose-region detection, so unused body tokens cannot start/end the document or open math or argument regions in following prose. |

The HTML check is a static source analysis. It recognizes supported element
behavior and literal inline whitespace declarations; it does not compute an
external stylesheet cascade, script-driven layout or a browser's final bidi
rendering. Review the rendered document when layout or external styles affect
direction. `U+2028` is a line separator, distinct from the bidi paragraph
separator `U+2029`.

TeX dependency discovery remains conservative: complete includes with literal
filenames within default arguments or braced replacement arguments, and image
references inside definitions, are still admitted and checked when they are
outside accepted inline/verbatim literal spans. Declaration names and single-token
replacement arguments do not dispatch includes. Each reference is bounded by its
own data argument, including nested declarations and supported caller
continuations; following prose cannot supply its filename. Definition-body
document markers cannot stop later include discovery. Definition ownership is
retained on each original file visit and mapped through closure segments, so
braces in a conservatively discovered child cannot end its parent's definition.
The same file can be definition data in one visit and visible prose in another.
Plain-text extraction uses this ownership for document boundaries and delimiter
matching while retaining ordinary replacement text. Live math and excluded
environment pairs are matched with declaration data masked; they may still span
an unused declaration. Escaped math delimiters cannot terminate these matches.
Paired math inside each declaration is removed separately,
so a delimiter cannot pair with live prose or another declaration's data. Complete
inline/verbatim literal spans hide their delimiters in this owner-local matching
view; retained output still follows raw replacement-text extraction.
One data cursor supplies accepted literal spans and dependency events from each
original file visit. It resumes at the exact literal endpoint, including after a
backslash delimiter, while the separate raw collector retains comment and brace
semantics. Matching masks literals before normalizing remaining backslashes.
Declaration names, count headers and single-token replacements cannot supply
literal starts. Incomplete literal spelling does not introduce an extraction
error, borrow a closer beyond its data/owner boundary, or repeatedly scan a suffix.
These extraction rules do not change unexpanded argument collection. Original
declaration starts separate adjacent owners while keeping one owner's included
and continued fragments together. Image, listing and direction checks consume
the same accepted literal spans. A real listing environment still supplies its
opener for direction checks; command-looking inline-literal payload does not.
This does not expand macro invocations
or change the existing source-closure limits.

Include dispatch retains the existing ASCII-letter command boundary, so both
`\input@chapter` and `\input @chapter` discover `@chapter.tex` in the default
lexical model. Definition names can still contain `@`. This does not evaluate
arbitrary category-code changes such as a redefined `\input@chapter` command.

For literal unbraced `\input file `, a definition can continue in the caller
after the included file ends at a supported LaTeX lookahead position: after the
definition command, its complete name, or its first complete optional argument.
The replacement argument must be collected completely in one original file.
Recursive returns and
their generated newline separators retain ownership only after that body is
established. A star without its name, an open argument/body, or a second optional
argument without its body cannot transfer across EOF. Braced `\input{file}` and
`\include{file}` do not transfer this state because their file-handling wrappers
insert following tokens. These rules preserve real document ends and dependency
limits while preventing unused continued definitions from hiding later includes.

The lexical projection follows that same collection context. Comments retain
their TeX line semantics. Literal syntax stays opaque in ordinary source, while
replacement arguments are collected without executing `\verb`: its braces,
percent signs and subsequent tokens retain their unexpanded meanings. A consumed
single paragraph or control token stays protected, and the next token returns to
ordinary analysis. Included continuations take precedence over apparent local
declarations starting inside their consumed prefix; later declarations are then
selected from the existing index. Incomplete argument contents cannot export
pending definition state into a caller.

Definition recognition indexes delimiters once and resolves each candidate with
bounded lookups, including incomplete definitions and caller continuations.
Optional-argument prose scans
skip inert preamble and post-document positions; ignored trailing declarations
cannot trigger repeated scans of the remaining source.

## Waivers and bounded reporting

Existing `bidi-isolate` waivers apply at the actual source location. Waived
controls still participate in nesting; the waiver suppresses the diagnostic,
not the structural effect of the character. The rule emits at most **64**
unwaived findings. Suppressed candidates do not consume that budget or hide a
later unwaived error. Existing source and token size limits remain in force.

The dedicated bidi projection is separate from ordinary Persian lexical lint.
Adding a formatting span or wrapping an HTML/TeX source line therefore does not
change the lexical exclusions used by other rules.

## Verification

The [bidi regression tests](../crates/revayat-scientific/tests/lint_bidi_recheck.rs)
and [lint context tests](../crates/revayat-scientific/tests/lint_context.rs) cover
inline exclusions, hidden and block content, ordinary and preserved newlines,
entities, TeX paragraph and protected regions, include locations, nested
waivers, and the reporting ceiling. The
[definition syntax tests](../crates/revayat-scientific/tests/lint_bidi_definitions.rs),
[definition caller tests](../crates/revayat-scientific/tests/lint_bidi_definition_callers.rs),
and [listing whitespace tests](../crates/revayat-scientific/tests/lint_bidi_listing.rs)
cover definition-token variants, real document boundaries, dependency/direction
compatibility, and explicit whitespace overrides. The
[provenance tests](../crates/revayat-scientific/tests/lint_bidi_definition_provenance.rs)
cover delimiter-changing dependencies, nested and repeated file visits, mixed
newlines and original locations. The
[continuation tests](../crates/revayat-scientific/tests/lint_bidi_definition_continuations.rs)
cover unbraced input returns, both definition commands, control-symbol names,
recursive empty returns, invalid seams, conservative dependencies and real ends.
The [lexical ownership tests](../crates/revayat-scientific/tests/lint_bidi_definition_lexical.rs)
cover comment-only and blank lines, raw argument collection versus ordinary
literals, single-token replacement bodies, malformed-name/pending recovery,
continuation precedence and the shared lint/plain-text projection.
The [definition dependency tests](../crates/revayat-scientific/tests/tex_definition_dependencies.rs)
cover include-command boundaries, names versus references, bounded defaults and
replacement arguments, nested declarations, inherited data and caller returns.
The [definition extraction tests](../crates/revayat-scientific/tests/tex_definition_extraction.rs)
cover live and owned math/environment pairs, adjacent owners, included and
continued fragments, retained replacement text, bounded literal matching,
declaration-header and malformed-literal controls, public snapshots and a dense
valid-declaration workload.
The [literal boundary tests](../crates/revayat-scientific/tests/tex_definition_literal_boundaries.rs)
compare active and escaped math/literal boundaries against neutral-prefix
controls, including Unicode delimiters and inherited source bounds.
The [literal caller tests](../crates/revayat-scientific/tests/tex_definition_literal_callers.rs)
exercise actual image inventory, lint findings, original locations and comment
resumption alongside genuine image, listing and input controls.
The [literal dependency tests](../crates/revayat-scientific/tests/tex_literal_dependencies.rs)
cover complete literal payloads, exact endpoint resumption, active and escaped
inputs, declaration roles, original argument limits and raw comment endings.
The
[large-tail tests](../crates/revayat-scientific/tests/tex_definition_work.rs) exercise
production source loading and extraction with 100,000 incomplete declarations;
scanner unit tests separately assert a linear traversal bound without wall-clock
thresholds. Normal portable CI discovers all these suites.

References: [Unicode Bidirectional Algorithm](https://www.unicode.org/reports/tr9/)
and [CSS whitespace processing](https://www.w3.org/TR/css-text-3/#white-space-processing).
LaTeX's [definition argument scanning](https://github.com/latex3/latex2e/blob/0919db37a88f89e6af3809f8d3aeac198b0cdf2b/base/ltdefns.dtx),
[input dispatch](https://github.com/latex3/latex2e/blob/0919db37a88f89e6af3809f8d3aeac198b0cdf2b/base/ltfiles.dtx)
and [file hooks](https://github.com/latex3/latex2e/blob/0919db37a88f89e6af3809f8d3aeac198b0cdf2b/base/ltfilehook.dtx)
define the supported EOF continuation boundary.
