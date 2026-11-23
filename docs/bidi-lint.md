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
| HTML preserved-newline contexts | `pre`, `textarea`, and `xmp` preserve newlines by default. Recognized literal inline `white-space` declarations can preserve or collapse newlines, and their settings can be inherited. Visible protected inline text can still contain a paragraph break. |
| Hidden HTML content | Hidden content and fallback text in `iframe`, `noembed`, and `noframes` can neither end a prose paragraph nor close a visible isolate. |
| TeX prose | Explicit `\par`, list-item boundaries and blank lines end the paragraph. Ordinary wrapped source lines do not. |
| TeX protected content | Comments, escaped commands, math/code and protected arguments do not create prose boundaries. For `\newcommand` and `\renewcommand`, including their starred forms, the linter protects the command name, optional arguments, and braced definition body. |

The HTML check is a static source analysis. It recognizes supported element
behavior and literal inline whitespace declarations; it does not compute an
external stylesheet cascade, script-driven layout or a browser's final bidi
rendering. Review the rendered document when layout or external styles affect
direction. `U+2028` is a line separator, distinct from the bidi paragraph
separator `U+2029`.

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
waivers, and the reporting ceiling. Normal portable CI discovers both suites.

References: [Unicode Bidirectional Algorithm](https://www.unicode.org/reports/tr9/)
and [CSS whitespace processing](https://www.w3.org/TR/css-text-3/#white-space-processing).
