# Academic Persian style

This file owns Persian register and orthography. [terminology.md](terminology.md)
owns concept choices; [rtl-bidi.md](rtl-bidi.md) owns direction. Apply these rules
to translated Persian prose, not verbatim source quotes, code or formulas.

## Register follows the deliverable

Use standard written Persian. A casual user request does not turn a research paper
into chatty prose. Preserve the author's voice, scope and degree of confidence;
clarity is not permission to simplify away scientific distinctions.

| Genre | Voice |
| --- | --- |
| Paper, thesis, scholarly book | Clear academic Persian; established Persian concepts; precise claims and restrained transitions |
| Tutorial | Clear instructional Persian; direct address only when the source uses it; familiar tooling terms where appropriate |
| Reference or operational manual | Compact definitions and instructions; exact artifact and command names; low rhetorical density |

Use full forms such as می‌شود and می‌خواهد. Prefer direct verbs over ceremonial
phrases: بررسی کردیم instead of اقدام به انجام بررسی نمودیم. Judge alternatives
in their sentence. ارائه می‌کند, آغاز می‌شود, نشان داده شد and فراهم می‌کند are
legitimate scholarly expressions; do not ban them because a shorter synonym exists.
Do not impose a universal active-voice rule: a methods section may correctly use
an impersonal passive. Never invent the actor while rewriting one.

Preserve first person versus impersonal voice: we measured → اندازه‌گیری کردیم;
it was measured → اندازه‌گیری شد. Do not turn a source statement into an instruction,
add friendly asides, or replace source lists with fashionable prose patterns.

## Write Persian argument structure

- Read the entire source sentence, including final negation/modality and attached
  clauses, before drafting. Source language can be anything; English word order is
  not a universal intermediate representation.
- Split an overloaded sentence only when all conditions, qualifiers, referents and
  logical connections survive. Conversely, a short fragment may need its adjacent
  source context. Do not split equations, identifiers or defined multi-word concepts.
- Prefer a clear predicate and manageable ezafe chains. Avoid noun-heavy wording
  such as انجام یک ارزیابی از when ارزیابی کردن carries the same meaning.
- Choose connectors by logical role. بنابراین requires a consequence; بااین‌حال
  requires contrast. Do not introduce either merely to make a paragraph flow.
- Translate descriptive concepts rather than filling Persian function words with
  unnecessary English. In journal text, اثر علّی and فاصلهٔ اطمینان can be clearer
  than repeated original-language labels. Exact identifiers still remain exact.
- A foreign-name isolate is not a Persian word: rephrase awkward affix glue such
  as `\en{Go}ی`. Keep the approved term and its grammatical role unambiguous.

## Preserve scientific force

Check each assertion's actor, relation, condition, quantity and uncertainty.
Association is not causation; prediction is not explanation; statistical significance
is not practical importance. No significant difference is not proof of equality,
no effect, equivalence or safety. Relative change and percentage-point change differ.
Do not infer an equivalence margin, sample population or experimental condition.

Maintain distinctions such as may / supports / suggests / demonstrates / proves
from the actual source language. A negation may concern evidence, a possibility,
a measured difference or the entire proposition; do not move its scope. Preserve
negative findings and uncertainty even when their Persian sentence is less compact.

For a difficult passage, write a brief meaning check before polishing: what is
claimed, what is not claimed, what evidence/condition limits it. Recheck the polished
span against the original. A fluent mistranslation is still an accuracy error.
Use [fluency-gold.md](fluency-gold.md) to calibrate register and claim preservation.
These constructed examples are not a measured translation benchmark.

## Orthography and protected text

- Write UTF-8 and logical Unicode order. Use Persian ک/ی and proper نیم‌فاصله in
  translated Persian: می‌شود، نمی‌تواند، داده‌ها، شده‌اند.
- Use Persian punctuation in prose: ، ؛ ؟ «». Keep the punctuation belonging to
  a formula, code fragment, URL or original quotation unchanged.
- Normalize only prose spans. Whole-document cleaners may change whitespace,
  diacritics, distinct Urdu/Arabic letters, numbers and URLs. Preserve the original
  source and any protected spans before cleanup.
- For a correctly preserved non-Persian quote that triggers a Persian-only rule,
  follow the narrowly scoped procedure in [source-languages.md](source-languages.md).
  Never rewrite the quote to appease a linter or suppress unrelated errors.
- Scientific quantities in translated prose use Western digits and a decimal point:
  `3.14`, `2e-5`, `95%`, each isolated appropriately. First interpret the source's
  decimal/grouping convention and verify numerical equality. This formatting rule
  does not authorize changing the original text inside formulas or quotations.
- SI symbols stay exact; do not convert unit systems, round values or alter precision.
  A localized numeral must preserve its sign, exponent, uncertainty and unit.

The checker handles selected character/structure patterns, not full grammar,
word senses or scientific accuracy. Its English morphology rules are not valid
for every source language. Report only the checks that actually cover a finding.

## Dates, identifiers and references

Keep dates in the original calendar unless conversion is requested. Preserve
version strings, citation keys, ports, accession numbers, code names, DOI/URL
strings and equation symbols as identifiers, not quantities to reformat.
Keep a complete range or identifier in one appropriate directional span.

Use Persian generic labels: شکل، جدول، معادله، بخش، پیوست، قضیه، لم، اثبات،
فهرست مطالب. Preserve the identity of a named artifact within a translated heading;
a two-word heading is not automatically English-only. The rule applies to labels
from every source language, interpreted by function rather than a fixed word list.

Use real cross-references where possible. Preserve original reference targets and
bibliography entries, including their original script. Do not translate author lists,
rename cited titles, convert a citation style or silently renumber source equations.
A translated contents page reflects the translated document's actual pagination.

## Figures, tables and page layout

Follow [layout-and-images.md](layout-and-images.md) for mandatory source dimensions,
image pixels/PPI and faithful enhancement. The template's paper size must be replaced
with the measured source size. Retain margins, mixed orientations and print boxes
where applicable; report engine limitations instead of silently resizing the book.

Preserve figure artwork, aspect ratio, labels, color meaning, scale bars and order.
Keep untouched originals and trace every derivative. No mirroring for RTL and no
invented structures during image improvement. Translate captions and explanatory
prose; baked-in labels remain original unless a separately authorized, verified
label-edit workflow preserves all data. An alt description does not replace a figure.

Numeric table cells and formulas are LTR; Persian prose cells are RTL. Preserve row/
column relationships and source ordering. Use repeated headers for multipage tables.
Translate descriptive table titles according to the selected terminology level.
Missing cells, captions, notes or source objects are coverage failures.

## Footnotes, quotations and delivery

A footnote follows the direction of its own content. Preserve exact source quotes
and their source language; give the Persian rendering separately when requested.
Use a font that covers each retained script and check glyphs in the final PDF.
Keep URLs breakable without changing their bytes; move a long URL to its source-
appropriate note or reference rather than scattering direction controls through prose.

Review the Persian alone for readability, then compare changed spans with the
original again. Record meaningful corrections in the translation log beside the
output. Claim-changing ambiguity remains `needs-review`; work on unaffected parts
can continue. Never delete a limitation, add background or fabricate missing source
material to produce a smoother, apparently complete translation.
