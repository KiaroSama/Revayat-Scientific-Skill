# Source languages and direct translation

Read during intake for every source, including English. Target Persian does not
imply an English source. The host agent translates; this file is a routing and
review policy, not a claim that every model handles every language equally well.
[Research sources](research-sources.md) records the inspected resources and limits.

## Identify before translating

Record in `inventory.md`: source language(s), script/variety, discipline, target
Persian variety, source version, and direct or pivot route. Default to standard
Iranian scholarly Persian unless the user specifies otherwise. Inspect the body,
not just an English abstract or filename. Mixed-language sections get their own
language labels. Arabic script alone cannot distinguish Arabic, Persian or Urdu;
Cyrillic alone cannot distinguish Russian from Tajik. Treat automatic detection
as a suggestion. Resolve a material disagreement against actual source passages.

Translate directly from each original language into Persian when competent.
An English gloss may help identify a concept; it is not the replacement source.
If a pivot is needed, record the intermediate language/tool and compare the final
Persian with the original, especially negation, numbers, referents and terms.
When original-language meaning cannot be checked, label the affected part
`needs-review`; do not invent certainty or call pivot agreement independent review.
A Persian source normally needs editorial review, not a second translation.

## Research the encountered language and discipline

Before locking uncertain terminology or an unfamiliar language profile:

1. Search the exact source-language→Persian pair, scientific field and key terms,
   using English and the source language's own names. Search GitHub as well as
   publisher/university resources; try Persian query wording too.
2. Inspect actual guidance, glossary entries, examples and issue discussions.
   Prefer the source's definitions, an approved job glossary and comparable
   scholarly Persian usage over a generic dictionary or a repository's star count.
3. Record the URL, checked date, language direction, domain and the chosen lesson
   in the job's inventory/term evidence. Distinguish an example corpus, a model's
   advertised language list, an editorial policy and a tested scientific workflow.
4. Verify a proposed rule on the current passage. A forum suggestion or translated
   README is not an authority. Do not copy corpora/code/assets without appropriate
   rights, run fetched scripts or upload private source text to a new service.

Reuse current, relevant job evidence; do not repeat searches for settled terms.
Without browsing, record that limitation and use available approved references.
Missing evidence is not permission to guess a claim-changing meaning.

## Profiles to inspect selectively

The following are researched starting points, not an exhaustive language list or
language-pair accuracy certification. Read only the row(s) matching the source.
Tatoeba pair IDs below are corpus directions/labels, not installed model names.
NI means the inspected Natural Instructions task index; its TED examples are not
scientific gold and instance licenses may be unknown. FLORES is general evaluation.
Links and licensing caveats are in [research-sources.md](research-sources.md).

| Source | Verified resource lead | Review focus before Persian drafting |
| --- | --- | --- |
| English | Esposito/EPOQUE; QuantEcon; Tatoeba `eng-fas` | Hedge strength; negation; descriptive concept versus executable identifier |
| Arabic | PALI; Tatoeba `ara-fas`; NI `task1108_ted_translation_ar_fa` | Diacritics that distinguish meanings; pronoun antecedents; negation and attached clitics; preserve original Arabic quotes |
| German | Tatoeba `deu-fas`; ParCourE `de-pes`; UD German | Read the whole compound and sentence-final predicate; resolve cases, negation and decimal commas |
| French | Tatoeba `fas-fra`; QuantEcon register lessons | Conditional/reporting force; impersonal clauses; false friends; decimal commas and grouping spaces |
| Russian | Tatoeba `fas-rus`; UD Russian | Case roles, aspect and negation; Cyrillic/Latin lookalikes; stable names across sections |
| Chinese | Tatoeba `fas-zho`; UD Chinese; BabelDOC workflow | Identify simplified/traditional and variety; no whitespace word assumption; omitted arguments and quantities with 万/亿 |
| Japanese | Tatoeba `fas-jpn`; NI `task1098_ted_translation_ja_fa`; UD Japanese | Read predicate endings before deciding modality/negation; omitted subjects; technical katakana and mixed symbols |
| Spanish | Tatoeba `fas-spa`; NI `task1103_ted_translation_es_fa` | Subjunctive/conditional and negation scope; pronoun references; decimal/grouping conventions |
| Portuguese | Tatoeba `fas-por`; NI `task1282_ted_translation_pt_fa` | Identify source variety; conditional force, impersonal claims and local numerical notation |
| Italian | Tatoeba `fas-ita`; NI `task1254_ted_translation_it_fa` | Impersonal clauses and clitic referents; preserve technical symbols and argument roles |
| Turkish | Tatoeba `fas-tur`; UD Turkish | Suffixes carrying negation, possibility and reported evidence; dotted/dotless I; do not strip endings as noise |
| Korean | FLORES `kor_Hang` paired with `pes_Arab` | Predicate endings and omitted arguments; mixed-script terms and compound boundaries; scientific→Persian quality unverified |
| Hindi | FLORES `hin_Deva` paired with `pes_Arab` | Combining signs, negation and agreement; lakh/crore and digit grouping; scientific→Persian quality unverified |
| Urdu | FLORES `urd_Arab`; PALI | Preserve ہ/ے/ں and aspirated forms in originals; Urdu is not Persian with different spelling; resolve numerical grouping |
| Hebrew | NI `task1113_ted_translation_he_fa`; Unicode | Preserve pointed originals and names; RTL does not imply Arabic joining; inspect abbreviations and referents |
| Polish | NI `task1263_ted_translation_pl_fa` | Case roles, compound terminology and decimal notation; examples are TED, not journal validation |
| Galician | NI `task1245_ted_translation_gl_fa` | Identify it independently of Spanish/Portuguese; inspect technical equivalents in context |
| Tajik / Dari | FLORES `tgk_Cyrl` / `prs_Arab`; variety research | Script conversion alone does not adapt terminology or register; preserve source variety and target choice |

For **any other language**, use the identification/research procedure above and
write a short job-specific profile: evidence, segmentation risks, negation/modality,
number conventions, terminology, names and script/font needs. Absence from this
table does not reject the source; inability to understand it limits the review.
Never manufacture a dedicated repository or a tested-language badge.

## Protect meaning across scripts

- Keep verbatim originals unmodified in `source/`. Normalize only translated Persian
  prose. Do not run whole-document NLP cleaning that deletes stopwords, diacritics,
  numbers, URLs, paragraph breaks or distinct Arabic/Urdu letters.
- Decode quantities from the source locale before formatting ordinary translated
  prose with the skill's Western-digit convention. `1.234,5` can mean `1234.5`;
  decimal/grouping marks are not interchangeable. Preserve original notation in
  formulas, code, identifiers and quotations. Do not convert units or calendars.
- Keep a concept's original spelling and optional established English alias in
  `terms.tsv`; choose Persian by concept and discipline. Never pivot every proper
  name through English or apply English plural stripping to a non-English word.
- Translate heading functions in any source language: `摘要`, `Zusammenfassung`
  and `Résumé` may label an abstract, but inspect context before assigning چکیده.
- Original bibliography entries and requested quotations keep their language and
  script. Isolate by that span's direction and choose a font with its glyphs.
  Arabic/Urdu/Hebrew originals stay RTL; Latin/Cyrillic/CJK spans normally stay LTR.
  Do not label a non-English quote English merely to silence a checker.

## Narrow checker exceptions for preserved originals

The mechanical checker is Persian-oriented, not a multilingual proofreader.
In HTML, declare the actual `lang` on retained foreign spans and use `cite`, `q`
or `blockquote` for original identities/quotations; `data-source-identity="true"`
marks other explicitly preserved identities. English morphology checks respect
these boundaries. TeX `latin` blocks preserve original source passages. Ordinary
LTR term isolates are not automatically original titles: mark their identity or
use the narrow documented exception with source evidence.
If a correctly preserved source quote triggers a Persian-only rule, keep the
quote on its own line and use the existing `fa-lint: allow <check-id>` comment on
that line or immediately before it. Record language, source location and reason.
For example, `arabic-letters` may be waived for the exact Arabic `كتاب علمي`;
Persian translated prose must still use `کتاب علمی`. A foreign original ending in
`s` may need the specific `en-plural` exception; do not singularize its name.
Never use `allow all`, a document-wide waiver or a fake code block. Check the exact
source quote manually; neighboring Persian and unrelated checks must remain active.
Only real source comments can waive a rule; attribute text cannot. Waivers stay
within the original file when literal TeX chapters are included.

## Completion evidence

Before `done`, every selected source span has a target location or an explicit
reason to remain original. Inspect equations, table cells, captions and notes as
well as paragraphs. Record actual source-language review coverage and unresolved
ambiguities. A fluent Persian draft, back-translation, language-code match or clean
lint result alone does not establish scientific fidelity.
