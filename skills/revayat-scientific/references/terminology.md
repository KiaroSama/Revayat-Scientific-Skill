# Terminology policy

This file owns the choice between Persian concepts and preserved source terms.
`scientific-style.md` owns register; `rtl-bidi.md` owns direction. The source can
be in any language: follow [source-languages.md](source-languages.md) at intake.
Choose terms for the actual discipline, audience and sense, not a generic word list.

## Level and audience

| Level | Select for | Terminology treatment |
| --- | --- | --- |
| `journal` | Scientific papers, theses, research reviews and scholarly books | Prefer established Persian concepts, including multi-word terms; give the original designation at first use when useful |
| `system-docs` | Operational manuals, product/API documentation, installation guides and runbooks | Preserve exact tooling names and the familiar operational lexicon; translate ordinary explanation into Persian |

Choose `journal` for a research paper even though the helper CLI's legacy default
is `system-docs`. Pass the selected level explicitly to lint/build. A technical book
is not automatically a system manual: infer genre from its content. The user's
explicit choice wins. Both modes preserve equations, identifiers, citation targets,
proper-name identity and official artifact names.

A concept does not become English-only because it is central to a paper or contains
two to five words. For example, causal effect can be اثر علّی, confidence interval
فاصلهٔ اطمینان, and reference implementation پیاده‌سازی مرجع in journal prose.
Those are candidate discipline-appropriate forms, not a replacement for the source
or the user's approved glossary. Keep `PyTorch`, `PCR`, `HTTP`, `Adam`, `p`,
`fit(x)`, DOI strings and executable option names exact.

## Decide in context

Apply the first matching rule to the complete source concept:

0. **Generic document label:** translate the function into Persian in every source
   language: abstract, methods, figure, appendix and contents. A heading containing
   an artifact name can have Persian explanatory words around its exact name.
1. **Verbatim identity or notation:** preserve source spelling for code, identifiers,
   official product/model/standard names, units, formulas and reference entries.
   Do not force Arabic, Cyrillic or CJK names through an invented English spelling.
2. **Approved concept:** use the job's preferred form for the same sense, source
   language and domain. A glossary of another meaning does not override context.
3. **Journal concept:** use familiar, accurate scholarly Persian for descriptive
   technical terms, including multi-word phrases. Give the original term once if
   it aids lookup or disambiguation. If no reliable Persian equivalent exists,
   retain the original and record the choice as provisional until reviewed.
4. **System-document term:** retain a defined command, configuration label or
   operational term where the original form is what practitioners use. Preserve a
   kept multi-word label as a whole; do not translate half of its locked identity.
5. **Ordinary prose:** write natural Persian. An ordinary verb or noun does not
   need an English isolate merely because it occurs in a scientific document.

For a close decision, consult the source definition, an approved glossary and
comparable publications in that discipline. Record the source/evidence and reason.
Neither a rare coinage nor the shortest English form is automatically superior.
A disputed community proposal is a candidate, not a settled standard.

## One concept, one preferred form

Create `WORK/terms.tsv` before drafting; retain it with the editable document.
Use [the template](../assets/terms.tsv). Existing required columns stay compatible:
`source`, `output`, `step`, `count`, `forbidden_fa`. Recommended columns:
`concept`, `status`, `admitted`, `deprecated`. For multilingual jobs, the agent may
add `source_lang`, `context` and `evidence`; the current checker ignores these extra
columns, so the fidelity reviewer must inspect them.

- Key a choice by sense and discipline. Selection bias, estimator bias and neural
  network bias need separate concept decisions; the spelling bias alone is not a
  sufficient identifier. Do not replace every occurrence of an ambiguous word.
- Distinguish a translated descriptive name from a quoted identifier. Original
  source aliases and an official English alias, if one exists, can aid lookup.
- `preferred` governs output; `admitted` is not a second interchangeable preferred.
  Mark uncertainty in notes rather than inventing an authoritative equivalent.
- Record the selected ledger revision with each reviewed part. Drafting, reviewing
  and resuming use that same ledger. An explicitly supplied unreadable glossary is
  an error; do not silently substitute another or overwrite user corrections.
- When a term changes, find affected parts and review those spans and nearby
  references. A source or glossary change invalidates their prior review status.
- Reuse neighbor context to resolve pronouns and repeated names. Keep the source
  text and its scientific meaning as the authority when a ledger entry is wrong.

## First mention, morphology and direction

In `journal`, introduce a useful original designation once after the Persian term;
subsequent mentions use the preferred Persian form. Repeated parenthetical English
is noise. In `system-docs`, retained operational terms normally need no gloss.

Keep the full retained expression together and isolate it according to its own
script. Latin/Cyrillic/CJK normally use LTR; Arabic/Urdu/Hebrew originals use RTL.
Use [source-languages.md](source-languages.md) for non-Persian quote exceptions and
font checks. Do not reverse character order or remove diacritics from originals.

For an ordinary retained English term, Persian plural morphology may use
`\en{service}ها`. Preserve true names such as `Windows` and source-language titles
unchanged. English plural rules do not apply to French, German or other original
forms. Avoid ambiguous affix glue; rephrase the Persian sentence around the exact
identifier when needed. Do not apply a system-docs half-translation heuristic to
forbid accurate scholarly Persian descriptions around a named algorithm.

## Mechanical coverage and its limits

`term-pairs.tsv` contains the house system-document bans. Its `system-docs` rows,
including descriptive multi-word labels, are skipped at `journal`. The optional
`all` value remains available for explicitly justified rules applying to both
levels. A word's presence in a house table is not evidence about every discipline.

The checker also reads job terms. Its legacy keep-original Latin rows require an
actual `forbidden_fa` counterform and may forbid `deprecated` forms. Use concrete
wrong alternatives, never invented filler merely to fill a cell. Terms whose exact
identity needs preservation but has no useful global ban can be recorded as
protected source objects in the inventory and checked in fidelity review.
The checker does not understand word senses or language-specific inflection.
Do not globally ban a Persian form that is valid for another concept in the same
file. Separate the relevant part's ledger/scope and review the ambiguity explicitly.

```bash
"$PY" "$SKILL_DIR/scripts/revayat-scientific.py" lint "$WORK/doc.tex" --level "$LEVEL" --terms "$WORK/terms.tsv" --manifest "$WORK/manifest.txt" --strict
```

A clean result proves only the implemented string/structure checks. Verify preferred
Persian outputs, context, definitions and source-language meaning by reading.
Do not modify the shipped glossary during a translation job; capture job-specific
knowledge with that job so later agents can resume it.
