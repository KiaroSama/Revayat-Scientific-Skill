# Review mode

Use for a translation's review stage or a user-requested audit of an existing
translation. A review-only request produces findings first. If the user already
requested corrections or a completed translation, apply necessary corrections
within that scope and review the changed spans again; no extra approval loop.

## Inputs and review scope

Read the original, editable translation, source-language profile, inventory,
coverage map, selected terminology revision and progress. The source can be in
any language; [source-languages.md](source-languages.md) governs interpretation.
If the original is absent, assess Persian fluency/presentation only and disclose
that fidelity cannot be verified. A translation PDF alone cannot prove the source
was preserved. Record reviewer identity/mode and exactly which parts were read.

## L0 — Mechanical checks

Run strict lint with the job's explicit level, terms and scoped figure manifest.
Use the full manifest for the assembled document, part-specific manifests for
partial files. Check findings against their source context; the checker cannot
resolve scientific senses or proofread every retained source language.

```bash
"$PY" "$SKILL_DIR/scripts/revayat-scientific.py" lint "$WORK/doc.tex" --level "$LEVEL" --terms "$WORK/terms.tsv" --manifest "$WORK/manifest.txt" --strict
```

A narrowly documented quote exception may be valid. Never hide a real Persian
error or use `allow all` to obtain a green result. Fixing punctuation must not
rewrite code, URLs, formulas, identifiers or original-language quotations.

## L1 — Meaning and scientific force

For a full translation, compare every selected source part with its target;
check critical claims, numbers, equations, table cells, captions, notes and cited
relationships. Sampling is useful for triage or an explicitly scoped audit, but
must not be reported as full-document review.

Inspect actor, action/relation, condition, quantifier, negation, modality and
reference target. Prioritize added/omitted claims, sign or exponent changes,
wrong units, correlation→causation, no-significance→equivalence, and misleading
rounding. Check source-language endings and qualifiers before approving Persian.
Back-translate a small set of difficult hedges/numerical statements **into the
original language** as an additional diagnostic, then compare with the actual
original. English pivot agreement or the same model agreeing with itself is not
independent evidence. Unreadable source material remains unresolved.

## L2 — Terms and document context

Use the same `terms.tsv` revision used for the draft. Prefer the approved form
for the matching concept, domain and source language. Keep exact identifiers;
allow established Persian multi-word concepts at `journal`. Do not treat a house
system-document ban as proof that a scholarly Persian equivalent is wrong.
Check repeated names, pronoun antecedents and abbreviations across part boundaries.
Neighbor context is for interpretation, not duplicate output. Source or term changes
invalidate affected review status; re-review these spans instead of trusting a stale
checkpoint. The checker does not enforce sense-specific preferred Persian forms.

## L3 — Persian readability

Read target prose alone against [scientific-style.md](scientific-style.md) and
[fluency-gold.md](fluency-gold.md). Flag unclear predicates, ambiguous ezafe chains,
word-for-word source structure, excessive nominalization and unnecessary foreign
jargon. Judge verbs/passives in context; do not turn editorial preference into an
accuracy error. Preserve author voice and scientific force while improving flow.
After a fluency edit, return to L1 for the changed span.

## L4 — Page and image fidelity

Follow [layout-and-images.md](layout-and-images.md). Measure output physical page
sizes/orientations and applicable print boxes against the source inventory. Inspect
all unusual page classes and all modified/low-resolution figures, plus first,
middle and last page samples. Verify original pixel information, effective PPI,
aspect ratio, labels, scale bars, source order and unmodified scientific evidence.
A larger pixel count does not prove successful enhancement.

Inspect actual rendered pages for Persian joining, punctuation, script glyphs,
clipping, table relationships and complete math. Keep original Arabic/Urdu/Hebrew
quotes RTL and appropriate LTR source spans isolated. Do not diagnose visual order
from extracted text alone or claim that selecting a font proves correct shaping.
Generic build verification does not automatically compare original page geometry.

## L5 — Completeness and handoff

Reconcile `coverage.tsv` with the source inventory. Each location appears once in
its intended role or has a recorded reason to remain original. Check for missing,
duplicate, empty, truncated or source-mismatched parts. Identical paragraphs at
different source locations remain distinct; a content hash alone is not an ID.
Figures match the manifest; tables/notes/appendices and a source contents page are
accounted for. Reflow may change page count, not source coverage or physical format.
Check actual output paths and the translation log beside the delivered file.

## Finding records and acceptance

Each finding records: source location/language, exact source and target spans,
category, severity, consequence, correction and recheck status. Categories are
accuracy, terminology, fluency, locale/notation, layout/image or completeness.
Severity follows consequence: `critical` changes a central scientific/safety claim;
`major` changes meaning or loses content; `minor` impairs presentation without
changing meaning; `preference` is an equally accurate editorial alternative.
This is an adapted review vocabulary, not a calibrated MQM score or certification.

Resolve critical/major findings before marking the affected part `done`. Record
minor unresolved limits explicitly. Do not hide a critical error in an average
score or claim unseen parts passed. Report `self-review`, the actual separate
reviewer or `unreviewed`; model count alone does not establish independence.

Lead the report with usability and scope, then actionable findings, policy-correct
borderline cases and unperformed/engine-limited checks. Record corrections and
their reasons throughout the translation log. A final fluent paragraph is not a
substitute for a traceable source comparison.
