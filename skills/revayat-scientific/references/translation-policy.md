# Translation and review roles

Use the current host's available model and tools. Vendors, model names and parallel agents are optional. Respect the user's model and delegation choices.

## One-model workflow

Translate a bounded section, strict-lint it, compare with the source for fidelity, then read the Persian alone for fluency. Revise flagged spans without changing claims, quantities, hedges or terms. Record `self-review` in `progress.md`; this is not independent review.

## Independent review

Delegate a bounded review only when available and authorized. The translator owns the output; the reviewer returns exact source/target spans and reasons. Use a judge only for unresolved disagreements, with source and competing spans instead of duplicate full drafts. Record actual reviewer and coverage. Without a reviewer, use the one-model workflow and disclose that limitation.

## Translation brief

Translate directly from the identified original language into clear scholarly Persian. Read its profile in `source-languages.md`, the selected terminology revision and adjacent source context. Follow `terms.tsv` and the selected level; established Persian multi-word concepts belong in journal prose. Preserve claims, uncertainty, negation, numbers, units, equations, protected originals and citations. Isolate retained text by its own script direction. Translate only the assigned source locations, not overlap supplied for context. Return source/target locations and unresolved meaning-changing ambiguities.

## Fidelity brief

Compare the original-language source and target for additions, omissions, changed certainty, wrong numbers/units, lost negation and incorrect references. Check the same glossary revision and coverage map. Return exact source/target spans, category, consequence-based severity and a bounded correction. Distinguish direct review from a pivot-only check. An unclear source remains unclear; do not invent a scientific resolution.

## Fluency brief

Read against `scientific-style.md` and `fluency-gold.md`. Flag awkward structure, unnatural collocations, excessive nominalization and ordinary words unnecessarily kept English. Preserve technical terms and epistemic force. Return `OK` or one line per finding:

```text
FLAG | exact target span | reason | faithful correction
```

Review revised spans again. Record `fluency: ok|revised|unreviewed`, review mode and coverage. Mark a part `done` after required mechanical and reading checks; changed source or terminology invalidates affected parts.
