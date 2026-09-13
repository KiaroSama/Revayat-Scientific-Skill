# Translation and review roles

Use the current host's available model and tools. Vendors, model names and parallel agents are optional. Respect the user's model and delegation choices.

## One-model workflow

Translate a bounded section, strict-lint it, compare with the source for fidelity, then read the Persian alone for fluency. Revise flagged spans without changing claims, quantities, hedges or terms. Record `self-review` in `progress.md`; this is not independent review.

## Independent review

Delegate a bounded review only when available and authorized. The translator owns the output; the reviewer returns exact source/target spans and reasons. Use a judge only for unresolved disagreements, with source and competing spans instead of duplicate full drafts. Record actual reviewer and coverage. Without a reviewer, use the one-model workflow and disclose that limitation.

## Translation brief

Translate into clear formal Persian. Follow `terms.tsv` and the selected level. Preserve claims, uncertainty, negation, numbers, units, equations and citations. Use one LTR isolate per complete English cluster. Return the assigned translation and any claim-changing ambiguity with its source span.

## Fidelity brief

Compare for additions, omissions, changed certainty, wrong numbers/units, lost negation and incorrect references. Check terms. Return exact source span, target span, consequence and bounded correction. An unclear source remains unclear; do not invent a scientific resolution.

## Fluency brief

Read against `scientific-style.md` and `fluency-gold.md`. Flag awkward structure, unnatural collocations, excessive nominalization and ordinary words unnecessarily kept English. Preserve technical terms and epistemic force. Return `OK` or one line per finding:

```text
FLAG | exact target span | reason | faithful correction
```

Review revised spans again. Record `fluency: ok|revised|unreviewed`, review mode and coverage. Mark a part `done` after required mechanical and reading checks; changed source or terminology invalidates affected parts.
