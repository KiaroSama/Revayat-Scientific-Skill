# Translation and review roles

Follow the [six-stage workflow](multi-agent-workflow.md) on every translation. Use the current host's tools and the requested model where available. Record the actual reviewer and coverage. Only a host that physically lacks spawning can use the disclosed sequential fallback; record `self-review` in `progress.md` for both review passes in that mode.

## Independent review

Stages 3 and 6 use separate reviewers who did not write, apply or repair the translation. Reviewers return exact source/target locations and reasons. The coordinator validates findings before the Stage 4 integrator applies them and routes unresolved disagreements with the source and competing spans. A missing review stays unverified.

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
