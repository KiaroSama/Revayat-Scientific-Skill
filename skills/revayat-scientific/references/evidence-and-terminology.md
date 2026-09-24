# Source-based terminology and scientific evidence

Use this after identifying the actual source language and document genre. A
published corpus, dictionary or another skill provides candidates; the source
paper and the job's reviewed decisions determine the translation. Keep
unpublished or restricted material local unless its owner authorizes a specific
external processing route.

## One brief per reviewed source part

After checking extraction order, run the packaged helper on a reviewed UTF-8
text or Markdown part and the job's `terms.tsv`:

```bash
python scripts/revayat-scientific.py term-brief source/part-01.txt --terms terms.tsv --language ja > term-brief-01.json
```

The helper reads only those two local files. Its JSON records their SHA-256
revisions, the identified language/variety, approved ledger rows actually found,
and source line/column locations. Different outputs for one source form are
marked ambiguous. Unmatched, rejected and unresolved rows do not become
translation instructions. Text without a matched row is a valid `no-matches`
result, not evidence that the source has no important terminology.
At most 64 locations per term are reported; `more_matches` marks truncation.
The brief is for selecting context, not a completeness count.

The helper does not translate, detect language, infer scientific senses, evaluate
glossary quality or approve a citation. It scans exact original-script forms;
Latin words require word boundaries, while CJK candidate matching also finds
terms inside unspaced text. Inspect each reported passage and context. Do not
normalize away Arabic/Urdu letters, Chinese variety, diacritics, code identifiers
or decimal punctuation to force a match. Record accepted concepts in the same
job ledger and rerun affected parts if that ledger changes. Log this stage beside
the translation file under the main skill's logging rule.

## Bind critical claims to original evidence

During source-fidelity review, identify every important claim, numerical value,
formula, table relation and citation target by a stable source location, then
locate its Persian target. For each one, record the original proposition,
qualifier or value, target location, review outcome and unresolved question in
the job's `coverage.tsv` or a local review ledger. Preserve separate rows for
repeated identical text at different locations.

Check negation, comparison group, condition, causality, uncertainty, units,
denominator, time point, signs, exponents and references against the original.
The abstract states the authors' claim, methods specify what was done, results
report findings and discussion interprets limits; keep each section's role and
register without adding certainty or invented conclusions. A fluent sentence or
a model's agreement with itself is not evidence of source fidelity.

Verify DOI, title, author and publication metadata against the cited original or
an authoritative record when available. If the source bibliography is the only
record, preserve its entries and mark unverified metadata. Search results and
other articles' reference lists are leads, not proof. Never complete missing
citations, results, approvals or disclosures with plausible details. Missing,
failed and inconclusive checks remain visible until the owner resolves them.

The workflow applies to any source language. External examples and corpora are
not bundled; research direction, license, domain and register are checked per
job in [source-languages.md](source-languages.md) and
[research-sources.md](research-sources.md).
