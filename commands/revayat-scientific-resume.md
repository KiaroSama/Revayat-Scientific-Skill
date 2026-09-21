---
description: Resume a scientific translation from its source inventory, terms and progress ledger.
argument-hint: [working directory]
---

Use `revayat-scientific` to resume the job in `$ARGUMENTS`.

Read the skill, then the job's `inventory.md`, `terms.tsv`, `manifest.txt` and
`progress.md` and `coverage.tsv`. Preserve source language/variety, translation route,
selected terminology revision, page/image inventory and output directory.
Reuse the job's recorded parallel-work choice; if absent, ask before activating
subagents. Reconcile unfinished assignments and stale drafts using
`references/parallel-work.md`; only the coordinator merges canonical output.
Read the previous translation log and start the new run's log beside the translation
file, referring to that previous log. Append each resumed action and correction.
Compare the current source and translated parts with those records; re-review
affected parts when source or terminology changed. Continue the first unfinished
part using `references/long-documents.md`. Do not restart unchanged approved work.

If records are missing, inspect the existing source and output before rebuilding
the inventory. Report the missing evidence and never infer that an absent review
passed. Finish with the same strict, PDF and visual gates as a new translation.
