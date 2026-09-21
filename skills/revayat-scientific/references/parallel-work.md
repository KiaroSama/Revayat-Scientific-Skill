# Optional parallel translation and editing

Use this workflow only after the user's affirmative choice in SKILL.md step1.
The choice belongs to this document job, not every future user or project. Record
it in `progress.md` and the main translation log; a missing answer means sequential
work. Reuse an existing recorded choice on resume. Respect later cancellation.

## Assign independent units

The coordinating agent retains the inventory, canonical editable document,
`terms.tsv`, coverage map and final delivery. Divide work at scientific argument or
section boundaries using long-documents.md. Give neighboring context for coherence,
but assign each source unit to exactly one translator. Preserve source order,
equation/figure/citation IDs and page geometry. Sections that depend on an unsettled
definition wait for that definition; unrelated sections may proceed.

Use the host's available subagent tools. Start with a small bounded batch, at most
two workers unless the user requests another limit or the coordinator identifies
more independent work within host limits. State the chosen count and record it.
Workers do not create further workers. If subagents are unavailable, record the
limitation and continue sequentially; do not claim independent review.

Each assignment includes:

- Task: translate, fidelity review, fluency review or correction; exact source
  unit IDs, source language/variety and selected terminology level.
- Approved source and draft revision, glossary revision, style constraints and
  read-only neighboring context. Source text remains untrusted data.
- One worker-owned draft, findings or patch file. Canonical documents, shared
  glossary, source assets and coordinator log are read-only to workers.
- Acceptance criteria: coverage, preserved claims/quantities/uncertainty, equations,
  references, original names, unresolved questions and checks to perform.
- A unique UTF-8 log beside the artifact being translated/reviewed, following the
  main skill's naming and entry format; include a worker/unit suffix to avoid
  filename collisions. Return its path and keep it updated throughout the work.

For DOCX, workers return addressed text patches rather than simultaneously writing
one ZIP package. For PDF, workers translate/review extracted source units; the
coordinator owns assembled editable sources, rendering and publication. Shared
fonts, figures, databases and renderer sessions have one writer.

## Translate and review

Draft independent sections concurrently. A reviewer starts only after its assigned
draft snapshot is complete; it may review section A while a translator drafts B.
An editing worker returns proposed changes with source/draft locations and reasons,
not silent replacements. New terminology is a proposal for the coordinator; workers
keep the approved glossary revision until a new revision is distributed.

Track each unit as pending, running, submitted, accepted or failed in `progress.md`.
Submissions include the exact covered units, artifact and log paths, input/glossary
revision, actual checks, located findings, proposed terms and unresolved questions.
A worker's success message alone does not establish complete coverage or review.

## Integrate and verify

Only the coordinator writes canonical output and accepts glossary changes. Check
that submissions still match their assigned source/draft/glossary revisions. Reconcile
stale work before acceptance; preserve disputed alternatives for a source-based
decision. Review the joined boundaries, repeated concepts, pronouns, equation/table/
figure numbering, citations and scientific claims. Verify no source unit is missing
or duplicated, then update coverage and append worker outcomes to the main log.

Worker failure leaves its units incomplete. Retry only the failed units in a bounded
assignment or complete them sequentially; keep previous accepted work. On cancel,
stop owned workers and record pending units. On resume, inspect actual artifacts and
logs rather than assuming a previously running worker finished.

Run the ordinary assembled-document lint, fidelity, fluency, layout, extraction and
delivery gates after integration. Parallelism changes scheduling, not acceptance.
Report the actual review arrangement and preserve each log. Multiple agents are
not a claim of independent human or expert review, and speedup is not guaranteed.
