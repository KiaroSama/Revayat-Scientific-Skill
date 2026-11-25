---
description: Translate a scientific source into Persian and prepare a reviewed, verified PDF.
argument-hint: [source file or URL]
---

Use the `revayat-scientific` skill for `$ARGUMENTS`. Resolve and read `skills/revayat-scientific/SKILL.md` from this plugin's root, then follow its source, terminology, review and delivery workflow. Ask for the source only if it was not supplied. Report actual output paths and unverified stages.

On every run, follow `skills/revayat-scientific/references/multi-agent-workflow.md`.
Dispatch a separate agent for each of its six ordered stages. If the host
physically lacks subagent spawning, disclose that limit and execute the same six
prompts as separate passes. A failed or denied spawn does not qualify.
