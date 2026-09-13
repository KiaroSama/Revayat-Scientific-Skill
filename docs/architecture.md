# Architecture

`skills/revayat-scientific/` is the entire distributable payload. Its entrypoint routes an agent through source inventory, concept decisions, translation, review and verification; references own their detailed policies.

`scripts/revayat-scientific.py` maps portable commands to the existing Python helpers or OS-native build scripts. `runtime.py` owns per-run logging, subprocess deadlines and termination. The scientific checker remains the owner of mechanical rules. The agent owns translation, semantic review and visual inspection; no script simulates these decisions.

`install/install.py` stages allowlisted payload files before replacing an installation, retaining its previous copy. Shell entrypoints share this implementation. `tools/package.py` uses the same payload selection. Tests exercise public commands, installed packages and scientific fixtures; CI adds actual renderer checks.

Job data stays outside the installed skill: preserved sources, inventory, terms, figure manifest, progress, editable document and delivered PDF. A failed build or requested verification preserves the previous delivered PDF. Logs contain operation names, durations and exit codes, not document text.
