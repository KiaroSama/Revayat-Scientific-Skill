# Installation integrity

The Rust installer is a bounded, recoverable directory transaction. It copies a complete allowlisted skill payload, including its native executable, and never links an installed skill back to the checkout.

## Admission

Payload identity requires simple unambiguous skill frontmatter. Payload addresses are unique under conservative case comparison; links, junctions, reparse points, nonregular entries, hidden files, job data and interpreter implementations are excluded or refused. Payloads are limited to 64 MiB and 10,000 files. Existing trees are bounded to 100,000 entries and 512 MiB; counted hashes and native object identity detect changes during inspection.

Destination admission walks components before filesystem normalization. It refuses parent traversal, linked/reparse components, case collisions, nested targets, source/implementation overlap and reserved stage/backup/recovery paths. Git discovery resolves worktree markers, separate/private/common directories, object databases, configured hooks and selected indexes. Ambiguous or failed discovery fails closed. Existing Git files and their known hardlink aliases remain protected.

## Preparation and activation

All selected destinations are preflighted before any old installation moves. Cooperative exclusive locks identify the owning operation. All stage directories are created with normal destination inheritance, and an initial complete recovery plan records their native identities before copying. Copies are checked against one captured payload; source bytes are checked again after staging. The complete prepared journal is refreshed before activation.

The destructive boundary rechecks destination snapshots, staged contents, directory paths and lock ownership. Old installations move to a sibling `skill-backups` area outside normal skill discovery, then complete staged directories become active. Previous editions remain available after success.

## Failure and recovery

A failed batch restores targets in reverse order. Native identity reconciles operations that completed before reporting an error. A concurrent foreign destination, changed backup, substituted stage or replaced lock is preserved, and cannot be deleted to force a successful rollback. Incomplete restoration or cleanup retains the complete journal, backups, stages and locks and reports a local recovery location. Do not delete them until every target in the plan has been resolved.

Locks coordinate cooperating installers; directory rename is not a global multi-target atomic transaction. These checks are not a substitute for a secure host filesystem or a sandbox against an attacker with equivalent access.

Regression coverage lives in the native [installation tests](../crates/revayat-scientific/tests/distribution_install.rs). The migration inventory records the original scenario IDs, including failure injection, concurrent edits, retained recovery evidence, ambiguous identity, multi-target rollback and native Windows junction refusal.
