# Installation admission, batch publication and recovery

The Python installer and both native launchers share one contract. An invocation
plans **all** selected destinations, reads the payload once, stages every new copy
and verifies its bytes before replacing any existing installation. A late invalid
target or failed copy cannot leave an earlier agent silently upgraded.

## Destination admission

`--dest` remains an explicit final directory, not permission to replace arbitrary
user data. An existing nonempty directory must have a UTF-8 `SKILL.md` whose
frontmatter identifies exactly `name: revayat-scientific`; `--force` is additionally
required. An existing empty directory is replaceable with `--force`. A missing,
ambiguous or different skill identity requires a separately reviewed manual
migration, not a forced overwrite. This identity is a safety marker, not proof of
trust or authentication of downloaded code.

Source/destination overlap, implementation folders, filesystem root, `.git`
components, detected repository administration, links/junctions/reparse points,
case collisions and overlapping target sets are refused before replacement.
Source and old-installation trees must contain regular files/directories; linked
content requires manual review rather than implicit copying. This deliberately
includes Windows reparse points, not just POSIX-style symlinks.

The source and target repository contexts are checked with read-only Git path
queries, including separate Git directories and worktree/common administration.
A detected repository requires Git and unambiguous metadata resolution. Source
archives with no repository do not acquire a new Git dependency. This is not a
search of every repository or mounted filesystem on the machine.

Backups, owned stages and recovery-storage paths cannot be selected as new targets.
Normal `<agent>/skills/revayat-scientific` replacements retain their old directory
under `<agent>/skill-backups/revayat-scientific-<run>-<index>`, outside normal skill
discovery. For other explicit parent names, the backup folder is a sibling
`skill-backups` directory; custom host discovery rules must exclude it. Existing
backups are never overwritten. Backup and target must share a filesystem.

## Staging and publication

`install/install_paths.py` owns directory/path admission.
`install/install_transaction.py` owns the bounded payload snapshot, target plan,
cooperative locks, staging, recovery journal and whole-invocation rollback.
`install/install.py` retains agent selection, payload allowlisting and the public
CLI. Native launcher options and detected host directories are unchanged.

Source SHA-256 values and staged bytes must match the selected payload snapshot.
A source change or concurrent change to an existing installation aborts instead
of combining versions or overwriting a local edit. Stop running work that writes
inside the installation before replacing it. Payloads are limited to 64 MiB and
10000 files; inspected existing trees are limited to 512 MiB and 100000 entries.
Exceeding a limit is a refused operation, not partial installation.

Directories used as final stages retain normal parent permission/ACL inheritance.
The private recovery journal does not become the final installation. Each target
has an exclusively created `.revayat-install-<digest>.lock`; another invocation
must not remove or ignore it. After every target has been published and cleanup
has succeeded, the installer prints completion and retained-backup paths.

## Failure and recovery

Before replacing anything, the installer writes `recovery.json` beneath a private
`.revayat-install-recovery-<run>` directory. The prepared record identifies every
destination, stage, previous-backup path and directory identity. It contains
operational paths, not document contents or credentials.

On an ordinary copy/admission failure, existing installations remain unchanged.
On a later publication failure or interrupt, newly installed directories are
withdrawn and all earlier installations are restored in reverse order. Rollback
identifies its own directory objects; an unexpected concurrent directory is not
deleted just to force a clean result.

When safe restoration fails, the operation reports **recovery required** and keeps
the journal, original backups, owned stages and locks. Do not retry with `--force`
or delete all `.revayat-*` paths. Under the owner's Rules, stop other installers,
read the named journal, inspect **every** target and retain any concurrent user
changes. Restore each verified previous directory from its retained backup (or
remove only the verified new copy for a previously absent target), then verify
all destinations and finish cleanup. Record recovery evidence before releasing
only this operation's locks. A stale lock is not proof that no recovery is needed.

Cleanup failures are also non-success outcomes with a retained recovery location;
an already published complete set is not misreported as rolled back. Logs use the
shared timestamped INFO/WARNING/ERROR/DEBUG facility and do not include file bodies.

This is recoverable multi-target publication with cooperative concurrency checks,
**not** one globally atomic filesystem operation, a crash-proof database, an
adversarial filesystem sandbox or protection against arbitrary same-user mutation
between OS calls. A machine crash, lost volume or hostile parent-directory swap
requires operator recovery; no automatic deletion is justified by a missing path.

## Research and acceptance

The implementation adapts contracts rather than importing a package manager:

- [pip's stashed uninstall paths](https://github.com/pypa/pip/blob/main/src/pip/_internal/req/req_uninstall.py): retain a reversible move plan. Unlike an uninstall, Revayat retains successful previous editions and never deletes a concurrent foreign destination during recovery.
- [Python shutil](https://docs.python.org/3.10/library/shutil.html): distinguish rename, copy and deletion, including symlink/junction limitations. A fallback cross-device copy is not an atomic rename.
- [Git administrative path resolution](https://git-scm.com/docs/git-rev-parse): discover the real private/common/object/index/hooks paths rather than assuming `.git` is always a directory.
- [Microsoft junctions and reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions): test native Windows junctions and preserve parent ACL inheritance.
- [Spec Kit workflow](https://github.github.com/spec-kit/reference/agentic-sdd.html): carry reproductions and closure tests through the owner's configured chain and explicitly selected private feature, not an invented public plan.

`tests/test_install_transaction.py` exercises full-plan refusal, actual copying,
source identity, aliasing, injected late failures/interrupts, concurrent changes,
recovery retention, privacy and native Windows junctions. Existing package tests
still install and launch the real distribution through Bash/PowerShell, test
Windows ACL inheritance and execute installed DOCX/PDF and terminology helpers.
A successful install is not proof of every host's user-interface discovery or
scientific correctness of a later translation.
