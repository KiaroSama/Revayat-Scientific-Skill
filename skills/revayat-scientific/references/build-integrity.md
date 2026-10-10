# Checked inputs and build-artifact integrity

Both native `build` adapters create a temporary per-run record before linting.
It reserves the working PDF, final PDF and, with `--verify`, three preview paths.
A destination cannot alias a checked source, included fragment, explicit image,
terms ledger or figure manifest, even through a hardlink. Source extension alone
does not decide whether a path is protected: a TSV supplied as `terms.pdf` is
still an input. Linked output paths and case/name collisions remain refused.
The shared publisher checks lexical ancestors with `lstat`, including Windows
reparse attributes on Python 3.11; it does not rely on `Path.is_junction`, which
was added in Python 3.12. Missing future paths remain usable; inspection errors
fail closed. This source policy is separate from observed native CI enforcement.

The record fingerprints the selected source closure, sidecars, explicit assets
and original requested source when engine selection chooses a sibling. The HTML
renderer contributes actual consumed resources, including CSS-only images and
fonts. TeX records the bytes copied into its isolated input tree, including
approved local fonts. The standalone TeX controller also hashes originals before
copying and checks both original and staged input bytes before use and after
backend cleanup. Resource-policy and container isolation controls remain
independent and mandatory; a fingerprint never grants resource access.

Recheck the snapshots between lint, render, verification and delivery. A missing
or changed input fails the run; preserve the user's new input rather than rolling
it back. Rerun the complete build against that revision. A rendered working PDF is
sealed to its exact SHA-256, and guarded final publication requires those bytes,
not merely a plausible PDF produced by another job with the same filename.
Records have strict schema/duplicate-key validation, at most 8192 inputs and 4 MiB
of metadata; a hashed file is limited to 512 MiB. Existing lower source, renderer
and process deadlines still apply. Hashes are not semantic review or signatures.

Delivery compares counted SHA-256 observations before and after copying and against
the sealed rendered digest, without allocating two complete PDFs. Every read is
at most 1 MiB and the observed initial file size plus one growth-detection byte
bounds the complete read. Pre/post path and opened-descriptor observations
(device, inode, size and modification time) must agree; each path/descriptor
channel's own change time must also stay stable. Windows can report different
change/creation times across those channels after a metadata-preserving copy, so
they are not conflated. Truncation, growth, path substitution or ordinary revision
changes refuse publication.

The shared publisher uses that initial-size budget by default, preserving callers'
existing admission policies rather than imposing a new universal artifact cap.
An explicit `max_file_bytes` may tighten a caller's budget; build/delivery hashing
still applies its 512 MiB limit. Crop/embedded-image pixel limits, image metadata,
DOCX package limits and installation's 64 MiB payload limit remain separate.
Copied backups have different device/inode identity: comparison deliberately uses
size, modification time and exact byte digest for copy validation, then the
recorded backup object for restoration. No hash is cached across mutable revisions.

## Verification samples

`verify-SLUG-first.png`, `verify-SLUG-last.png` and `verify-SLUG-mid.png` are reserved
only when verification is requested. Input figures with those names must be
renamed or a different output slug selected; the build refuses before replacing
any protected input. A CSS-only collision discovered during rendering refuses
before the working PDF is published. Without `--verify`, those names remain
ordinary usable input filenames.

Render samples inside the owned per-run staging directory. Validate the complete
PNG batch and all current snapshots, then use the common recoverable publication
helper. Do not delete an existing user path to make room for a raster. A late
raster failure publishes none of that batch; a failed replacement rolls earlier
replacements back. Every successful raster batch refreshes all three roles.
For one page all roles refer to page 1; for two pages the middle role is page 1.
This avoids misleading last/middle samples remaining from a longer previous PDF.

Samples are diagnostic artifacts, not approval. They may remain after a later
text-order failure so a reviewer can inspect the failed candidate. A working PDF
can likewise be newer than the delivered edition when verification fails. The
previous final delivery stays unchanged on failed guards/verification. Do not
claim an atomic transaction across the working PDF, previews and a final file on
another filesystem. A published file's own staged replacement and rollback use
`publication.py`. It records attempted replacements before the OS call and
reconciles observed state if a move completes before raising. Copied backup bytes
are verified before activation and again before restoration; a changed backup is
retained for recovery, never trusted to overwrite a current edition. Existing
recovery-manifest behavior remains authoritative. Recovery is marked unresolved
before restoration starts: a second `KeyboardInterrupt` or `SystemExit` retains
all remaining recovery records and owned locks and propagates with a location
note. Do not erase this evidence even if the last interrupted move completed;
the rest of the batch still needs reconciliation. Ordinary completed-then-raised
restoration is recognized only by the recorded object and byte identity. A
foreign changed destination is never deleted to force rollback.

Each recovery record names its destination, copied backup, stage and owned lock
identity; the lock contains that record's path. Successful restoration removes
only this operation's temporary paths. Cleanup failure is non-success, even if
the complete candidate is already published; retain the named evidence and inspect
the actual locations before releasing locks. Stage paths owned by a caller can
be removed by that caller's context manager, so a record names an intended
location, not a guarantee that every unactivated candidate remains available.

On Windows, a private caller staging directory can give its files a protected
owner-only ACL that survives rename. Before activation, the publisher creates an
exact-byte candidate with normal destination-parent inheritance and moves it back
to the caller's staged path. Activation still uses that staged path; its file
object identity may change while its verified bytes remain the same. Previous
backups likewise start as destination-parent-inherited files before the checked
metadata-preserving copy. No ACL is granted or edited, and arbitrary custom ACL
preservation is not promised. Native inheritance tests require nonempty access
rules and fail on inspection errors; empty failed queries are never equivalence.

## Limits and evidence

The record coordinates cooperating build stages. It is not authentication,
filesystem locking, crash durability, or protection against a privileged writer
repeatedly replacing and restoring files between checks. Do not intentionally run
concurrent builds against the same mutable working filename. A forced process
kill may leave an owned staging directory; never broadly delete similarly named
user directories. Ordinary exits clean only the current run's staging directory.

Tests bind source/sidecar/asset identity, runtime CSS resources, renderer output
identity, whole-batch preview publication and native Bash/PowerShell behavior.
Synthetic TeX mutation tests exercise the actual controller with a controlled
backend; real Docker/XeLaTeX remains the separate mandatory scientific tier.
Visual inspection of the PDF is still required for scientific and RTL fidelity.

The Linux scientific CI tier also runs a bounded, harmless probe through the
production container launch options. It observes read-only input/root mounts,
allowed output/temporary writes, absence of a dummy host-only environment value,
non-root execution, dropped capabilities, no-new-privileges, effective CPU/memory/
process/file limits, bounded temporary storage and an isolated network namespace.
The required tier fails if its runtime or observations are unavailable, and checks
owned container cleanup. These are specific enforcement regressions, not a complete
security audit, proof against every container escape, or real-job translation
approval. The test never inspects actual credentials or contacts a deployed endpoint.

## Primary research used for this design

- [Python temporary directories](https://docs.python.org/3/library/tempfile.html):
  use owned per-run staging instead of predictable destructive filenames.
- [Python filesystem replacement](https://docs.python.org/3/library/os.html#os.replace):
  staged rename is not a multi-file, cross-filesystem transaction.
- [WeasyPrint resource/security guidance](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#security):
  preserve constrained fetching and inspect actual resources, not only img tags.
- [atomicwrites](https://github.com/untitaker/python-atomicwrites): reviewed as a
  same-filesystem publication reference, not adopted; upstream labels it unmaintained.
- [Hypothesis](https://github.com/HypothesisWorks/hypothesis): optional future
  stateful failure-interleaving tests, not a new runtime dependency or a claim that
  property tests ran in this audit.
- [Spec Kit workflows](https://github.github.com/spec-kit/reference/workflows.html):
  bind these acceptance cases to the owner's existing feature and configured chain.
