//! Recoverable publication of a checked file set. Refuse aliases and foreign
//! revisions; retain journals and locks whenever recovery cannot be proved.
use crate::identity::{Fingerprint, ObjectId, file_identity, is_link, object_id, path_object_id};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use unicode_casefold::UnicodeCaseFold;
#[path = "publication_cancellation.rs"]
mod cancellation;
pub(crate) use cancellation::retain_cancellation_after;
pub use cancellation::{
    Cancellation, RecoveryFailures, RetainedPrimary, cancelled, retain_cancellation,
    retain_recovery,
};

fn absolute(path: &Path) -> Result<PathBuf> {
    let raw = std::path::absolute(path)?;
    let mut normalized = PathBuf::new();
    for part in raw.components() {
        match part {
            Component::CurDir => (),
            Component::ParentDir => {
                ensure!(normalized.pop(), "invalid parent path");
            }
            _ => normalized.push(part.as_os_str()),
        }
    }
    Ok(normalized)
}

fn path_identity(path: &Path) -> Result<Option<ObjectId>> {
    if !path.try_exists()? {
        return Ok(None);
    }
    Ok(Some(path_object_id(path)?))
}

fn fingerprint(path: &Path, max_bytes: Option<u64>) -> Result<Option<Fingerprint>> {
    if !path.try_exists()? {
        return Ok(None);
    }
    Ok(Some(file_identity(path, max_bytes)?))
}

fn case_key(path: &Path) -> String {
    // Full Unicode default case folding preserves the legacy collision contract
    // on every platform, including ligatures and non-Latin filename spellings.
    path.to_string_lossy().to_lowercase().case_fold().collect()
}

pub fn validate_destination(destination: &Path, sources: &[PathBuf]) -> Result<PathBuf> {
    // Inspect components BEFORE normalization so a linked directory followed by
    // .. cannot make the checked path differ from the OS-resolved destination.
    let raw = std::path::absolute(destination)?;
    for part in raw.ancestors() {
        ensure!(
            !is_link(part)?,
            "output path must not contain links or junctions"
        );
    }
    let destination = absolute(&raw)?;
    ensure!(
        !destination.try_exists()? || fs::metadata(&destination)?.is_file(),
        "output destination must be a regular file"
    );
    let parent = destination.parent().context("output has no parent")?;
    if parent.is_dir() {
        for sibling in fs::read_dir(parent)? {
            let sibling = sibling?.path();
            if case_key(&sibling) == case_key(&destination)
                && sibling.file_name() != destination.file_name()
            {
                bail!("output collides with an existing case-variant filename");
            }
        }
    }
    let id = path_identity(&destination)?;
    for source in sources {
        let source_absolute = absolute(source)?;
        ensure!(
            source_absolute != destination,
            "output destination aliases a protected source"
        );
        if let (Some(destination_id), Some(source_id)) = (id, path_identity(source)?) {
            ensure!(
                destination_id != source_id,
                "output destination aliases a protected source"
            );
        }
    }
    Ok(destination)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    /// Windows inherited candidate closed, before ownership validation. Path is candidate.
    InheritedCandidateReady,
    /// Backup closed, before ownership validation. Path is backup.
    BackupPrepared,
    BackupReady,
    BeforeCommit,
    BeforeReplace,
    AfterCommit,
    BeforeRollback,
    AfterRollback,
    BeforeCleanup,
    BeforeBackupDisposal,
}

/// Hooks identify real publication boundaries for deterministic failure/race
/// regressions. The production implementation is the same I/O path with no hook.
pub fn publish_files(
    entries: &[(PathBuf, PathBuf)],
    protected: &[PathBuf],
    max_bytes: Option<u64>,
) -> Result<()> {
    publish_observed(entries, protected, max_bytes, |_, _| Ok(()))
}

#[derive(Serialize)]
struct Recovery {
    destination: PathBuf,
    stage: PathBuf,
    backup: PathBuf,
    previous: Option<Fingerprint>,
    lock: PathBuf,
    lock_identity: ObjectId,
}

struct HeldLock {
    path: PathBuf,
    identity: ObjectId,
    file: File,
}

struct Entry {
    recovery: Recovery,
    directory: PathBuf,
    directory_identity: ObjectId,
    published: Option<Fingerprint>,
    backup_identity: Option<ObjectId>,
}

fn owned(path: &Path, identity: ObjectId) -> Result<()> {
    ensure!(
        !is_link(path)? && path_identity(path)? == Some(identity),
        "publication object ownership changed"
    );
    Ok(())
}

fn copied(
    source: &Path,
    destination: &Path,
    max_bytes: Option<u64>,
    created: &mut Option<ObjectId>,
    boundary: &mut impl FnMut(Boundary, &Path) -> Result<()>,
) -> Result<()> {
    let original = file_identity(source, max_bytes)?;
    // Create in the destination's parent so native Windows ACL inheritance is
    // preserved, without copying a private stage's DACL or granting access.
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let id = object_id(&output)?;
    *created = Some(id);
    let mut input = File::open(source)?;
    let count = std::io::copy(
        &mut (&mut input).take(original.size.saturating_add(1)),
        &mut output,
    )?;
    ensure!(
        count == original.size,
        "publication source changed during copying"
    );
    output.set_times(fs::FileTimes::new().set_modified(original.modified))?;
    output.sync_all()?;
    drop(input);
    drop(output);
    boundary(Boundary::BackupPrepared, destination)?;
    owned(destination, id)?;
    ensure!(
        file_identity(source, max_bytes)? == original,
        "publication source changed during copying"
    );
    ensure!(
        file_identity(destination, max_bytes)?.same_bytes(&original),
        "publication copied backup differs"
    );
    Ok(())
}

#[cfg(windows)]
fn prepare_inherited_stage(
    stage: &Path,
    parent: &Path,
    max_bytes: Option<u64>,
    boundary: &mut impl FnMut(Boundary, &Path) -> Result<()>,
) -> Result<()> {
    let original = file_identity(stage, max_bytes)?;
    let candidate = tempfile::Builder::new()
        .prefix(".revayat-publish-")
        .tempfile_in(parent)?;
    let (mut output, candidate) = candidate.keep()?;
    let id = object_id(&output)?;
    let result = (|| -> Result<()> {
        let mut input = File::open(stage)?;
        let count = std::io::copy(
            &mut (&mut input).take(original.size.saturating_add(1)),
            &mut output,
        )?;
        ensure!(
            count == original.size,
            "publication stage changed during inherited preparation"
        );
        output.set_times(fs::FileTimes::new().set_modified(original.modified))?;
        output.sync_all()?;
        owned(&candidate, id)?;
        ensure!(
            file_identity(stage, max_bytes)? == original,
            "publication stage changed during inherited preparation"
        );
        ensure!(
            file_identity(&candidate, max_bytes)?.same_bytes(&original),
            "inherited stage differs"
        );
        // Close both files before rename on Windows.
        drop(input);
        drop(output);
        boundary(Boundary::InheritedCandidateReady, &candidate)?;
        owned(&candidate, id)?;
        ensure!(
            file_identity(stage, max_bytes)? == original,
            "publication stage changed after inherited preparation"
        );
        ensure!(
            file_identity(&candidate, max_bytes)?.same_bytes(&original),
            "inherited stage changed after close"
        );
        fs::rename(&candidate, stage)?;
        Ok(())
    })();
    let cleanup = (|| -> Result<()> {
        if candidate.try_exists()?
            && !is_link(&candidate)?
            && path_identity(&candidate)? == Some(id)
        {
            fs::remove_file(&candidate)?;
        }
        Ok(())
    })();
    if let Err(error) = cleanup {
        return Err(retain_recovery(result.err(), vec![error])
            .context("inherited stage cleanup needs recovery; candidate retained"));
    }
    result
}

pub fn publish_observed(
    entries: &[(PathBuf, PathBuf)],
    protected: &[PathBuf],
    max_bytes: Option<u64>,
    boundary: impl FnMut(Boundary, &Path) -> Result<()>,
) -> Result<()> {
    publish_with_identity(entries, protected, max_bytes, boundary, file_identity)
}

pub fn publish_with_identity(
    entries: &[(PathBuf, PathBuf)],
    protected: &[PathBuf],
    max_bytes: Option<u64>,
    mut boundary: impl FnMut(Boundary, &Path) -> Result<()>,
    mut inspect: impl FnMut(&Path, Option<u64>) -> Result<Fingerprint>,
) -> Result<()> {
    let stages: Vec<PathBuf> = entries
        .iter()
        .map(|(s, _)| absolute(s))
        .collect::<Result<_>>()?;
    let all_protected: Vec<PathBuf> = protected
        .iter()
        .cloned()
        .chain(stages.iter().cloned())
        .collect();
    let mut destinations = Vec::new();
    let mut keys = HashSet::new();
    let mut ids = Vec::new();
    for ((_, destination), stage) in entries.iter().zip(&stages) {
        let destination = validate_destination(destination, &all_protected)?;
        ensure!(
            keys.insert(case_key(&destination)),
            "duplicate output destination in publication plan"
        );
        ensure!(
            !is_link(stage)? && stage.is_file(),
            "staged output must be a regular non-linked file"
        );
        ensure!(
            destination.parent().is_some_and(Path::is_dir),
            "output parent is unavailable"
        );
        let stage_id = object_id(&File::open(stage)?)?;
        let parent_id = path_object_id(destination.parent().unwrap())?;
        ensure!(
            stage_id.volume == parent_id.volume,
            "stage and destination must be on the same filesystem"
        );
        if let Some(id) = path_identity(&destination)? {
            ensure!(!ids.contains(&id), "output destinations alias each other");
            ids.push(id);
        }
        destinations.push(destination);
    }
    let mut locks: Vec<HeldLock> = Vec::new();
    let mut plans: Vec<Entry> = Vec::new();
    let mut committed = Vec::new();
    let operation = (|| -> Result<()> {
        let mut ordered = destinations.clone();
        ordered.sort_by_key(|p| case_key(p));
        for destination in ordered {
            let digest = format!("{:x}", Sha256::digest(case_key(&destination).as_bytes()));
            let path = destination
                .parent()
                .unwrap()
                .join(format!(".revayat-publish-{}.lock", &digest[..24]));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            locks.push(HeldLock {
                identity: object_id(&file)?,
                path,
                file,
            });
        }
        for (stage, destination) in stages.iter().zip(&destinations) {
            validate_destination(destination, protected)?;
            #[cfg(windows)]
            prepare_inherited_stage(
                stage,
                destination.parent().unwrap(),
                max_bytes,
                &mut boundary,
            )?;
            let previous = if destination.try_exists()? {
                Some(inspect(destination, max_bytes)?)
            } else {
                None
            };
            let published = inspect(stage, max_bytes)?;
            let temp = tempfile::Builder::new()
                .prefix(".revayat-publish-")
                .tempdir_in(destination.parent().unwrap())?;
            let directory = temp.keep();
            let directory_identity = path_object_id(&directory)?;
            let backup = directory.join("previous");
            let lock = locks
                .iter_mut()
                .find(|l| {
                    l.path.parent() == destination.parent()
                        && l.path.file_name().unwrap().to_string_lossy().contains(
                            &format!("{:x}", Sha256::digest(case_key(destination).as_bytes()))
                                [..24],
                        )
                })
                .unwrap();
            plans.push(Entry {
                recovery: Recovery {
                    destination: destination.clone(),
                    stage: stage.clone(),
                    backup: backup.clone(),
                    previous: previous.clone(),
                    lock: lock.path.clone(),
                    lock_identity: lock.identity,
                },
                directory,
                directory_identity,
                published: Some(published),
                backup_identity: None,
            });
            let plan = plans.last_mut().unwrap();
            let journal = plan.directory.join("recovery.json");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&journal)?;
            serde_json::to_writer_pretty(&mut file, &plan.recovery)?;
            file.sync_all()?;
            writeln!(lock.file, "{}", journal.display())?;
            lock.file.sync_all()?;
            drop(file);
            if let Some(original) = &previous {
                copied(
                    destination,
                    &backup,
                    max_bytes,
                    &mut plan.backup_identity,
                    &mut boundary,
                )?;
                ensure!(
                    fingerprint(destination, max_bytes)?.as_ref() == Some(original),
                    "destination changed before publication"
                );
            }
            boundary(Boundary::BackupReady, destination)?;
        }
        for (index, plan) in plans.iter().enumerate() {
            let recovery = &plan.recovery;
            boundary(Boundary::BeforeCommit, &recovery.destination)?;
            validate_destination(&recovery.destination, protected)?;
            ensure!(
                fingerprint(&recovery.destination, max_bytes)? == recovery.previous,
                "destination changed before publication"
            );
            ensure!(
                fingerprint(&recovery.stage, max_bytes)? == plan.published,
                "stage changed before publication"
            );
            committed.push(index);
            boundary(Boundary::BeforeReplace, &recovery.destination)?;
            // rename replaces files atomically on supported Unix and Windows.
            // On Windows std::fs::rename uses MoveFileExW(REPLACE_EXISTING).
            fs::rename(&recovery.stage, &recovery.destination)?;
            boundary(Boundary::AfterCommit, &recovery.destination)?;
        }
        Ok(())
    })();
    let mut failures = Vec::new();
    let mut secondary = Vec::new();
    if operation.is_err() {
        for &index in committed.iter().rev() {
            let plan = &plans[index];
            let recovery = &plan.recovery;
            let mut retained = None;
            let restored = (|| -> Result<()> {
                boundary(Boundary::BeforeRollback, &recovery.destination)?;
                validate_destination(&recovery.destination, protected)?;
                let current = fingerprint(&recovery.destination, max_bytes)?;
                if current == recovery.previous {
                    return Ok(());
                }
                ensure!(
                    current == plan.published,
                    "published destination changed before rollback"
                );
                if let Some(original) = &recovery.previous {
                    owned(
                        &recovery.backup,
                        plan.backup_identity
                            .context("backup ownership was not recorded")?,
                    )?;
                    let backup = file_identity(&recovery.backup, max_bytes)?;
                    ensure!(
                        backup.same_bytes(original),
                        "previous backup changed before rollback"
                    );
                    retained = Some(backup.clone());
                    fs::rename(&recovery.backup, &recovery.destination)?;
                    boundary(Boundary::AfterRollback, &recovery.destination)?;
                    ensure!(
                        file_identity(&recovery.destination, max_bytes)? == backup,
                        "restored destination changed during rollback"
                    );
                } else {
                    fs::remove_file(&recovery.destination)?;
                    boundary(Boundary::AfterRollback, &recovery.destination)?;
                    ensure!(
                        !recovery.destination.try_exists()?,
                        "destination reappeared during rollback"
                    );
                }
                Ok(())
            })();
            if let Err(error) = &restored
                && cancelled(error)
            {
                return Err(retain_cancellation_after(
                    operation.err(),
                    restored.unwrap_err(),
                    secondary,
                )
                .context("publication rollback cancelled; owned recovery records retained"));
            }
            if let Err(restore_error) = restored {
                // A native operation can complete before its caller observes an
                // error. Reconcile only the exact recorded backup object (or
                // proven absence), never a same-looking foreign replacement.
                let reconciled = (|| -> Result<bool> {
                    validate_destination(&recovery.destination, protected)?;
                    let current = fingerprint(&recovery.destination, max_bytes)?;
                    Ok(if recovery.previous.is_none() {
                        current.is_none()
                    } else {
                        retained.is_some()
                            && current == retained
                            && !recovery.backup.try_exists()?
                    })
                })()
                .unwrap_or(false);
                if !reconciled {
                    failures.push(plan.directory.join("recovery.json"));
                }
                secondary.push(restore_error);
            }
        }
    }
    if !failures.is_empty() {
        return Err(retain_recovery(operation.err(), secondary)
            .context("publication rollback needs recovery; owned records retained"));
    }
    let operation = if secondary.is_empty() {
        operation
    } else {
        Err(retain_recovery(operation.err(), secondary)
            .context("publication failed; rollback completed with secondary diagnostics"))
    };
    let cleanup = (|| -> Result<()> {
        for plan in &plans {
            boundary(Boundary::BeforeCleanup, &plan.recovery.destination)?;
            owned(&plan.directory, plan.directory_identity)?;
        }
        for lock in &locks {
            owned(&lock.path, lock.identity)?;
        }
        // Validate the complete backup set before removing any recovery data.
        // A foreign later backup must not cause earlier owned backups to vanish.
        for plan in &plans {
            let path = &plan.recovery.backup;
            if path.try_exists()? {
                owned(
                    path,
                    plan.backup_identity
                        .context("backup ownership was not recorded")?,
                )?;
            }
        }
        for plan in &plans {
            let path = &plan.recovery.backup;
            if path.try_exists()? {
                owned(
                    path,
                    plan.backup_identity
                        .context("backup ownership was not recorded")?,
                )?;
                boundary(Boundary::BeforeBackupDisposal, path)?;
                owned(path, plan.backup_identity.unwrap())?;
                fs::remove_file(path)?;
            }
        }
        // Windows disallows deleting open lock handles: close them explicitly.
        let paths: Vec<_> = locks.iter().map(|l| (l.path.clone(), l.identity)).collect();
        drop(locks);
        for (path, id) in paths.into_iter().rev() {
            owned(&path, id)?;
            fs::remove_file(path)?;
        }
        for plan in &plans {
            owned(&plan.directory, plan.directory_identity)?;
            fs::remove_dir_all(&plan.directory)?;
        }
        Ok(())
    })();
    if let Err(error) = cleanup {
        return Err(if cancelled(&error) {
            retain_cancellation(operation.err(), error)
                .context("publication cleanup cancelled; owned recovery records retained")
        } else {
            retain_recovery(operation.err(), vec![error])
                .context("publication cleanup needs recovery; owned records retained")
        });
    }
    operation
}
