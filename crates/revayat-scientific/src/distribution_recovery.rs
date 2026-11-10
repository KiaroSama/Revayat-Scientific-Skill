//! Recover a complete installation plan without dropping cancellation evidence.
use super::*;
use crate::publication::{cancelled, retain_cancellation, retain_cancellation_after, retain_recovery};

pub(super) struct Root {
    pub(super) path: PathBuf,
    pub(super) identity: ObjectId,
}
impl Root {
    pub(super) fn verify(&self) -> Result<()> {
        directory_path(&self.path)?;
        ensure!(
            path_object_id(&self.path)? == self.identity,
            "installation recovery directory ownership changed"
        );
        Ok(())
    }
}

pub(super) fn rollback(
    error: anyhow::Error,
    targets: &[Target],
    recovery: Option<&Root>,
    created: &[(PathBuf, ObjectId)],
    observe: &mut impl FnMut(InstallBoundary, &Path) -> Result<()>,
) -> Result<Vec<PathBuf>> {
    let mut unresolved = false;
    let mut secondary = Vec::new();
    for (index, target) in targets.iter().enumerate().rev() {
        let restored = (|| -> Result<()> {
            observe(InstallBoundary::BeforeRestore(index), &target.destination)?;
            directory_path(&target.destination)?;
            directory_path(&target.stage)?;
            directory_path(&target.backup)?;
            if target.prepared.is_some() && same(&target.destination, &target.prepared) {
                ensure!(!target.stage.exists(), "stage occupied during rollback");
                fs::rename(&target.destination, &target.stage)?;
            }
            if target.old.is_some() && !same(&target.destination, &target.old) {
                ensure!(
                    !target.destination.exists() && same(&target.backup, &target.old),
                    "cannot safely restore previous installation"
                );
                observe(InstallBoundary::BeforeBackupRestore(index), &target.destination)?;
                fs::rename(&target.backup, &target.destination)?;
            }
            observe(InstallBoundary::AfterRestore(index), &target.destination)?;
            ensure!(same(&target.destination, &target.old), "installation rollback incomplete");
            Ok(())
        })();
        if let Err(cancellation) = restored.as_ref()
            && cancelled(cancellation)
        {
            return Err(retain_cancellation_after(Some(error), restored.unwrap_err(), secondary)
                .context("installation rollback cancelled; complete owned recovery plan retained"));
        }
        if let Err(failure) = restored {
            // Exact-old reconciliation permits cleanup, not diagnostic loss.
            unresolved |= !same(&target.destination, &target.old);
            secondary.push(failure);
        }
    }
    for target in targets {
        if path_object_id(&target.lock).ok() != Some(target.lock_identity) {
            unresolved = true;
            secondary.push(anyhow::anyhow!("installation lock ownership changed"));
        }
    }
    if unresolved {
        return Err(retain_recovery(Some(error), secondary)
            .context("installation recovery required; complete owned plan retained"));
    }
    let error = if secondary.is_empty() {
        error
    } else {
        retain_recovery(Some(error), secondary)
            .context("installation failed; rollback completed with secondary diagnostics")
    };
    let cleaned = (|| -> Result<()> {
        for (index, target) in targets.iter().enumerate() {
            observe(InstallBoundary::BeforeStageCleanup(index), &target.stage)?;
        }
        cleanup(targets, recovery, created)
    })();
    if let Err(cancellation) = cleaned {
        return Err(if cancelled(&cancellation) {
            retain_cancellation(Some(error), cancellation)
                .context("installation cleanup cancelled; complete owned recovery plan retained")
        } else {
            retain_recovery(Some(error), vec![cancellation])
                .context("installation cleanup needs recovery; owned plan retained")
        });
    }
    Err(error)
}
pub(super) fn cleanup(
    targets: &[Target],
    recovery: Option<&Root>,
    created: &[(PathBuf, ObjectId)],
) -> Result<()> {
    if let Some(root) = recovery {
        root.verify()?;
    }
    for target in targets {
        if target.stage.exists() {
            ensure!(
                path_object_id(&target.stage).ok() == target.stage_identity,
                "stage ownership changed; recovery required"
            );
            fs::remove_dir_all(&target.stage)?;
        }
        ensure!(
            path_object_id(&target.lock)? == target.lock_identity,
            "lock ownership changed; recovery required"
        );
        fs::remove_file(&target.lock)?;
    }
    if let Some(root) = recovery {
        root.verify()?;
        fs::remove_dir_all(&root.path)?;
    }
    for (path, id) in created.iter().rev() {
        if path_object_id(path).ok() == Some(*id) {
            let _ = fs::remove_dir(path);
        }
    }
    Ok(())
}
