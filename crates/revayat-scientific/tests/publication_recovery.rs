use anyhow::bail;
use revayat_scientific::publication::{Boundary, publish_observed};
use std::{
    fs,
    path::{Path, PathBuf},
};
fn plans(root: &Path) -> [(PathBuf, PathBuf); 2] {
    let entries = [
        (root.join("a"), root.join("first")),
        (root.join("b"), root.join("second")),
    ];
    for (s, d) in &entries {
        fs::write(s, b"candidate").unwrap();
        fs::write(d, b"approved").unwrap();
    }
    entries
}
fn artifacts(root: &Path) -> Vec<PathBuf> {
    fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".revayat-publish-")
        })
        .collect()
}
#[test]
fn test_interrupted_rollback_retains_previous_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let entries = plans(temp.path());
    let error = publish_observed(&entries, &[], None, |event, dest| {
        if event == Boundary::AfterCommit && dest == entries[1].1 {
            bail!("controlled publication failure");
        }
        if event == Boundary::BeforeRollback && dest == entries[1].1 {
            bail!("second interruption during rollback");
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("needs recovery"));
    let artifacts = artifacts(temp.path());
    assert!(
        artifacts
            .iter()
            .filter(|p| p.is_dir())
            .any(|p| fs::read(p.join("previous")).is_ok_and(|b| b == b"approved"))
    );
    assert!(
        artifacts
            .iter()
            .any(|p| p.extension().is_some_and(|e| e == "lock"))
    );
}
#[test]
fn test_completed_file_restoration_error_preserves_previous_bytes_and_cleans() {
    let temp = tempfile::tempdir().unwrap();
    let entries = plans(temp.path());
    let mut restored = false;
    let error = publish_observed(&entries, &[], None, |event, dest| {
        if event == Boundary::AfterCommit && dest == entries[0].1 {
            bail!("controlled publication failure");
        }
        if event == Boundary::AfterRollback {
            restored = true;
            bail!("native restore completed before reporting error");
        }
        Ok(())
    })
    .unwrap_err();
    assert!(restored);
    assert!(!error.to_string().contains("needs recovery"));
    assert_eq!(fs::read(&entries[0].1).unwrap(), b"approved");
    assert!(artifacts(temp.path()).is_empty());
}
#[test]
fn test_later_restore_failure_keeps_whole_batch_and_foreign_destination() {
    let temp = tempfile::tempdir().unwrap();
    let entries = plans(temp.path());
    let error = publish_observed(&entries, &[], None, |event, dest| {
        if event == Boundary::AfterCommit && dest == entries[1].1 {
            fs::write(&entries[0].1, b"foreign revision")?;
            bail!("controlled failure");
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("needs recovery"));
    assert_eq!(fs::read(&entries[0].1).unwrap(), b"foreign revision");
    let artifacts = artifacts(temp.path());
    assert_eq!(
        artifacts
            .iter()
            .filter(|p| p.join("recovery.json").is_file())
            .count(),
        2
    );
    assert_eq!(
        artifacts
            .iter()
            .filter(|p| p.extension().is_some_and(|e| e == "lock"))
            .count(),
        2
    );
}
#[test]
fn test_unchanged_publication_cleans_only_owned_paths() {
    let temp = tempfile::tempdir().unwrap();
    let entries = plans(temp.path());
    let foreign = temp.path().join("foreign");
    fs::create_dir(&foreign).unwrap();
    fs::write(foreign.join("sentinel"), b"foreign data").unwrap();
    let displaced = temp.path().join("displaced-recovery");
    let mut changed = None;
    let error = publish_observed(&entries, &[], None, |event, _| {
        if event == Boundary::BeforeCleanup && changed.is_none() {
            let owned = artifacts(temp.path())
                .into_iter()
                .find(|p| p.is_dir())
                .unwrap();
            fs::rename(&owned, &displaced)?;
            fs::rename(&foreign, &owned)?;
            changed = Some(owned);
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("cleanup needs recovery"));
    assert_eq!(
        fs::read(changed.unwrap().join("sentinel")).unwrap(),
        b"foreign data"
    );
    assert!(displaced.join("recovery.json").is_file());
    assert!(displaced.join("previous").is_file());
}
#[test]
fn test_absent_destination_completed_rollback_unlink_is_reconciled() {
    let temp = tempfile::tempdir().unwrap();
    let stage = temp.path().join("stage");
    let dest = temp.path().join("dest");
    fs::write(&stage, b"candidate").unwrap();
    let mut restored = false;
    let error = publish_observed(&[(stage, dest.clone())], &[], None, |event, _| {
        if event == Boundary::AfterCommit {
            bail!("controlled publication failure");
        }
        if event == Boundary::AfterRollback {
            restored = true;
            bail!("unlink completed before reporting interruption");
        }
        Ok(())
    })
    .unwrap_err();
    assert!(restored);
    assert!(!dest.exists());
    assert!(!error.to_string().contains("needs recovery"));
    assert!(artifacts(temp.path()).is_empty());
}
#[test]
fn test_publication_cleanup_cancellation_retains_journal_and_owned_lock() {
    let temp = tempfile::tempdir().unwrap();
    let entries = plans(temp.path());
    let error = publish_observed(&entries, &[], None, |event, _| {
        if event == Boundary::BeforeCleanup {
            bail!("controlled cleanup interruption");
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("cleanup needs recovery"));
    let artifacts = artifacts(temp.path());
    assert_eq!(
        artifacts
            .iter()
            .filter(|p| p.join("recovery.json").is_file())
            .count(),
        2
    );
    assert_eq!(
        artifacts
            .iter()
            .filter(|p| p.extension().is_some_and(|e| e == "lock"))
            .count(),
        2
    );
    assert_eq!(fs::read(&entries[0].1).unwrap(), b"candidate");
}
