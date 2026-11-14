use anyhow::bail;
use revayat_scientific::{
    identity::path_object_id,
    publication::{
        Boundary, Cancellation, RecoveryFailures, RetainedPrimary, publish_files, publish_observed,
    },
};
use std::{
    fs,
    path::{Path, PathBuf},
};
fn plans(root: &Path) -> [(PathBuf, PathBuf); 2] {
    let entries = [
        (root.join("a"), root.join("first")),
        (root.join("b"), root.join("second")),
    ];
    for ((s, d), label) in entries.iter().zip(["A", "B"]) {
        fs::write(s, format!("candidate {label}")).unwrap();
        fs::write(d, format!("approved {label}")).unwrap();
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
fn retained(root: &Path, count: usize) -> Vec<serde_json::Value> {
    let values = artifacts(root);
    let records = values
        .iter()
        .filter(|p| p.join("recovery.json").is_file())
        .map(|directory| {
            let path = directory.join("recovery.json");
            let record: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            let lock = Path::new(record["lock"].as_str().unwrap());
            assert_eq!(
                record["lock_identity"],
                serde_json::to_value(path_object_id(lock).unwrap()).unwrap()
            );
            assert_eq!(
                fs::read_to_string(lock).unwrap().trim(),
                path.to_str().unwrap()
            );
            record
        })
        .collect::<Vec<_>>();
    assert_eq!(records.len(), count);
    assert_eq!(
        values
            .iter()
            .filter(|p| p.extension().is_some_and(|e| e == "lock"))
            .count(),
        count
    );
    records
}
#[test]
fn test_interrupted_rollback_retains_previous_bytes() {
    for cancellation in [Cancellation::Signal, Cancellation::Requested] {
        for completed in [false, true] {
            for (interrupted_index, earlier_failure) in [(0, false), (1, false), (0, true)] {
                let temp = tempfile::tempdir().unwrap();
                let root = temp.path().canonicalize().unwrap();
                let entries = plans(&root);
                let mut interrupted = false;
                let error = publish_observed(&entries, &[], None, |event, dest| {
                    let activation = if interrupted_index == 0 && !earlier_failure {
                        Boundary::BeforeCommit
                    } else {
                        Boundary::AfterCommit
                    };
                    if event == activation && dest == entries[1].1 {
                        bail!("controlled second activation failure");
                    }
                    if earlier_failure && event == Boundary::AfterRollback && dest == entries[1].1 {
                        bail!("earlier ordinary restore diagnostic");
                    }
                    let restoration = if completed {
                        Boundary::AfterRollback
                    } else {
                        Boundary::BeforeRollback
                    };
                    if dest == entries[interrupted_index].1 && event == restoration {
                        interrupted = true;
                        return Err(anyhow::Error::new(cancellation)
                            .context("controlled second cancellation"));
                    }
                    Ok(())
                })
                .unwrap_err();
                assert!(interrupted);
                assert_eq!(error.downcast_ref::<Cancellation>(), Some(&cancellation));
                let primary = error.downcast_ref::<RetainedPrimary>().unwrap();
                assert!(
                    primary
                        .0
                        .to_string()
                        .contains("controlled second activation failure")
                );
                let failures = &error.downcast_ref::<RecoveryFailures>().unwrap().0;
                assert_eq!(failures.len(), if earlier_failure { 2 } else { 1 });
                if earlier_failure {
                    assert!(
                        failures[0]
                            .to_string()
                            .contains("earlier ordinary restore diagnostic")
                    );
                    assert!(!format!("{error:#}").contains("earlier ordinary restore diagnostic"));
                }
                assert_eq!(
                    failures.last().unwrap().downcast_ref::<Cancellation>(),
                    Some(&cancellation)
                );
                assert!(!format!("{error:#}").contains("controlled second activation failure"));
                assert!(format!("{error:#}").contains("recovery"));
                assert!(!format!("{error:#}").contains(root.to_str().unwrap()));
                let records = retained(&root, 2);
                let destination = &entries[interrupted_index].1;
                let record = records
                    .iter()
                    .find(|r| r["destination"] == destination.to_str().unwrap())
                    .unwrap();
                let previous = if completed {
                    destination.as_path()
                } else {
                    Path::new(record["backup"].as_str().unwrap())
                };
                let label = ["A", "B"][interrupted_index];
                assert_eq!(
                    fs::read(previous).unwrap(),
                    format!("approved {label}").as_bytes()
                );
                assert_eq!(
                    fs::read(destination).unwrap(),
                    format!(
                        "{} {label}",
                        if completed { "approved" } else { "candidate" }
                    )
                    .as_bytes()
                );
                if interrupted_index == 0 {
                    assert_eq!(fs::read(&entries[1].1).unwrap(), b"approved B");
                }
            }
        }
    }
}
#[test]
fn test_completed_file_restoration_error_preserves_previous_bytes_and_cleans() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let entries = plans(&root);
    let mut restored = false;
    let error = publish_observed(&entries, &[], None, |event, dest| {
        if event == Boundary::BeforeCommit && dest == entries[1].1 {
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
    assert!(
        error
            .to_string()
            .contains("rollback completed with secondary diagnostics")
    );
    assert!(
        error
            .downcast_ref::<RetainedPrimary>()
            .unwrap()
            .0
            .to_string()
            .contains("controlled publication failure")
    );
    assert_eq!(error.downcast_ref::<RecoveryFailures>().unwrap().0.len(), 1);
    assert!(!format!("{error:#}").contains("controlled publication failure"));
    assert!(!error.to_string().contains("needs recovery"));
    assert_eq!(fs::read(&entries[0].1).unwrap(), b"approved A");
    assert_eq!(fs::read(&entries[1].1).unwrap(), b"approved B");
    assert!(artifacts(&root).is_empty());
}
#[test]
fn test_later_restore_failure_keeps_whole_batch_and_foreign_destination() {
    for failed_second_restore in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let entries = plans(&root);
        let error = publish_observed(&entries, &[], None, |event, dest| {
            if event == Boundary::AfterCommit && dest == entries[1].1 {
                fs::write(&entries[0].1, b"foreign revision")?;
                bail!("controlled failure");
            }
            if failed_second_restore && event == Boundary::BeforeRollback && dest == entries[1].1 {
                bail!("controlled second restore failure");
            }
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("needs recovery"));
        assert!(
            error
                .downcast_ref::<RetainedPrimary>()
                .unwrap()
                .0
                .to_string()
                .contains("controlled failure")
        );
        assert_eq!(
            error.downcast_ref::<RecoveryFailures>().unwrap().0.len(),
            if failed_second_restore { 2 } else { 1 }
        );
        assert_eq!(fs::read(&entries[0].1).unwrap(), b"foreign revision");
        assert_eq!(
            fs::read(&entries[1].1).unwrap(),
            if failed_second_restore {
                b"candidate B".as_slice()
            } else {
                b"approved B"
            }
        );
        let records = retained(&root, 2);
        if failed_second_restore {
            let mut backups = records
                .iter()
                .map(|r| fs::read(r["backup"].as_str().unwrap()).unwrap())
                .collect::<Vec<_>>();
            backups.sort();
            assert_eq!(backups, [b"approved A".to_vec(), b"approved B".to_vec()]);
        }
    }
}
#[test]
fn test_unchanged_publication_cleans_only_owned_paths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let entries = plans(&root);
    let foreign = root.join(".revayat-publish-foreign");
    fs::create_dir(&foreign).unwrap();
    fs::write(foreign.join("sentinel"), b"foreign data").unwrap();
    publish_files(&entries, &[], None).unwrap();
    assert_eq!(fs::read(&entries[0].1).unwrap(), b"candidate A");
    assert_eq!(fs::read(foreign.join("sentinel")).unwrap(), b"foreign data");
    assert!(entries.iter().all(|(stage, _)| !stage.exists()));
    assert_eq!(artifacts(&root), vec![foreign.clone()]);
    let entries = plans(&root);
    let displaced = root.join("displaced-recovery");
    let mut changed = None;
    let error = publish_observed(&entries, &[], None, |event, _| {
        if event == Boundary::BeforeCleanup && changed.is_none() {
            let owned = artifacts(&root)
                .into_iter()
                .find(|p| p.is_dir() && p != &foreign)
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
    let root = temp.path().canonicalize().unwrap();
    let entries = plans(&root);
    fs::remove_file(&entries[0].1).unwrap();
    let mut restored = false;
    let error = publish_observed(&entries, &[], None, |event, dest| {
        if event == Boundary::BeforeCommit && dest == entries[1].1 {
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
    assert!(!entries[0].1.exists());
    assert_eq!(fs::read(&entries[1].1).unwrap(), b"approved B");
    assert!(
        error
            .to_string()
            .contains("rollback completed with secondary diagnostics")
    );
    assert!(
        error
            .downcast_ref::<RetainedPrimary>()
            .unwrap()
            .0
            .to_string()
            .contains("controlled publication failure")
    );
    assert_eq!(error.downcast_ref::<RecoveryFailures>().unwrap().0.len(), 1);
    assert!(!format!("{error:#}").contains("controlled publication failure"));
    assert!(!error.to_string().contains("needs recovery"));
    assert!(artifacts(&root).is_empty());
}
#[test]
fn test_publication_cleanup_cancellation_retains_journal_and_owned_lock() {
    for cancellation in [Cancellation::Signal, Cancellation::Requested] {
        for (boundary, skip) in [
            (Boundary::BeforeCleanup, 0),
            (Boundary::BeforeBackupDisposal, 0),
            (Boundary::BeforeBackupDisposal, 1),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let entries = plans(&root);
            let mut cancelled = false;
            let mut visits = 0;
            let error = publish_observed(&entries, &[], None, |event, _| {
                if event == boundary {
                    visits += 1;
                }
                if event == boundary && visits == skip + 1 && !cancelled {
                    cancelled = true;
                    return Err(
                        anyhow::Error::new(cancellation).context("controlled cleanup interruption")
                    );
                }
                Ok(())
            })
            .unwrap_err();
            assert!(cancelled);
            assert_eq!(error.downcast_ref::<Cancellation>(), Some(&cancellation));
            let records = retained(&root, 2);
            for record in &records {
                let label = if record["destination"] == entries[0].1.to_str().unwrap() {
                    "A"
                } else {
                    "B"
                };
                let backup = Path::new(record["backup"].as_str().unwrap());
                if boundary == Boundary::BeforeBackupDisposal && skip == 1 && label == "A" {
                    assert!(!backup.exists(), "earlier disposal already completed");
                } else {
                    assert_eq!(
                        fs::read(backup).unwrap(),
                        format!("approved {label}").as_bytes()
                    );
                }
            }
            assert_eq!(fs::read(&entries[0].1).unwrap(), b"candidate A");
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let entries = plans(&root);
        let mut interrupted = false;
        let mut cleanup_failed = false;
        let error = publish_observed(&entries, &[], None, |event, dest| {
            if event == Boundary::BeforeCommit && dest == entries[1].1 {
                interrupted = true;
                return Err(
                    anyhow::Error::new(cancellation).context("private primary cancellation")
                );
            }
            if event == Boundary::BeforeCleanup {
                cleanup_failed = true;
                bail!("private ordinary cleanup failure");
            }
            Ok(())
        })
        .unwrap_err();
        assert!(interrupted && cleanup_failed);
        assert!(revayat_scientific::publication::cancelled(&error));
        assert_eq!(error.downcast_ref::<Cancellation>(), Some(&cancellation));
        let primary = &error.downcast_ref::<RetainedPrimary>().unwrap().0;
        assert_eq!(primary.downcast_ref::<Cancellation>(), Some(&cancellation));
        assert!(primary.to_string().contains("private primary cancellation"));
        assert_eq!(error.downcast_ref::<RecoveryFailures>().unwrap().0.len(), 1);
        let display = format!("{error:#}");
        assert!(!display.contains("private primary cancellation"));
        assert!(!display.contains("private ordinary cleanup failure"));
        assert!(!display.contains(root.to_str().unwrap()));
        assert_eq!(fs::read(&entries[0].1).unwrap(), b"approved A");
        assert_eq!(fs::read(&entries[1].1).unwrap(), b"approved B");
        retained(&root, 2);
    }
}
