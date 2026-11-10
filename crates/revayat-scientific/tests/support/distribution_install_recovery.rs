// Included at the integration-suite root to retain the mapped libtest identities.
fn assert_no_install_artifacts(f: &Fixture) {
    assert!(f.journals().is_empty());
    for target in [&f.first, &f.second] {
        if let Ok(entries) = fs::read_dir(target.parent().unwrap()) {
            assert!(!entries.map(|e| e.unwrap().file_name()).any(|name| {
                let name = name.to_string_lossy();
                name.starts_with(".revayat-install-")
                    || name.starts_with(".revayat-scientific-stage-")
            }));
        }
    }
}
#[test]
fn test_second_staging_copy_failure_leaves_both_old_installs() {
    let f = Fixture::new();
    f.old(&f.first, "first");
    f.old(&f.second, "second");
    let a = d::snapshot(&f.first).unwrap();
    let b = d::snapshot(&f.second).unwrap();
    let mut stages = 0;
    let error = f
        .observed(&[f.first.clone(), f.second.clone()], true, |at, _| {
            if at == B::BeforeCopy(0) {
                stages += 1;
                if stages == 2 {
                    bail!("second copy failure");
                }
            }
            Ok(())
        })
        .unwrap_err();
    assert_eq!(stages, 2);
    assert!(error.to_string().contains("second copy failure"));
    assert_eq!(d::snapshot(&f.first).unwrap(), a);
    assert_eq!(d::snapshot(&f.second).unwrap(), b);
    assert_no_install_artifacts(&f);
}
#[test]
fn test_second_activation_failure_restores_both_old_installs() {
    for (failure, native) in [
        (B::BeforeActivate(1), false),
        (B::BeforeStageActivate(1), false),
        (B::BeforeStageActivate(1), true),
    ] {
        let f = Fixture::new();
        f.old(&f.first, "first");
        f.old(&f.second, "second");
        let a = d::snapshot(&f.first).unwrap();
        let b = d::snapshot(&f.second).unwrap();
        let mut reached = false;
        let error = f
            .observed(&[f.first.clone(), f.second.clone()], true, |at, _| {
                if at == failure {
                    reached = true;
                    assert_eq!(f.second.exists(), at == B::BeforeActivate(1));
                    if native {
                        let journal: serde_json::Value = serde_json::from_slice(&fs::read(&f.journals()[0])?)?;
                        fs::remove_dir_all(journal["targets"][1]["stage"].as_str().unwrap())?;
                    } else {
                        bail!("activation failure");
                    }
                }
                Ok(())
            })
            .unwrap_err();
        assert!(reached, "the selected activation boundary must execute");
        if native {
            assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::NotFound);
        } else {
            assert!(error.to_string().contains("activation failure"));
        }
        assert_eq!(d::snapshot(&f.first).unwrap(), a);
        assert_eq!(d::snapshot(&f.second).unwrap(), b);
        assert_no_install_artifacts(&f);
    }
}
#[test]
fn test_failed_batch_removes_a_new_first_install() {
    for (failure, native) in [
        (B::BeforeActivate(1), false),
        (B::BeforeStageActivate(1), false),
        (B::BeforeStageActivate(1), true),
    ] {
        let f = Fixture::new();
        f.old(&f.second, "second");
        let b = d::snapshot(&f.second).unwrap();
        let mut reached = false;
        let error = f
            .observed(&[f.first.clone(), f.second.clone()], true, |at, _| {
                if at == failure {
                    reached = true;
                    assert_eq!(f.second.exists(), at == B::BeforeActivate(1));
                    if native {
                        let journal: serde_json::Value = serde_json::from_slice(&fs::read(&f.journals()[0])?)?;
                        fs::remove_dir_all(journal["targets"][1]["stage"].as_str().unwrap())?;
                    } else {
                        bail!("activation failure");
                    }
                }
                Ok(())
            })
            .unwrap_err();
        assert!(reached, "the selected activation boundary must execute");
        if native {
            assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::NotFound);
        } else {
            assert!(error.to_string().contains("activation failure"));
        }
        assert!(!f.first.exists());
        assert_eq!(d::snapshot(&f.second).unwrap(), b);
        assert_no_install_artifacts(&f);
    }
}
#[test]
fn test_copy_corruption_is_detected_before_publishing() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    let old = d::snapshot(&f.first).unwrap();
    let mut corrupted = false;
    let error = f
        .observed(std::slice::from_ref(&f.first), true, |at, path| {
            if at == B::AfterCopy(0) {
                fs::write(path, "corrupt candidate")?;
                corrupted = true;
            }
            Ok(())
        })
        .unwrap_err();
    assert!(corrupted);
    assert!(error.to_string().contains("staged payload differs"));
    assert_eq!(d::snapshot(&f.first).unwrap(), old);
    assert_no_install_artifacts(&f);
}
#[test]
fn test_changed_source_is_not_mixed_into_an_installation() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    let old = d::snapshot(&f.first).unwrap();
    let changed = b"changed during stage";
    let mut injected = false;
    let error = f
        .observed(std::slice::from_ref(&f.first), true, |at, _| {
            if at == B::AfterCopy(0) {
                fs::write(f.source.join("references/helper.md"), changed)?;
                injected = true;
            }
            Ok(())
        })
        .unwrap_err();
    assert!(injected);
    assert!(error.to_string().contains("source") || error.to_string().contains("staged payload"));
    assert_eq!(fs::read(f.source.join("references/helper.md")).unwrap(), changed);
    assert_eq!(d::snapshot(&f.first).unwrap(), old);
    assert_no_install_artifacts(&f);
}
#[test]
fn test_concurrent_old_install_change_is_not_overwritten() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    assert!(
        f.observed(std::slice::from_ref(&f.first), true, |at, _| {
            if at == B::AfterCopy(0) {
                fs::write(f.first.join("retained"), "concurrent owner")?;
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fs::read(f.first.join("retained")).unwrap(), b"concurrent owner");
}
#[test]
fn test_failed_rollback_retains_a_located_recovery_record_and_original() {
    for failure in [B::BeforeStageActivate(0), B::AfterActivate(0)] {
        let f = Fixture::new();
        f.old(&f.first, "owner");
        let old = d::snapshot(&f.first).unwrap();
        let mut reached = false;
        let error = f
            .observed(std::slice::from_ref(&f.first), true, |at, _| {
                if at == failure {
                    reached = true;
                    bail!("controlled activation interruption");
                }
                if at == B::BeforeRestore(0) {
                    bail!("controlled restoration interruption");
                }
                Ok(())
            })
            .unwrap_err();
        assert!(reached);
        assert!(error.to_string().contains("recovery"));
        let journals = f.journals();
        assert_eq!(journals.len(), 1);
        let j: serde_json::Value = serde_json::from_slice(&fs::read(&journals[0]).unwrap()).unwrap();
        assert_eq!(j["targets"].as_array().unwrap().len(), 1);
        let target = &j["targets"][0];
        assert_eq!(target["destination"], f.first.to_str().unwrap());
        let backup = Path::new(target["backup"].as_str().unwrap());
        assert_eq!(d::snapshot(backup).unwrap(), old);
        assert_eq!(fs::read_dir(backup.parent().unwrap()).unwrap().count(), 1);
        assert!(Path::new(target["lock"].as_str().unwrap()).is_file());
    }
}
#[test]
fn test_successful_batch_keeps_backups_outside_discovery() -> Result<()> {
    let f = Fixture::new();
    f.old(&f.first, "a");
    f.old(&f.second, "b");
    let old = [d::snapshot(&f.first)?, d::snapshot(&f.second)?];
    let payload = f.payload();
    let backups = f.install(&[f.first.clone(), f.second.clone()], true)?;
    assert_eq!(backups.len(), 2);
    for ((target, backup), previous) in [&f.first, &f.second].into_iter().zip(backups).zip(old) {
        assert_collected_payload(&payload, target);
        assert_eq!(d::snapshot(&backup)?, previous);
        assert_eq!(fs::read_dir(backup.parent().unwrap())?.count(), 1);
        assert_eq!(backup.parent().unwrap().file_name().unwrap(), "skill-backups");
        assert!(!backup.starts_with(target.parent().unwrap()));
    }
    assert_no_install_artifacts(&f);
    Ok(())
}
#[test]
fn test_existing_lock_is_not_removed_or_ignored() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    let old = d::snapshot(&f.first).unwrap();
    let lock = f.lock(&f.first);
    fs::write(&lock, "another operation").unwrap();
    assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
    assert_eq!(fs::read(lock).unwrap(), b"another operation");
    assert_eq!(d::snapshot(&f.first).unwrap(), old);
}
#[test]
fn test_busy_second_lock_releases_only_owned_first_lock() {
    let f = Fixture::new();
    f.old(&f.second, "owner");
    let old = d::snapshot(&f.second).unwrap();
    let lock = f.lock(&f.second);
    fs::write(&lock, "other").unwrap();
    assert!(f.install(&[f.first.clone(), f.second.clone()], true).is_err());
    assert_eq!(fs::read(lock).unwrap(), b"other");
    assert_eq!(d::snapshot(&f.second).unwrap(), old);
    assert!(!f.lock(&f.first).exists());
    assert!(!f.first.exists());
}
#[test]
fn test_replaced_lock_is_preserved_and_cleanup_is_not_success() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    let lock = f.lock(&f.first);
    let mut swapped = false;
    let mut prevented = false;
    let result = f.observed(std::slice::from_ref(&f.first), true, |at, _| {
        if at == B::AfterCopy(0) && !swapped && !prevented {
            match fs::rename(&lock, lock.with_extension("retained")) {
                Ok(()) => {
                    fs::write(&lock, "new owner lock")?;
                    swapped = true;
                }
                Err(error)
                    if cfg!(windows) && error.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    prevented = true;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    });
    if prevented {
        assert!(!swapped);
        assert!(result.is_ok());
        for row in f.payload().files {
            assert_eq!(
                fs::read(f.first.join(row.relative)).unwrap(),
                fs::read(row.source).unwrap()
            );
        }
        assert_no_install_artifacts(&f);
    } else {
        assert!(swapped);
        assert!(result.unwrap_err().to_string().contains("recovery"));
        assert_eq!(fs::read(lock).unwrap(), b"new owner lock");
        assert_eq!(f.journals().len(), 1);
    }
}
#[test]
fn test_late_backup_root_swap_is_refused_without_writing_through_link() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    let old = d::snapshot(&f.first).unwrap();
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    let backup = f.first.parent().unwrap().parent().unwrap().join("skill-backups");
    assert!(
        f.observed(std::slice::from_ref(&f.first), true, |at, _| {
            if at == B::Staged(0) {
                fs::remove_dir(&backup)?;
                link(&outside, &backup);
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(d::snapshot(&f.first).unwrap(), old);
    assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
}
#[test]
fn test_target_created_during_staging_is_not_overwritten() {
    let f = Fixture::new();
    assert!(
        f.observed(std::slice::from_ref(&f.first), false, |at, _| {
            if at == B::Staged(0) {
                fs::create_dir(&f.first)?;
                fs::write(f.first.join("other-data"), "new concurrent owner")?;
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fs::read(f.first.join("other-data")).unwrap(), b"new concurrent owner");
}
#[test]
fn test_actual_rename_then_exception_is_reconciled_by_directory_identity() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    let old = d::snapshot(&f.first).unwrap();
    let error = f
        .observed(std::slice::from_ref(&f.first), true, |at, _| {
            if at == B::AfterActivate(0) {
                bail!("interruption after completed rename");
            }
            Ok(())
        })
        .unwrap_err();
    assert!(error.to_string().contains("interruption after completed rename"));
    assert_eq!(d::snapshot(&f.first).unwrap(), old);
    assert_no_install_artifacts(&f);
}
#[test]
fn test_new_destination_after_failure_is_not_deleted_to_force_rollback() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    let old = d::snapshot(&f.first).unwrap();
    assert!(
        f.observed(std::slice::from_ref(&f.first), true, |at, _| {
            if at == B::AfterActivate(0) {
                fs::rename(&f.first, f.root.join("candidate-held"))?;
                fs::create_dir(&f.first)?;
                fs::write(f.first.join("outside-writer"), "concurrent content")?;
                bail!("activation blocked");
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fs::read(f.first.join("outside-writer")).unwrap(), b"concurrent content");
    let journals = f.journals();
    assert_eq!(journals.len(), 1);
    let j: serde_json::Value = serde_json::from_slice(&fs::read(&journals[0]).unwrap()).unwrap();
    let backup = Path::new(j["targets"][0]["backup"].as_str().unwrap());
    assert_eq!(d::snapshot(backup).unwrap(), old);
}
#[test]
fn test_journal_write_failure_preserves_old_installation() {
    for failure in [B::BeforeInitialJournal, B::BeforeJournal] {
        let f = Fixture::new();
        f.old(&f.first, "owner");
        let old = d::snapshot(&f.first).unwrap();
        let mut reached = false;
        let result = f.observed(std::slice::from_ref(&f.first), true, |at, path| {
            if at == failure {
                reached = true;
                fs::create_dir(path.join(if at == B::BeforeInitialJournal {
                    "recovery.json"
                } else {
                    "prepared.json"
                }))?;
            }
            Ok(())
        });
        assert!(reached);
        assert!(result.is_err());
        assert_eq!(d::snapshot(&f.first).unwrap(), old);
        assert_no_install_artifacts(&f);
    }
    for boundary in [B::BeforeInitialJournal, B::BeforeJournal, B::BeforeCleanup] {
        let f = Fixture::new();
        f.old(&f.first, "owner");
        let old = d::snapshot(&f.first).unwrap();
        let displaced = f.root.join("owned recovery retained");
        let mut foreign = None;
        let error = f.observed(std::slice::from_ref(&f.first), true, |at, observed| {
            if at == boundary && foreign.is_none() {
                let root = if at == B::BeforeCleanup {
                    f.journals()[0].parent().unwrap().to_owned()
                } else {
                    observed.to_owned()
                };
                let id = revayat_scientific::identity::path_object_id(&root)?;
                fs::rename(&root, &displaced)?;
                fs::create_dir(&root)?;
                fs::write(root.join("foreign sentinel"), b"retain unrelated recovery data")?;
                foreign = Some((root, id));
            }
            Ok(())
        }).unwrap_err();
        assert!(error.to_string().contains("recovery"));
        let (root, id) = foreign.expect("real recovery directory boundary must execute");
        assert_ne!(revayat_scientific::identity::path_object_id(&root).unwrap(), id);
        assert_eq!(revayat_scientific::identity::path_object_id(&displaced).unwrap(), id);
        assert_eq!(fs::read(root.join("foreign sentinel")).unwrap(), b"retain unrelated recovery data");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        assert_eq!(displaced.join("recovery.json").is_file(), boundary != B::BeforeInitialJournal);
        assert_eq!(d::snapshot(&f.first).unwrap(), old);
        assert!(f.lock(&f.first).is_file());
    }
}
#[test]
fn test_keyboard_interrupt_during_second_activation_restores_batch() {
    use revayat_scientific::publication::Cancellation;
    for failure in [B::BeforeStageActivate(1), B::AfterActivate(1)] {
        for cancellation in [None, Some(Cancellation::Signal), Some(Cancellation::Requested)] {
            let f = Fixture::new();
            f.old(&f.first, "a");
            f.old(&f.second, "b");
            let a = d::snapshot(&f.first).unwrap();
            let b = d::snapshot(&f.second).unwrap();
            let mut reached = false;
            let error = f
                .observed(&[f.first.clone(), f.second.clone()], true, |at, _| {
                    if at == failure {
                        reached = true;
                        assert_eq!(f.second.exists(), at == B::AfterActivate(1));
                        if let Some(cancellation) = cancellation {
                            return Err(cancellation.into());
                        }
                        bail!("cancelled owned activation");
                    }
                    Ok(())
                })
                .unwrap_err();
            assert!(reached, "the selected cancellation boundary must execute");
            assert_eq!(error.downcast_ref::<Cancellation>().copied(), cancellation);
            if cancellation.is_none() {
                assert!(error.to_string().contains("cancelled owned activation"));
            }
            assert_eq!(d::snapshot(&f.first).unwrap(), a);
            assert_eq!(d::snapshot(&f.second).unwrap(), b);
            assert_no_install_artifacts(&f);
        }
    }
}
