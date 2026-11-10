use anyhow::{Result, bail};
use revayat_scientific::{
    distribution::{self as d, InstallBoundary as B},
    identity::path_object_id,
    publication::{Cancellation, RecoveryFailures, RetainedPrimary},
};
use std::{fs, path::Path};
#[path = "support/distribution_fixture.rs"]
mod support;
use support::*;

fn assert_payload_at(f: &Fixture, path: &Path) {
    for row in f.payload().files {
        assert_eq!(fs::read(path.join(row.relative)).unwrap(), fs::read(row.source).unwrap());
    }
}
fn assert_recovery_ownership(f: &Fixture, journal: &Path, stage_exists: bool) -> std::path::PathBuf {
    let record: serde_json::Value = serde_json::from_slice(&fs::read(journal).unwrap()).unwrap();
    let targets = record["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 1);
    let entry = &targets[0];
    let stage = Path::new(entry["stage"].as_str().unwrap());
    assert_eq!(stage.is_dir(), stage_exists);
    if stage_exists {
        assert_eq!(
            entry["stage_identity"],
            serde_json::to_value(path_object_id(stage).unwrap()).unwrap()
        );
    }
    let lock = Path::new(entry["lock"].as_str().unwrap());
    assert_eq!(lock, f.lock(&f.first));
    assert!(lock.is_file());
    assert_eq!(
        entry["lock_identity"],
        serde_json::to_value(path_object_id(lock).unwrap()).unwrap()
    );
    assert_eq!(
        fs::read_to_string(lock).unwrap().trim(),
        journal.to_str().unwrap()
    );
    assert_eq!(
        fs::read_dir(lock.parent().unwrap())
            .unwrap()
            .filter(|entry| {
                let name = entry.as_ref().unwrap().file_name();
                let name = name.to_string_lossy();
                name.starts_with(".revayat-install-") && name.ends_with(".lock")
            })
            .count(),
        1
    );
    stage.to_owned()
}

#[test]
fn simple_frontmatter_spacing_and_line_endings_preserve_original_bytes() -> Result<()> {
    for declaration in [
        "---\nname \t: revayat-scientific\n---\n",
        "---\rname: 'revayat-scientific'\r---\r",
        "\u{feff}---\r\nname: \"revayat-scientific\"\r\n---\r\n",
    ] {
        let f = Fixture::new();
        fs::write(f.source.join("SKILL.md"), declaration)?;
        f.install(std::slice::from_ref(&f.first), false)?;
        assert_eq!(fs::read(f.first.join("SKILL.md"))?, declaration.as_bytes());
    }
    Ok(())
}
#[test]
fn test_genuine_quoted_and_bom_installation_identity_remains_supported() -> Result<()> {
    for value in [
        "revayat-scientific",
        "'revayat-scientific'",
        "\"revayat-scientific\"",
    ] {
        let f = Fixture::new();
        f.old(&f.first, "owner");
        let old = format!("\u{feff}---\nname: {value}\ndescription: |\n  Fixture\n---\n");
        fs::write(f.first.join("SKILL.md"), &old)?;
        let source = fs::read(f.source.join("SKILL.md"))?;
        let backups = f.install(std::slice::from_ref(&f.first), true)?;
        assert_eq!(backups.len(), 1);
        assert_eq!(fs::read(backups[0].join("retained"))?, b"owner");
        assert_eq!(fs::read(backups[0].join("SKILL.md"))?, old.as_bytes());
        assert_eq!(fs::read(f.first.join("SKILL.md"))?, source);
    }
    Ok(())
}
#[test]
fn test_ambiguous_frontmatter_never_replaces_existing_installation() {
    let f = Fixture::new();
    for value in [
        "name: revayat-scientific\nname: []",
        "name: 'revayat-scientific\"",
        "name: revayat-scientific\nname: |\n  other",
        "name: revayat-scientific\n? name\n: []",
        "name: revayat-scientific\n\"\\u006eame\": []",
        "name: revayat-scientific\n  name: []",
    ] {
        fs::create_dir_all(&f.first).unwrap();
        let data = format!("---\n{value}\n---\n");
        fs::write(f.first.join("SKILL.md"), &data).unwrap();
        fs::write(f.first.join("retained"), b"local owner content").unwrap();
        assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
        assert_eq!(fs::read(f.first.join("SKILL.md")).unwrap(), data.as_bytes());
        assert_eq!(
            fs::read(f.first.join("retained")).unwrap(),
            b"local owner content"
        );
        assert!(
            !f.first
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("skill-backups")
                .exists()
        );
        assert!(f.journals().is_empty());
        assert!(!f.lock(&f.first).exists());
    }
}
#[test]
fn test_partial_copy_cleanup_failure_retains_owned_stage_and_lock_evidence() {
    for cancellation in [None, Some(Cancellation::Signal), Some(Cancellation::Requested)] {
        let f = Fixture::new();
        let mut partial = None;
        let mut cleanup_attempts = 0;
        let error = f
            .observed(std::slice::from_ref(&f.first), false, |at, path| {
                if at == B::AfterCopy(0) {
                    fs::write(path, b"partial candidate")?;
                    partial = Some(path.to_owned());
                    if let Some(reason) = cancellation {
                        return Err(anyhow::Error::new(reason).context("private partial cancellation"));
                    }
                    bail!("partial copy");
                }
                if at == B::BeforeStageCleanup(0) {
                    cleanup_attempts += 1;
                    bail!("stage cleanup failure; recovery required");
                }
                Ok(())
            })
            .unwrap_err();
        assert!(error.to_string().contains("cleanup needs recovery"));
        assert_eq!(error.downcast_ref::<Cancellation>().copied(), cancellation);
        assert_eq!(revayat_scientific::publication::cancelled(&error), cancellation.is_some());
        let primary = &error.downcast_ref::<RetainedPrimary>().unwrap().0;
        assert_eq!(primary.downcast_ref::<Cancellation>().copied(), cancellation);
        if cancellation.is_none() {
            assert!(primary.to_string().contains("partial copy"));
        }
        assert!(error.downcast_ref::<RecoveryFailures>().unwrap().0[0]
            .to_string().contains("stage cleanup failure"));
        assert!(!format!("{error:#}").contains("private partial cancellation"));
        assert!(!format!("{error:#}").contains("stage cleanup failure"));
        assert_eq!(cleanup_attempts, 1);
        assert!(!f.first.exists());
        let journals = f.journals();
        assert_eq!(journals.len(), 1);
        let stage = assert_recovery_ownership(&f, &journals[0], true);
        let partial = partial.expect("partial-copy boundary must execute");
        assert!(partial.starts_with(stage));
        assert_eq!(fs::read(partial).unwrap(), b"partial candidate");
    }
}
#[test]
fn test_failed_journal_refresh_cleanup_keeps_initial_stage_identity() {
    let f = Fixture::new();
    let mut initial = None;
    let mut cleanup_attempts = 0;
    let error = f
        .observed(std::slice::from_ref(&f.first), false, |at, path| {
            if at == B::BeforeJournal {
                let json: serde_json::Value =
                    serde_json::from_slice(&fs::read(path.join("recovery.json"))?)?;
                let stage = Path::new(json["targets"][0]["stage"].as_str().unwrap());
                let identity = serde_json::to_value(path_object_id(stage)?)?;
                assert_eq!(json["targets"][0]["stage_identity"], identity);
                initial = Some(identity);
                fs::create_dir(path.join("prepared.json"))?;
            }
            if at == B::BeforeStageCleanup(0) {
                cleanup_attempts += 1;
                bail!("retain owned evidence");
            }
            Ok(())
        })
        .unwrap_err();
    assert!(error.to_string().contains("cleanup needs recovery"));
    assert!(error.downcast_ref::<RetainedPrimary>().is_some());
    assert!(
        error.downcast_ref::<RecoveryFailures>().unwrap().0[0]
            .to_string().contains("retain owned evidence")
    );
    assert_eq!(cleanup_attempts, 1);
    assert!(initial.is_some(), "initial journal must exist before refresh");
    assert!(!f.first.exists());
    let journals = f.journals();
    assert_eq!(journals.len(), 1);
    let stage = assert_recovery_ownership(&f, &journals[0], true);
    assert_eq!(
        Some(serde_json::to_value(path_object_id(&stage).unwrap()).unwrap()),
        initial
    );
    assert!(journals[0].parent().unwrap().join("prepared.json").is_dir());
}
#[test]
fn test_install_second_cancellation_retains_journal_backups_stages_and_locks() {
    for cancellation in [Cancellation::Signal, Cancellation::Requested] {
        for completed in [false, true] {
            for activation in [B::BeforeStageActivate(0), B::AfterActivate(0)] {
                let f = Fixture::new();
                f.old(&f.first, "owner");
                let old = d::snapshot(&f.first).unwrap();
                let mut interrupted = false;
                let error = f
                    .observed(std::slice::from_ref(&f.first), true, |at, _| {
                        if at == activation {
                            bail!("controlled activation failure");
                        }
                        let restoration = if completed {
                            B::AfterRestore(0)
                        } else {
                            B::BeforeRestore(0)
                        };
                        if at == restoration {
                            interrupted = true;
                            return Err(anyhow::Error::new(cancellation)
                                .context("controlled restoration cancellation"));
                        }
                        Ok(())
                    })
                    .unwrap_err();
                assert!(interrupted);
                assert_eq!(error.downcast_ref::<Cancellation>(), Some(&cancellation));
                let primary = error.downcast_ref::<RetainedPrimary>().unwrap();
                assert!(primary.0.to_string().contains("controlled activation failure"));
                let journals = f.journals();
                assert_eq!(journals.len(), 1);
                let stage = assert_recovery_ownership(
                    &f,
                    &journals[0],
                    activation == B::BeforeStageActivate(0) || completed,
                );
                if activation == B::BeforeStageActivate(0) || completed {
                    for row in f.payload().files {
                        assert_eq!(
                            fs::read(stage.join(row.relative)).unwrap(),
                            fs::read(row.source).unwrap()
                        );
                    }
                } else {
                    assert_payload_at(&f, &f.first);
                }
                let record: serde_json::Value =
                    serde_json::from_slice(&fs::read(&journals[0]).unwrap()).unwrap();
                let previous = if completed {
                    f.first.as_path()
                } else {
                    Path::new(record["targets"][0]["backup"].as_str().unwrap())
                };
                assert_eq!(d::snapshot(previous).unwrap(), old);
            }
        }
    }
}
#[test]
fn test_completed_install_restoration_error_reconciles_the_previous_edition() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    let old = d::snapshot(&f.first).unwrap();
    let mut restored = false;
    let error = f
        .observed(std::slice::from_ref(&f.first), true, |at, _| {
            if at == B::BeforeStageActivate(0) {
                bail!("controlled activation failure");
            }
            if at == B::AfterRestore(0) {
                restored = true;
                bail!("completed rename reports error");
            }
            Ok(())
        })
        .unwrap_err();
    assert!(restored);
    assert!(error.to_string().contains("rollback completed with secondary diagnostics"));
    assert!(error.downcast_ref::<RetainedPrimary>().unwrap().0.to_string()
        .contains("controlled activation failure"));
    let secondary = &error.downcast_ref::<RecoveryFailures>().unwrap().0;
    assert_eq!(secondary.len(), 1);
    assert!(secondary[0].to_string().contains("completed rename reports error"));
    assert!(!format!("{error:#}").contains("controlled activation failure"));
    assert!(!format!("{error:#}").contains("completed rename reports error"));
    assert_eq!(d::snapshot(&f.first).unwrap(), old);
    assert!(f.journals().is_empty());
    assert!(!f.lock(&f.first).exists());
    assert!(!fs::read_dir(f.first.parent().unwrap()).unwrap().any(|e| {
        e.unwrap().file_name().to_string_lossy().starts_with(".revayat-")
    }));
}
#[test]
fn test_second_install_restore_cancellation_retains_the_complete_target_plan() {
    for (interruption, earlier_failure) in [
        (B::BeforeRestore(0), false),
        (B::BeforeBackupRestore(0), false),
        (B::BeforeBackupRestore(0), true),
    ] {
        let f = Fixture::new();
        f.old(&f.first, "first");
        f.old(&f.second, "second");
        let previous = [d::snapshot(&f.first).unwrap(), d::snapshot(&f.second).unwrap()];
        let mut interrupted = false;
        let error = f
            .observed(&[f.first.clone(), f.second.clone()], true, |at, _| {
                if at == B::BeforeStageActivate(1) {
                    bail!("controlled second activation failure");
                }
                if earlier_failure && at == B::AfterRestore(1) {
                    bail!("earlier ordinary restoration diagnostic");
                }
                if at == interruption {
                    interrupted = true;
                    return Err(Cancellation::Requested.into());
                }
                Ok(())
            })
            .unwrap_err();
        assert!(interrupted);
        assert_eq!(error.downcast_ref::<Cancellation>(), Some(&Cancellation::Requested));
        let primary = error.downcast_ref::<RetainedPrimary>().unwrap();
        assert!(primary.0.to_string().contains("controlled second activation failure"));
        let failures = &error.downcast_ref::<RecoveryFailures>().unwrap().0;
        assert_eq!(failures.len(), if earlier_failure { 2 } else { 1 });
        if earlier_failure {
            assert!(failures[0].to_string().contains("earlier ordinary restoration diagnostic"));
            assert!(!format!("{error:#}").contains("earlier ordinary restoration diagnostic"));
        }
        assert_eq!(failures.last().unwrap().downcast_ref::<Cancellation>(), Some(&Cancellation::Requested));
        assert_eq!(d::snapshot(&f.second).unwrap(), previous[1]);
        let journals = f.journals();
        assert_eq!(journals.len(), 1);
        let j: serde_json::Value = serde_json::from_slice(&fs::read(&journals[0]).unwrap()).unwrap();
        let targets = j["targets"].as_array().unwrap();
        assert_eq!(targets.len(), 2);
        for (index, (entry, destination)) in targets.iter().zip([&f.first, &f.second]).enumerate() {
            assert_eq!(entry["destination"], destination.to_str().unwrap());
            let stage = Path::new(entry["stage"].as_str().unwrap());
            let lock = Path::new(entry["lock"].as_str().unwrap());
            let staged = index == 1 || interruption == B::BeforeBackupRestore(0);
            assert_eq!(stage.is_dir(), staged);
            assert!(lock.is_file());
            let candidate = if staged { stage } else { destination.as_path() };
            assert_payload_at(&f, candidate);
            assert_eq!(entry["stage_identity"], serde_json::to_value(path_object_id(candidate).unwrap()).unwrap());
            assert_eq!(entry["lock_identity"], serde_json::to_value(path_object_id(lock).unwrap()).unwrap());
            assert_eq!(fs::read_to_string(lock).unwrap().trim(), journals[0].to_str().unwrap());
        }
        assert_eq!(d::snapshot(Path::new(targets[0]["backup"].as_str().unwrap())).unwrap(), previous[0]);
    }
}
