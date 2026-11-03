use anyhow::{Result, bail};
use revayat_scientific::distribution::{self as d, InstallBoundary as B, NAME, Payload};
use std::{fs, path::Path, process::Command};
#[path = "support/distribution_fixture.rs"]
mod support;
use support::*;
#[test]
fn test_new_install_and_force_replacement_preserve_exact_backup() -> Result<()> {
    let f = Fixture::new();
    f.install(std::slice::from_ref(&f.first), false)?;
    assert_eq!(
        fs::read(f.first.join("SKILL.md"))?,
        fs::read(f.source.join("SKILL.md"))?
    );
    fs::write(f.first.join("retained"), "owner edition")?;
    let previous = fs::read(f.first.join("SKILL.md"))?;
    let backups = f.install(std::slice::from_ref(&f.first), true)?;
    assert_eq!(backups.len(), 1);
    f.assert_old(&backups[0], &previous);
    assert_eq!(fs::read(backups[0].join("retained"))?, b"owner edition");
    Ok(())
}
#[test]
fn test_foreign_nonempty_directory_is_not_a_force_installation() {
    let f = Fixture::new();
    fs::create_dir_all(&f.first).unwrap();
    fs::write(f.first.join("private"), "owner content").unwrap();
    assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
    assert_eq!(fs::read(f.first.join("private")).unwrap(), b"owner content");
}
#[test]
fn test_wrong_skill_name_does_not_authorize_replacement() {
    let f = Fixture::new();
    fs::create_dir_all(&f.first).unwrap();
    fs::write(f.first.join("SKILL.md"), "---\nname: another\n---\n").unwrap();
    assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
    assert!(
        fs::read_to_string(f.first.join("SKILL.md"))
            .unwrap()
            .contains("another")
    );
}
#[test]
fn test_git_metadata_and_case_variant_are_never_install_targets() {
    let f = Fixture::new();
    for path in [f.root.join(".git/new"), f.root.join(".GIT/new")] {
        assert!(f.install(std::slice::from_ref(&path), true).is_err());
        assert!(!path.exists());
    }
}
#[test]
fn test_separate_git_administration_directory_remains_intact() {
    let f = Fixture::new();
    let admin = f.root.join("admin");
    assert!(
        Command::new("git")
            .args(["init", "--quiet", "--separate-git-dir"])
            .arg(&admin)
            .arg(&f.repo)
            .status()
            .unwrap()
            .success()
    );
    let before = fs::read(admin.join("config")).unwrap();
    assert!(f.install(&[admin.join("installed")], true).is_err());
    assert_eq!(fs::read(admin.join("config")).unwrap(), before);
}
#[test]
fn test_parent_symlink_never_redirects_installation() {
    let f = Fixture::new();
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    let alias = f.root.join("alias");
    link(&outside, &alias);
    assert!(f.install(&[alias.join(NAME)], false).is_err());
    assert!(!outside.join(NAME).exists());
}
#[test]
fn test_destination_symlink_is_preserved() {
    let f = Fixture::new();
    let actual = f.root.join("actual");
    let old = f.old(&actual, "owner");
    fs::create_dir_all(f.first.parent().unwrap()).unwrap();
    link(&actual, &f.first);
    assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
    assert!(revayat_scientific::identity::is_link(&f.first).unwrap());
    f.assert_old(&actual, &old);
}
#[test]
fn test_source_root_link_is_not_dereferenced() {
    let f = Fixture::new();
    let alias = f.root.join("alias");
    link(&f.source, &alias);
    assert!(Payload::collect(&alias, None).is_err());
    assert!(!f.first.exists());
}
#[test]
fn test_backup_directory_link_does_not_move_the_old_install_outside() {
    let f = Fixture::new();
    let old = f.old(&f.first, "owner");
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    link(
        &outside,
        &f.first
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("skill-backups"),
    );
    assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
    f.assert_old(&f.first, &old);
    assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
}
#[test]
fn test_case_colliding_destination_is_refused() {
    let f = Fixture::new();
    let other = f.first.with_file_name("Revayat-Scientific");
    let old = f.old(&other, "owner");
    assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
    f.assert_old(&other, &old);
}
#[test]
fn test_source_overlap_is_refused_without_changes() {
    let f = Fixture::new();
    let old = d::snapshot(&f.source).unwrap();
    for path in [
        f.source.clone(),
        f.source.join("child"),
        f.source.parent().unwrap().to_owned(),
    ] {
        assert!(f.install(&[path], true).is_err());
    }
    assert_eq!(d::snapshot(&f.source).unwrap(), old);
}
#[test]
fn test_late_existing_target_preflight_does_not_install_first() {
    let f = Fixture::new();
    let old = f.old(&f.second, "owner");
    assert!(
        f.install(&[f.first.clone(), f.second.clone()], false)
            .is_err()
    );
    assert!(!f.first.exists());
    f.assert_old(&f.second, &old);
}
#[test]
fn test_late_invalid_target_preflight_does_not_install_first() {
    let f = Fixture::new();
    fs::create_dir_all(f.second.parent().unwrap()).unwrap();
    fs::write(&f.second, "ordinary file").unwrap();
    assert!(
        f.install(&[f.first.clone(), f.second.clone()], true)
            .is_err()
    );
    assert!(!f.first.exists());
    assert_eq!(fs::read(&f.second).unwrap(), b"ordinary file");
}
#[test]
fn test_payload_enumerated_once_for_the_entire_batch() -> Result<()> {
    let f = Fixture::new();
    let payload = f.payload();
    let names: Vec<_> = payload.files.iter().map(|p| p.relative.clone()).collect();
    d::install_targets(
        &[f.first.clone(), f.second.clone()],
        false,
        &f.source,
        &f.repo,
        &payload,
    )?;
    for name in names {
        assert_eq!(
            fs::read(f.first.join(&name))?,
            fs::read(f.second.join(name))?
        );
    }
    Ok(())
}
#[test]
fn test_second_staging_copy_failure_leaves_both_old_installs() {
    let f = Fixture::new();
    let a = f.old(&f.first, "first");
    let b = f.old(&f.second, "second");
    let mut stages = 0;
    assert!(
        f.observed(&[f.first.clone(), f.second.clone()], true, |at, _| {
            if at == B::BeforeCopy(0) {
                stages += 1;
                if stages == 2 {
                    bail!("second copy failure");
                }
            }
            Ok(())
        })
        .is_err()
    );
    f.assert_old(&f.first, &a);
    f.assert_old(&f.second, &b);
    assert!(f.journals().is_empty());
}
#[test]
fn test_second_activation_failure_restores_both_old_installs() {
    let f = Fixture::new();
    let a = f.old(&f.first, "first");
    let b = f.old(&f.second, "second");
    assert!(
        f.observed(&[f.first.clone(), f.second.clone()], true, |at, _| {
            if at == B::BeforeActivate(1) {
                bail!("activation failure");
            }
            Ok(())
        })
        .is_err()
    );
    f.assert_old(&f.first, &a);
    f.assert_old(&f.second, &b);
    assert!(f.journals().is_empty());
}
#[test]
fn test_failed_batch_removes_a_new_first_install() {
    let f = Fixture::new();
    let b = f.old(&f.second, "second");
    assert!(
        f.observed(&[f.first.clone(), f.second.clone()], true, |at, _| {
            if at == B::BeforeActivate(1) {
                bail!("activation failure");
            }
            Ok(())
        })
        .is_err()
    );
    assert!(!f.first.exists());
    f.assert_old(&f.second, &b);
}
#[test]
fn test_copy_corruption_is_detected_before_publishing() {
    let f = Fixture::new();
    let old = f.old(&f.first, "owner");
    assert!(
        f.observed(std::slice::from_ref(&f.first), true, |at, path| {
            if at == B::AfterCopy(0) {
                fs::write(path, "corrupt candidate")?;
            }
            Ok(())
        })
        .is_err()
    );
    f.assert_old(&f.first, &old);
}
#[test]
fn test_changed_source_is_not_mixed_into_an_installation() {
    let f = Fixture::new();
    let old = f.old(&f.first, "owner");
    assert!(
        f.observed(std::slice::from_ref(&f.first), true, |at, _| {
            if at == B::AfterCopy(0) {
                fs::write(f.source.join("SKILL.md"), format!("{HEADER}changed source"))?;
            }
            Ok(())
        })
        .is_err()
    );
    f.assert_old(&f.first, &old);
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
    assert_eq!(
        fs::read(f.first.join("retained")).unwrap(),
        b"concurrent owner"
    );
}
#[test]
fn test_failed_rollback_retains_a_located_recovery_record_and_original() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    assert!(
        f.observed(std::slice::from_ref(&f.first), true, |at, _| {
            if at == B::AfterActivate(0) || at == B::BeforeRestore(0) {
                bail!("controlled interruption");
            }
            Ok(())
        })
        .is_err()
    );
    let journals = f.journals();
    assert_eq!(journals.len(), 1);
    let j: serde_json::Value = serde_json::from_slice(&fs::read(&journals[0]).unwrap()).unwrap();
    let target = &j["targets"][0];
    assert_eq!(
        fs::read(Path::new(target["backup"].as_str().unwrap()).join("retained")).unwrap(),
        b"owner"
    );
    assert!(Path::new(target["lock"].as_str().unwrap()).exists());
}
#[test]
fn test_successful_batch_keeps_backups_outside_discovery() -> Result<()> {
    let f = Fixture::new();
    f.old(&f.first, "a");
    f.old(&f.second, "b");
    let backups = f.install(&[f.first.clone(), f.second.clone()], true)?;
    assert_eq!(backups.len(), 2);
    for path in backups {
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "skill-backups");
        assert!(!path.starts_with(f.first.parent().unwrap()));
    }
    assert!(f.journals().is_empty());
    Ok(())
}
#[test]
fn test_empty_directory_requires_force_and_is_preserved_as_a_backup() -> Result<()> {
    let f = Fixture::new();
    fs::create_dir_all(&f.first)?;
    assert!(f.install(std::slice::from_ref(&f.first), false).is_err());
    let backups = f.install(std::slice::from_ref(&f.first), true)?;
    assert_eq!(fs::read_dir(&backups[0])?.count(), 0);
    Ok(())
}
#[test]
fn test_existing_install_with_nested_link_is_not_followed() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    link(&outside, &f.first.join("linked"));
    assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
    assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
}
#[test]
fn test_existing_lock_is_not_removed_or_ignored() {
    let f = Fixture::new();
    let old = f.old(&f.first, "owner");
    let lock = f.lock(&f.first);
    fs::write(&lock, "another operation").unwrap();
    assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
    assert_eq!(fs::read(lock).unwrap(), b"another operation");
    f.assert_old(&f.first, &old);
}
#[test]
fn test_busy_second_lock_releases_only_owned_first_lock() {
    let f = Fixture::new();
    f.old(&f.second, "owner");
    let lock = f.lock(&f.second);
    fs::write(&lock, "other").unwrap();
    assert!(
        f.install(&[f.first.clone(), f.second.clone()], true)
            .is_err()
    );
    assert_eq!(fs::read(lock).unwrap(), b"other");
    assert!(!f.lock(&f.first).exists());
    assert!(!f.first.exists());
}
#[test]
fn test_replaced_lock_is_preserved_and_cleanup_is_not_success() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    let lock = f.lock(&f.first);
    let mut swapped = false;
    assert!(
        f.observed(std::slice::from_ref(&f.first), true, |at, _| {
            if at == B::AfterCopy(0) && !swapped {
                fs::rename(&lock, lock.with_extension("retained"))?;
                fs::write(&lock, "new owner lock")?;
                swapped = true;
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fs::read(lock).unwrap(), b"new owner lock");
    assert_eq!(f.journals().len(), 1);
}
#[test]
fn test_late_backup_root_swap_is_refused_without_writing_through_link() {
    let f = Fixture::new();
    let old = f.old(&f.first, "owner");
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    let backup = f
        .first
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("skill-backups");
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
    f.assert_old(&f.first, &old);
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
    assert_eq!(
        fs::read(f.first.join("other-data")).unwrap(),
        b"new concurrent owner"
    );
}
#[test]
fn test_actual_rename_then_exception_is_reconciled_by_directory_identity() {
    let f = Fixture::new();
    let old = f.old(&f.first, "owner");
    assert!(
        f.observed(std::slice::from_ref(&f.first), true, |at, _| {
            if at == B::AfterActivate(0) {
                bail!("interruption after completed rename");
            }
            Ok(())
        })
        .is_err()
    );
    f.assert_old(&f.first, &old);
    assert!(f.journals().is_empty());
}
#[test]
fn test_new_destination_after_failure_is_not_deleted_to_force_rollback() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
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
    assert_eq!(
        fs::read(f.first.join("outside-writer")).unwrap(),
        b"concurrent content"
    );
    assert_eq!(f.journals().len(), 1);
}
#[test]
fn test_journal_write_failure_preserves_old_installation() {
    let f = Fixture::new();
    let old = f.old(&f.first, "owner");
    assert!(
        f.observed(std::slice::from_ref(&f.first), true, |at, path| {
            if at == B::BeforeJournal {
                fs::create_dir(path.join("prepared.json"))?;
            }
            Ok(())
        })
        .is_err()
    );
    f.assert_old(&f.first, &old);
    assert!(f.journals().is_empty());
}
#[test]
fn test_missing_or_misidentified_source_never_creates_target() {
    let f = Fixture::new();
    for source in [
        "",
        "not a skill",
        "---\nname: other\n---\n",
        "---\nname: revayat-scientific\nname: other\n---\n",
    ] {
        fs::write(f.source.join("SKILL.md"), source).unwrap();
        assert!(Payload::collect(&f.source, None).is_err());
        assert!(!f.first.exists());
    }
}
#[test]
fn test_payload_limit_refuses_before_any_target_mutation() {
    let f = Fixture::new();
    let old = f.old(&f.first, "owner");
    let file = fs::File::create(f.source.join("assets.bin")).unwrap();
    file.set_len(d::MAX_PAYLOAD_BYTES + 1).unwrap();
    fs::create_dir(f.source.join("assets")).unwrap();
    fs::rename(
        f.source.join("assets.bin"),
        f.source.join("assets/large.bin"),
    )
    .unwrap();
    assert!(Payload::collect(&f.source, None).is_err());
    f.assert_old(&f.first, &old);
}
#[test]
fn test_nested_target_plan_is_rejected_without_changes() {
    let f = Fixture::new();
    assert!(
        f.install(&[f.first.clone(), f.first.join("nested")], true)
            .is_err()
    );
    assert!(!f.first.exists());
}
#[test]
fn test_duplicate_case_target_plan_is_rejected_without_changes() {
    let f = Fixture::new();
    assert!(
        f.install(
            &[
                f.first.clone(),
                f.first.with_file_name("Revayat-Scientific")
            ],
            true
        )
        .is_err()
    );
    assert!(!f.first.exists());
}
#[test]
fn test_shared_agent_path_is_deduplicated_before_publication() {
    let paths: std::collections::HashSet<_> = d::AGENTS.iter().map(|a| a.2).collect();
    assert_eq!(
        d::AGENTS.iter().filter(|a| a.2 == ".agents/skills").count(),
        2
    );
    assert_eq!(paths.len(), 7);
    let f = Fixture::new();
    fs::create_dir(f.root.join(".agents")).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .current_dir(&f.repo)
        .env("REVAYAT_REPOSITORY", &f.repo)
        .args(["install", "--scope", "project", "--path"])
        .arg(&f.root)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        f.root
            .join(".agents/skills/revayat-scientific/SKILL.md")
            .exists()
    );
    assert_eq!(
        String::from_utf8_lossy(&result.stdout)
            .matches("Installed revayat-scientific:")
            .count(),
        1
    );
}
#[test]
fn test_success_messages_are_not_printed_for_a_failed_batch() {
    let f = Fixture::new();
    let late = f.root.join(".agents/skills/revayat-scientific");
    fs::create_dir_all(&late).unwrap();
    fs::create_dir(f.root.join(".claude")).unwrap();
    fs::write(late.join("private"), "owner data").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .env("REVAYAT_REPOSITORY", &f.repo)
        .args(["install", "--scope", "project", "--path"])
        .arg(&f.root)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Installed revayat-scientific:"));
    assert_eq!(fs::read(late.join("private")).unwrap(), b"owner data");
    assert!(!f.root.join(".claude/skills/revayat-scientific").exists());
}
#[test]
fn test_valid_bom_source_identity_is_supported() -> Result<()> {
    let f = Fixture::new();
    fs::write(
        f.source.join("SKILL.md"),
        format!("\u{feff}{HEADER}candidate"),
    )?;
    f.install(std::slice::from_ref(&f.first), false)?;
    assert_eq!(
        fs::read(f.source.join("SKILL.md"))?,
        fs::read(f.first.join("SKILL.md"))?
    );
    Ok(())
}
#[test]
fn test_public_cli_refuses_a_foreign_target_without_mutation() {
    let f = Fixture::new();
    fs::create_dir_all(&f.first).unwrap();
    fs::write(f.first.join("note"), "private user data").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .env("REVAYAT_REPOSITORY", &f.repo)
        .args(["install", "--dest"])
        .arg(&f.first)
        .arg("--force")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private user data"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private user data"));
    assert_eq!(
        fs::read(f.first.join("note")).unwrap(),
        b"private user data"
    );
}
#[test]
fn test_retained_backup_is_not_reinterpreted_as_an_install_target() -> Result<()> {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    let backups = f.install(std::slice::from_ref(&f.first), true)?;
    let old = d::snapshot(&backups[0])?;
    assert!(f.install(&[backups[0].clone()], true).is_err());
    assert_eq!(d::snapshot(&backups[0])?, old);
    Ok(())
}
#[test]
fn test_keyboard_interrupt_during_second_activation_restores_batch() {
    let f = Fixture::new();
    let a = f.old(&f.first, "a");
    let b = f.old(&f.second, "b");
    assert!(
        f.observed(&[f.first.clone(), f.second.clone()], true, |at, _| {
            if at == B::AfterActivate(1) {
                bail!("cancelled owned activation");
            }
            Ok(())
        })
        .is_err()
    );
    f.assert_old(&f.first, &a);
    f.assert_old(&f.second, &b);
    assert!(f.journals().is_empty());
}
#[test]
fn test_source_file_link_and_nonregular_old_entry_are_rejected() {
    let f = Fixture::new();
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    link(&outside, &f.source.join("references/linked"));
    assert!(Payload::collect(&f.source, None).is_err());
    assert!(!f.first.exists());
}
#[cfg(windows)]
#[test]
fn test_windows_junction_in_destination_parent_is_rejected() {
    let f = Fixture::new();
    let outside = f.root.join("junction-target");
    fs::create_dir(&outside).unwrap();
    let junction = f.root.join("junction");
    link(&outside, &junction);
    assert!(f.install(&[junction.join(NAME)], false).is_err());
    assert!(!outside.join(NAME).exists());
}
