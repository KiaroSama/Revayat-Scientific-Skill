use anyhow::{Result, bail};
use revayat_scientific::distribution::{self as d, InstallBoundary as B, NAME, Payload};
use std::{fs, path::Path, process::Command};
#[path = "support/distribution_fixture.rs"]
mod support;
use support::*;

fn assert_payload(f: &Fixture, target: &Path) {
    assert_collected_payload(&f.payload(), target);
}
fn assert_collected_payload(payload: &Payload, target: &Path) {
    for row in &payload.files {
        assert_eq!(
            fs::read(target.join(&row.relative)).unwrap(),
            fs::read(&row.source).unwrap()
        );
    }
    assert_eq!(
        d::snapshot(target)
            .unwrap()
            .unwrap()
            .files
            .values()
            .filter(|v| v.is_some())
            .count(),
        payload.files.len()
    );
}
fn file_link(source: &Path, destination: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(source, destination).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(source, destination)
        .expect("native file-link parity requires symlink creation on the hosted runner");
}
include!("support/distribution_install_recovery.rs");

#[test]
fn test_new_install_and_force_replacement_preserve_exact_backup() -> Result<()> {
    let f = Fixture::new();
    let source = d::snapshot(&f.source)?;
    f.install(std::slice::from_ref(&f.first), false)?;
    assert_payload(&f, &f.first);
    fs::write(f.first.join("retained"), "owner edition")?;
    let previous = d::snapshot(&f.first)?;
    assert!(f.install(std::slice::from_ref(&f.first), false).is_err());
    let backups = f.install(std::slice::from_ref(&f.first), true)?;
    assert_eq!(backups.len(), 1);
    assert_eq!(d::snapshot(&backups[0])?, previous);
    assert_payload(&f, &f.first);
    assert_eq!(d::snapshot(&f.source)?, source);
    Ok(())
}
#[test]
fn test_foreign_nonempty_directory_is_not_a_force_installation() {
    let f = Fixture::new();
    fs::create_dir_all(&f.first).unwrap();
    fs::write(f.first.join("private"), "owner content").unwrap();
    let old = d::snapshot(&f.first).unwrap();
    assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
    assert_eq!(d::snapshot(&f.first).unwrap(), old);
}
#[test]
fn test_wrong_skill_name_does_not_authorize_replacement() {
    let f = Fixture::new();
    fs::create_dir_all(&f.first).unwrap();
    fs::write(f.first.join("SKILL.md"), "---\nname: another\n---\n").unwrap();
    let old = d::snapshot(&f.first).unwrap();
    assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
    assert_eq!(d::snapshot(&f.first).unwrap(), old);
}
#[test]
fn test_git_metadata_and_case_variant_are_never_install_targets() {
    let f = Fixture::new();
    for (index, name) in [".git", ".GIT"].into_iter().enumerate() {
        let target = f.root.join(format!("case-{index}")).join(name);
        f.old(&target, "owner");
        let old = d::snapshot(&target).unwrap();
        assert!(f.install(std::slice::from_ref(&target), true).is_err());
        assert_eq!(d::snapshot(&target).unwrap(), old);
        let new = f.root.join(format!("new-{index}")).join(name).join("new");
        assert!(f.install(std::slice::from_ref(&new), true).is_err());
        assert!(!new.exists());
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
            .output()
            .unwrap()
            .status
            .success()
    );
    let before = d::snapshot(&admin).unwrap();
    for target in [admin.clone(), admin.join("installed")] {
        assert!(f.install(std::slice::from_ref(&target), true).is_err());
        assert_eq!(d::snapshot(&admin).unwrap(), before);
    }
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&f.repo)
            .args(["status", "--porcelain"])
            .output()
            .unwrap()
            .status
            .success()
    );
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
    f.old(&actual, "owner");
    let old = d::snapshot(&actual).unwrap();
    fs::create_dir_all(f.first.parent().unwrap()).unwrap();
    link(&actual, &f.first);
    assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
    assert!(revayat_scientific::identity::is_link(&f.first).unwrap());
    assert_eq!(d::snapshot(&actual).unwrap(), old);
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
    f.old(&f.first, "owner");
    let old = d::snapshot(&f.first).unwrap();
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
    assert_eq!(d::snapshot(&f.first).unwrap(), old);
    assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
}
#[test]
fn test_case_colliding_destination_is_refused() {
    let f = Fixture::new();
    let other = f.first.with_file_name("Revayat-Scientific");
    f.old(&other, "owner");
    let old = d::snapshot(&other).unwrap();
    assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
    assert_eq!(d::snapshot(&other).unwrap(), old);
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
    f.old(&f.second, "owner");
    let old = d::snapshot(&f.second).unwrap();
    assert!(
        f.install(&[f.first.clone(), f.second.clone()], false)
            .is_err()
    );
    assert!(!f.first.exists());
    assert_eq!(d::snapshot(&f.second).unwrap(), old);
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
    // Payload is already a frozen typed input; install_targets never invokes a payload factory.
    let payload = f.payload();
    d::install_targets(
        &[f.first.clone(), f.second.clone()],
        false,
        &f.source,
        &f.repo,
        &payload,
    )?;
    assert_payload(&f, &f.first);
    assert_payload(&f, &f.second);
    Ok(())
}
#[test]
fn test_empty_directory_requires_force_and_is_preserved_as_a_backup() -> Result<()> {
    let f = Fixture::new();
    fs::create_dir_all(&f.first)?;
    assert!(f.install(std::slice::from_ref(&f.first), false).is_err());
    let backups = f.install(std::slice::from_ref(&f.first), true)?;
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read_dir(&backups[0])?.count(), 0);
    Ok(())
}
#[test]
fn test_existing_install_with_nested_link_is_not_followed() {
    for file in [false, true] {
        let f = Fixture::new();
        f.old(&f.first, "owner");
        let old = d::snapshot(&f.first).unwrap();
        let outside = f.root.join("outside");
        if file {
            fs::write(&outside, b"retain private outside data").unwrap();
            file_link(&outside, &f.first.join("linked"));
        } else {
            fs::create_dir(&outside).unwrap();
            link(&outside, &f.first.join("linked"));
        }
        assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
        let mut entries = fs::read_dir(&f.first)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>();
        entries.sort();
        assert_eq!(
            entries,
            ["SKILL.md", "linked", "retained"].map(std::ffi::OsString::from)
        );
        assert!(revayat_scientific::identity::is_link(&f.first.join("linked")).unwrap());
        if file {
            assert_eq!(fs::read(outside).unwrap(), b"retain private outside data");
        } else {
            assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
        }
        for (name, fingerprint) in &old.unwrap().files {
            if let Some(fingerprint) = fingerprint {
                assert_eq!(
                    revayat_scientific::identity::file_identity(&f.first.join(name), None).unwrap(),
                    *fingerprint
                );
            }
        }
    }
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
    f.old(&f.first, "owner");
    let old = d::snapshot(&f.first).unwrap();
    let file = fs::File::create(f.source.join("assets.bin")).unwrap();
    file.set_len(d::MAX_PAYLOAD_BYTES + 1).unwrap();
    fs::create_dir(f.source.join("assets")).unwrap();
    fs::rename(
        f.source.join("assets.bin"),
        f.source.join("assets/large.bin"),
    )
    .unwrap();
    assert!(Payload::collect(&f.source, None).is_err());
    assert_eq!(d::snapshot(&f.first).unwrap(), old);
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
    let payload = Payload::collect(
        &f.source,
        Some(Path::new(env!("CARGO_BIN_EXE_revayat-scientific"))),
    )
    .unwrap();
    assert_collected_payload(&payload, &f.root.join(".agents/skills/revayat-scientific"));
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
    assert_payload(&f, &f.first);
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
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Installed revayat-scientific:"));
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
fn test_source_file_link_and_nonregular_old_entry_are_rejected() {
    for file in [false, true] {
        let f = Fixture::new();
        let outside = f.root.join("outside");
        if file {
            fs::write(&outside, b"outside").unwrap();
            file_link(&outside, &f.source.join("references/linked.txt"));
        } else {
            fs::create_dir(&outside).unwrap();
            link(&outside, &f.source.join("references/linked"));
        }
        assert!(Payload::collect(&f.source, None).is_err());
        assert!(!f.first.exists());
        if file {
            assert_eq!(fs::read(outside).unwrap(), b"outside");
        } else {
            assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
        }
    }
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
