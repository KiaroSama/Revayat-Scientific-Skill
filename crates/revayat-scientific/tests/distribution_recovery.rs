use anyhow::{Result, bail};
use revayat_scientific::distribution::InstallBoundary as B;
use std::{fs, path::Path};
#[path = "support/distribution_fixture.rs"]
mod support;
use support::*;
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
        let old = f.old(&f.first, "owner");
        fs::write(
            f.first.join("SKILL.md"),
            format!("\u{feff}---\nname: {value}\ndescription: |\n  Fixture\n---\n"),
        )?;
        let backups = f.install(std::slice::from_ref(&f.first), true)?;
        assert_eq!(fs::read(backups[0].join("retained"))?, b"owner");
        assert_ne!(fs::read(f.first.join("SKILL.md"))?, old);
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
        assert!(f.install(std::slice::from_ref(&f.first), true).is_err());
        assert_eq!(fs::read_to_string(f.first.join("SKILL.md")).unwrap(), data);
    }
}
#[test]
fn test_partial_copy_cleanup_failure_retains_owned_stage_and_lock_evidence() {
    let f = Fixture::new();
    assert!(
        f.observed(std::slice::from_ref(&f.first), false, |at, path| {
            if at == B::AfterCopy(0) {
                fs::write(path, "partial candidate")?;
                bail!("partial copy");
            }
            if at == B::BeforeStageCleanup(0) {
                bail!("stage cleanup failure; recovery required");
            }
            Ok(())
        })
        .is_err()
    );
    assert!(!f.first.exists());
    let journals = f.journals();
    assert_eq!(journals.len(), 1);
    let j: serde_json::Value = serde_json::from_slice(&fs::read(&journals[0]).unwrap()).unwrap();
    assert!(Path::new(j["targets"][0]["stage"].as_str().unwrap()).is_dir());
    assert!(f.lock(&f.first).is_file());
}
#[test]
fn test_failed_journal_refresh_cleanup_keeps_initial_stage_identity() {
    let f = Fixture::new();
    let mut initial = None;
    assert!(
        f.observed(std::slice::from_ref(&f.first), false, |at, path| {
            if at == B::BeforeJournal {
                let json: serde_json::Value =
                    serde_json::from_slice(&fs::read(path.join("recovery.json"))?)?;
                initial = Some(json["targets"][0]["stage_identity"].clone());
                fs::create_dir(path.join("prepared.json"))?;
            }
            if at == B::BeforeStageCleanup(0) {
                bail!("retain owned evidence");
            }
            Ok(())
        })
        .is_err()
    );
    let journals = f.journals();
    assert_eq!(journals.len(), 1);
    let j: serde_json::Value = serde_json::from_slice(&fs::read(&journals[0]).unwrap()).unwrap();
    assert_eq!(Some(j["targets"][0]["stage_identity"].clone()), initial);
    assert!(f.lock(&f.first).exists());
}
#[test]
fn test_install_second_cancellation_retains_journal_backups_stages_and_locks() {
    let f = Fixture::new();
    f.old(&f.first, "owner");
    assert!(
        f.observed(std::slice::from_ref(&f.first), true, |at, _| {
            if at == B::AfterActivate(0) || at == B::BeforeRestore(0) {
                bail!("controlled cancellation");
            }
            Ok(())
        })
        .is_err()
    );
    let journals = f.journals();
    assert_eq!(journals.len(), 1);
    let j: serde_json::Value = serde_json::from_slice(&fs::read(&journals[0]).unwrap()).unwrap();
    assert!(
        Path::new(j["targets"][0]["backup"].as_str().unwrap())
            .join("retained")
            .is_file()
    );
    assert!(f.lock(&f.first).exists());
}
#[test]
fn test_completed_install_restoration_error_reconciles_the_previous_edition() {
    let f = Fixture::new();
    let old = f.old(&f.first, "owner");
    assert!(
        f.observed(std::slice::from_ref(&f.first), true, |at, _| {
            if at == B::AfterActivate(0) || at == B::AfterRestore(0) {
                bail!("completed rename reports error");
            }
            Ok(())
        })
        .is_err()
    );
    f.assert_old(&f.first, &old);
    assert!(f.journals().is_empty());
    assert!(!f.lock(&f.first).exists());
}
#[test]
fn test_second_install_restore_cancellation_retains_the_complete_target_plan() {
    let f = Fixture::new();
    f.old(&f.first, "first");
    let second = f.old(&f.second, "second");
    assert!(
        f.observed(&[f.first.clone(), f.second.clone()], true, |at, _| {
            if at == B::AfterActivate(1) || at == B::BeforeRestore(0) {
                bail!("late restoration cancellation");
            }
            Ok(())
        })
        .is_err()
    );
    f.assert_old(&f.second, &second);
    let journals = f.journals();
    assert_eq!(journals.len(), 1);
    let j: serde_json::Value = serde_json::from_slice(&fs::read(&journals[0]).unwrap()).unwrap();
    assert_eq!(j["targets"].as_array().unwrap().len(), 2);
    assert!(f.lock(&f.first).exists() && f.lock(&f.second).exists());
}
