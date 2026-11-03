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
fn journals(root: &Path) -> Vec<PathBuf> {
    fs::read_dir(root)
        .unwrap()
        .map(|p| p.unwrap().path().join("recovery.json"))
        .filter(|p| p.is_file())
        .collect()
}
#[test]
fn test_completed_replace_exception_restores_whole_previous_batch() {
    for absent in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let entries = plans(temp.path());
        if absent {
            fs::remove_file(&entries[0].1).unwrap();
        }
        let result = publish_observed(&entries, &[], None, |event, dest| {
            if event == Boundary::AfterCommit && dest == entries[1].1 {
                bail!("second native replacement completed before reporting error");
            }
            Ok(())
        });
        assert!(result.is_err());
        if absent {
            assert!(!entries[0].1.exists());
        } else {
            assert_eq!(fs::read(&entries[0].1).unwrap(), b"approved");
        }
        assert_eq!(fs::read(&entries[1].1).unwrap(), b"approved");
        assert!(journals(temp.path()).is_empty());
    }
}
#[test]
fn test_corrupt_publication_backup_refuses_before_any_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let entries = plans(temp.path());
    let mut corrupted = false;
    let result = publish_observed(&entries, &[], None, |event, path| {
        if event == Boundary::BackupPrepared && !corrupted {
            corrupted = true;
            fs::write(path, b"corrupted backup")?;
        }
        Ok(())
    });
    assert!(corrupted);
    assert!(result.is_err());
    for (s, d) in &entries {
        assert_eq!(fs::read(s).unwrap(), b"candidate");
        assert_eq!(fs::read(d).unwrap(), b"approved");
    }
    assert!(journals(temp.path()).is_empty());
}
#[test]
fn test_changed_backup_is_retained_instead_of_restored_on_late_failure() {
    let temp = tempfile::tempdir().unwrap();
    let entries = plans(temp.path());
    let error = publish_observed(&entries, &[], None, |event, dest| {
        if event == Boundary::BeforeCommit && dest == entries[1].1 {
            let journal = journals(temp.path())
                .into_iter()
                .find(|path| {
                    let value: serde_json::Value =
                        serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                    value["destination"] == entries[0].1.to_string_lossy().as_ref()
                })
                .unwrap();
            fs::write(
                journal.parent().unwrap().join("previous"),
                b"changed recovery bytes",
            )?;
            bail!("controlled late failure");
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("rollback needs recovery"));
    assert_eq!(fs::read(&entries[0].1).unwrap(), b"candidate");
    assert_eq!(fs::read(&entries[1].1).unwrap(), b"approved");
    let journals = journals(temp.path());
    assert_eq!(journals.len(), 2);
    assert!(journals.iter().any(|p| {
        fs::read(p.parent().unwrap().join("previous")).is_ok_and(|b| b == b"changed recovery bytes")
    }));
}
