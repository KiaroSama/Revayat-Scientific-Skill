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
    for ((s, d), label) in entries.iter().zip(["A", "B"]) {
        fs::write(s, format!("candidate {label}")).unwrap();
        fs::write(d, format!("approved {label}")).unwrap();
    }
    entries
}
fn artifacts(root: &Path) -> Vec<PathBuf> {
    fs::read_dir(root)
        .unwrap()
        .map(|p| p.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".revayat-publish-")
        })
        .collect()
}
fn journals(root: &Path) -> Vec<PathBuf> {
    artifacts(root)
        .into_iter()
        .map(|p| p.join("recovery.json"))
        .filter(|p| p.is_file())
        .collect()
}
#[test]
fn test_completed_replace_exception_restores_whole_previous_batch() {
    for absent in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let entries = plans(root.as_path());
        if absent {
            fs::remove_file(&entries[0].1).unwrap();
        }
        let mut committed = false;
        let result = publish_observed(&entries, &[], None, |event, dest| {
            if event == Boundary::AfterCommit && dest == entries[1].1 {
                committed = true;
                bail!("second native replacement completed before reporting error");
            }
            Ok(())
        });
        assert!(committed, "second replacement must reach AfterCommit");
        assert!(result.is_err());
        if absent {
            assert!(!entries[0].1.exists());
        } else {
            assert_eq!(fs::read(&entries[0].1).unwrap(), b"approved A");
        }
        assert_eq!(fs::read(&entries[1].1).unwrap(), b"approved B");
        assert!(artifacts(root.as_path()).is_empty());
    }
}
#[test]
fn test_corrupt_publication_backup_refuses_before_any_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let entries = plans(root.as_path());
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
    for ((s, d), label) in entries.iter().zip(["A", "B"]) {
        assert_eq!(
            fs::read(s).unwrap(),
            format!("candidate {label}").as_bytes()
        );
        assert_eq!(fs::read(d).unwrap(), format!("approved {label}").as_bytes());
    }
    assert!(artifacts(root.as_path()).is_empty());
}
#[test]
fn test_changed_backup_is_retained_instead_of_restored_on_late_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let entries = plans(root.as_path());
    let error = publish_observed(&entries, &[], None, |event, dest| {
        if event == Boundary::BeforeCommit && dest == entries[1].1 {
            let journal = journals(root.as_path())
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
    assert_eq!(fs::read(&entries[0].1).unwrap(), b"candidate A");
    assert_eq!(fs::read(&entries[1].1).unwrap(), b"approved B");
    let journals = journals(root.as_path());
    assert_eq!(journals.len(), 2);
    assert!(journals.iter().any(|p| {
        fs::read(p.parent().unwrap().join("previous")).is_ok_and(|b| b == b"changed recovery bytes")
    }));
}
