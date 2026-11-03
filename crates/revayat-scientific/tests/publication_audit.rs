//! Additional identity and Unicode collision regressions found during migration audit.
use anyhow::{Result, bail};
use revayat_scientific::{
    identity::{object_id, path_object_id},
    publication::{Boundary, publish_files, publish_observed},
};
use std::{
    fs::{self, File, FileTimes},
    path::PathBuf,
};
#[test]
fn publication_uses_complete_unicode_default_casefold_for_collision_keys() -> Result<()> {
    for (a, b) in [
        ("ﬀ.pdf", "ff.pdf"),
        ("և.pdf", "եւ.pdf"),
        ("ﬅ.pdf", "st.pdf"),
        ("Ა.pdf", "ა.pdf"),
    ] {
        let root = tempfile::tempdir()?;
        let first = root.path().join("a");
        let second = root.path().join("b");
        fs::write(&first, b"first")?;
        fs::write(&second, b"second")?;
        let error = publish_files(
            &[
                (first.clone(), root.path().join(a)),
                (second.clone(), root.path().join(b)),
            ],
            &[],
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate"));
        assert_eq!(fs::read(first)?, b"first");
        assert_eq!(fs::read(second)?, b"second");
        assert!(!root.path().join(a).exists());
        assert!(!root.path().join(b).exists());
    }
    Ok(())
}
#[test]
fn foreign_backup_substitution_after_close_is_retained_for_recovery() -> Result<()> {
    let root = tempfile::tempdir()?;
    let stage = root.path().join("stage");
    let dest = root.path().join("dest");
    fs::write(&stage, b"candidate")?;
    fs::write(&dest, b"approved")?;
    let mut changed = None;
    let error = publish_observed(
        &[(stage.clone(), dest.clone())],
        &[],
        None,
        |event, path| {
            if event == Boundary::BackupPrepared {
                let original = File::open(path)?;
                let id = object_id(&original)?;
                let modified = original.metadata()?.modified()?;
                drop(original);
                let foreign = root.path().join("foreign");
                let contents = fs::read(path)?;
                fs::write(&foreign, &contents)?;
                File::options()
                    .write(true)
                    .open(&foreign)?
                    .set_times(FileTimes::new().set_modified(modified))?;
                let replacement = path_object_id(&foreign)?;
                assert_ne!(id, replacement);
                fs::rename(&foreign, path)?;
                changed = Some((path.to_owned(), replacement, contents));
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("ownership"), "{error}");
    let (path, id, contents) = changed.unwrap();
    assert_eq!(path_object_id(&path)?, id);
    assert_eq!(fs::read(&path)?, contents);
    assert_eq!(fs::read(stage)?, b"candidate");
    assert_eq!(fs::read(dest)?, b"approved");
    assert!(path.parent().unwrap().join("recovery.json").is_file());
    assert!(
        fs::read_dir(root.path())?
            .filter_map(|e| e.ok())
            .any(|e| e.path().extension().is_some_and(|s| s == "lock"))
    );
    Ok(())
}
#[test]
fn same_bytes_foreign_backup_cannot_be_activated_during_rollback() -> Result<()> {
    let root = tempfile::tempdir()?;
    let stage = root.path().join("stage");
    let dest = root.path().join("dest");
    fs::write(&stage, b"candidate")?;
    fs::write(&dest, b"approved")?;
    let mut backup: Option<PathBuf> = None;
    let mut foreign_id = None;
    let error = publish_observed(
        &[(stage.clone(), dest.clone())],
        &[],
        None,
        |event, path| {
            if event == Boundary::BackupPrepared {
                backup = Some(path.to_owned());
            }
            if event == Boundary::AfterCommit {
                let path = backup.as_ref().unwrap();
                let foreign = root.path().join("foreign");
                fs::copy(path, &foreign)?;
                let modified = fs::metadata(path)?.modified()?;
                File::options()
                    .write(true)
                    .open(&foreign)?
                    .set_times(FileTimes::new().set_modified(modified))?;
                foreign_id = Some(path_object_id(&foreign)?);
                fs::rename(foreign, path)?;
                bail!("controlled activation interruption");
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("rollback needs recovery"),
        "{error}"
    );
    let backup = backup.unwrap();
    assert_eq!(path_object_id(&backup)?, foreign_id.unwrap());
    assert_eq!(fs::read(backup)?, b"approved");
    assert_eq!(fs::read(dest)?, b"candidate");
    assert!(!stage.exists());
    Ok(())
}
