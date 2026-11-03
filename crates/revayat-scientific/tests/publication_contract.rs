//! Native file publication and exact-byte identity regressions.
use anyhow::{Result, bail};
use revayat_scientific::identity::{ReadBoundary, file_identity, file_identity_observed};
use revayat_scientific::publication::{
    Boundary, publish_files, publish_observed, validate_destination,
};
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

fn fixture(root: &Path) -> [(PathBuf, PathBuf); 2] {
    let pairs = [
        (root.join("a"), root.join("first")),
        (root.join("b"), root.join("second")),
    ];
    for ((stage, dest), old, new) in pairs
        .iter()
        .zip([b"approved A", b"approved B"])
        .zip([b"new A", b"new B"])
        .map(|((p, o), n)| (p, o, n))
    {
        fs::write(stage, new).unwrap();
        fs::write(dest, old).unwrap();
    }
    pairs
}
fn leftovers(root: &Path) -> Vec<PathBuf> {
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

#[test]
fn test_late_replace_failure_restores_previous_outputs() {
    let temp = tempfile::tempdir().unwrap();
    let pairs = fixture(temp.path());
    let result = publish_observed(&pairs, &[], None, |event, dest| {
        if event == Boundary::BeforeCommit && dest == pairs[1].1 {
            bail!("controlled activation failure");
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(fs::read(&pairs[0].1).unwrap(), b"approved A");
    assert_eq!(fs::read(&pairs[1].1).unwrap(), b"approved B");
    assert!(leftovers(temp.path()).is_empty());
}

#[test]
fn test_casefold_collision_is_rejected_before_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    fs::write(&a, b"A").unwrap();
    fs::write(&b, b"B").unwrap();
    assert!(
        publish_files(
            &[
                (a.clone(), temp.path().join("Output")),
                (b.clone(), temp.path().join("output"))
            ],
            &[],
            None
        )
        .is_err()
    );
    assert_eq!(fs::read(a).unwrap(), b"A");
    assert_eq!(fs::read(b).unwrap(), b"B");
    assert!(leftovers(temp.path()).is_empty());
}

#[test]
fn test_source_alias_and_directory_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source.pdf");
    fs::write(&source, b"original").unwrap();
    for destination in [&source, temp.path()] {
        assert!(validate_destination(destination, std::slice::from_ref(&source)).is_err());
    }
    let alias = temp.path().join("hardlink.pdf");
    fs::hard_link(&source, &alias).unwrap();
    assert!(validate_destination(&alias, &[source]).is_err());
}

#[test]
fn test_publication_rejects_growth_and_revisions_during_a_counted_read() {
    for mode in ["growth", "rewrite", "truncate"] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("dest");
        fs::write(&path, b"approved").unwrap();
        let mut changed = false;
        let mut reads = Vec::new();
        let result = file_identity_observed(&path, None, |event, path| {
            if let ReadBoundary::BeforeRead(size) = event {
                reads.push(size);
                if !changed {
                    changed = true;
                    if mode == "growth" {
                        OpenOptions::new()
                            .append(true)
                            .open(path)?
                            .write_all(b" growth")?;
                    } else {
                        fs::write(
                            path,
                            if mode == "rewrite" {
                                b"changed!".as_slice()
                            } else {
                                b"cut".as_slice()
                            },
                        )?;
                    }
                }
            }
            Ok(())
        });
        assert!(result.is_err(), "{mode}");
        assert!(changed);
        assert!(!reads.is_empty());
        assert!(reads.iter().all(|s| *s > 0 && *s <= 9));
        assert_eq!(
            fs::read(&path).unwrap(),
            match mode {
                "growth" => b"approved growth".as_slice(),
                "rewrite" => b"changed!",
                _ => b"cut",
            }
        );
    }
}

#[test]
fn test_unchanged_publication_accepts_copied_file_timestamps() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let original = root.join("original");
    let stage = root.join("stage");
    let dest = root.join("dest");
    fs::write(&original, b"candidate").unwrap();
    fs::write(&dest, b"approved").unwrap();
    fs::copy(&original, &stage).unwrap();
    File::options()
        .write(true)
        .open(&stage)
        .unwrap()
        .set_times(
            FileTimes::new().set_modified(fs::metadata(&original).unwrap().modified().unwrap()),
        )
        .unwrap();
    publish_files(&[(stage, dest.clone())], &[], None).unwrap();
    assert_eq!(fs::read(dest).unwrap(), b"candidate");
    assert_eq!(fs::read(original).unwrap(), b"candidate");
    assert!(leftovers(root).is_empty());
}

#[test]
fn test_opened_descriptor_substitution_is_refused_before_any_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("dest");
    let foreign = temp.path().join("foreign");
    fs::write(&path, b"approved").unwrap();
    fs::write(&foreign, b"foreign!").unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    File::options()
        .write(true)
        .open(&foreign)
        .unwrap()
        .set_times(FileTimes::new().set_modified(modified))
        .unwrap();
    let mut substituted = false;
    let result = file_identity_observed(&path, None, |event, path| {
        if event == ReadBoundary::BeforeOpen {
            fs::rename(&foreign, path)?;
            substituted = true;
        }
        Ok(())
    });
    assert!(substituted);
    assert!(result.is_err());
    assert_eq!(fs::read(path).unwrap(), b"foreign!");
}

#[test]
fn test_replaced_path_after_descriptor_close_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("dest");
    let foreign = temp.path().join("foreign");
    fs::write(&path, b"approved").unwrap();
    fs::write(&foreign, b"foreign!").unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    File::options()
        .write(true)
        .open(&foreign)
        .unwrap()
        .set_times(FileTimes::new().set_modified(modified))
        .unwrap();
    let mut replaced = false;
    let result = file_identity_observed(&path, None, |event, path| {
        if event == ReadBoundary::AfterClose {
            fs::rename(&foreign, path)?;
            replaced = true;
        }
        Ok(())
    });
    assert!(replaced);
    assert!(result.is_err());
    assert_eq!(fs::read(path).unwrap(), b"foreign!");
}

#[test]
fn test_exact_explicit_limit_and_copied_backup_inode_remain_supported() {
    let temp = tempfile::tempdir().unwrap();
    let pairs = fixture(temp.path());
    // Both candidate and previous outputs exactly fit the existing caller limit.
    fs::write(&pairs[0].1, b"approved").unwrap();
    fs::write(&pairs[1].1, b"previous").unwrap();
    fs::write(&pairs[0].0, b"candidate").unwrap();
    fs::write(&pairs[1].0, b"other new").unwrap();
    let mut copies = 0;
    let result = publish_observed(&pairs, &[], Some(9), |event, dest| {
        if event == Boundary::BackupReady {
            copies += 1;
        }
        if event == Boundary::BeforeCommit && dest == pairs[1].1 {
            bail!("controlled activation failure");
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(copies, 2);
    assert_eq!(fs::read(&pairs[0].1).unwrap(), b"approved");
    assert_eq!(fs::read(&pairs[1].1).unwrap(), b"previous");
    assert!(leftovers(temp.path()).is_empty());
}

#[test]
fn test_explicit_limit_refuses_without_replacing_previous_destination() {
    let temp = tempfile::tempdir().unwrap();
    let dest = temp.path().join("dest");
    let stage = temp.path().join("stage");
    fs::write(&dest, b"approved").unwrap();
    fs::write(&stage, b"candidate").unwrap();
    assert!(publish_files(&[(stage.clone(), dest.clone())], &[], Some(8)).is_err());
    assert_eq!(fs::read(dest).unwrap(), b"approved");
    assert_eq!(fs::read(stage).unwrap(), b"candidate");
    assert!(leftovers(temp.path()).is_empty());
}

#[test]
fn test_missing_previous_destination_and_empty_candidate_remain_supported() {
    let temp = tempfile::tempdir().unwrap();
    let dest = temp.path().join("dest");
    let stage = temp.path().join("stage");
    fs::write(&stage, b"").unwrap();
    publish_files(&[(stage.clone(), dest.clone())], &[], Some(0)).unwrap();
    assert_eq!(fs::read(dest).unwrap(), b"");
    assert!(!stage.exists());
    assert!(leftovers(temp.path()).is_empty());
}

#[test]
fn test_foreign_destination_revision_is_preserved_with_recovery_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let pairs = fixture(temp.path());
    let mut modified = false;
    let result = publish_observed(&pairs, &[], None, |event, dest| {
        if event == Boundary::AfterCommit && !modified {
            modified = true;
            fs::write(dest, b"concurrent foreign revision")?;
            bail!("controlled interruption");
        }
        Ok(())
    });
    assert!(result.unwrap_err().to_string().contains("needs recovery"));
    assert!(modified);
    assert_eq!(
        fs::read(&pairs[0].1).unwrap(),
        b"concurrent foreign revision"
    );
    let evidence = leftovers(temp.path());
    assert!(evidence.iter().any(|p| p.join("recovery.json").is_file()));
    assert!(
        evidence
            .iter()
            .any(|p| p.extension().is_some_and(|e| e == "lock"))
    );
}

#[test]
fn test_digest_and_empty_file_identity_are_exact() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("bytes");
    fs::write(&path, b"abc")?;
    assert_eq!(
        file_identity(&path, Some(3))?.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(file_identity(&path, Some(2)).is_err());
    fs::write(&path, b"")?;
    assert_eq!(file_identity(&path, Some(0))?.size, 0);
    Ok(())
}
