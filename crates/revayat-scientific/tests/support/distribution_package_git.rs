// Git-layout admission cases retain their root libtest identities via include!.
#[test]
fn test_ordinary_git_config_index_head_and_new_objects_are_protected() {
    let f = Fixture::new();
    for name in ["config", "index", "HEAD", "objects/new.skill"] {
        f.refused(&f.repo.join(".git").join(name));
    }
    assert!(
        f.git(&["status", "--porcelain", "--untracked-files=no"])
            .is_empty()
    );
}
#[test]
fn test_separate_git_directory_and_pointer_file_are_protected() {
    let f = Fixture::new();
    let admin = f.root.join("relocated");
    f.git(&[
        "init",
        "--quiet",
        "--separate-git-dir",
        admin.to_str().unwrap(),
    ]);
    for path in [
        f.repo.join(".git"),
        admin.join("config"),
        admin.join("HEAD"),
        admin.join("new.skill"),
    ] {
        f.refused(&path);
    }
    let observed = PathBuf::from(f.git(&["rev-parse", "--absolute-git-dir"]));
    assert!(observed.is_absolute());
    assert_eq!(
        revayat_scientific::identity::path_object_id(&observed).unwrap(),
        revayat_scientific::identity::path_object_id(&admin).unwrap()
    );
}
#[test]
fn test_linked_worktree_shared_and_private_metadata_are_protected() {
    let f = Fixture::new();
    let linked = f.worktree();
    let private = PathBuf::from(f.git_at(&linked, &["rev-parse", "--absolute-git-dir"]));
    for path in [
        linked.join(".git"),
        private.join("HEAD"),
        private.join("index"),
        f.repo.join(".git/config"),
        f.repo.join(".git/objects/new.skill"),
    ] {
        let before = fs::read(&path).ok();
        assert!(d::package(&linked.join("skills").join(NAME), &linked, &path, None).is_err());
        assert_eq!(fs::read(path).ok(), before);
    }
    assert_eq!(
        f.git_at(&linked, &["rev-parse", "HEAD"]),
        f.git(&["rev-parse", "HEAD"])
    );
}
#[test]
fn test_legitimate_archive_and_exported_source_output_remain_available() -> Result<()> {
    let f = Fixture::new();
    let ordinary = git_path(&f.root)?;
    assert_eq!(
        revayat_scientific::identity::path_object_id(&f.root)?,
        revayat_scientific::identity::path_object_id(&ordinary)?
    );
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        assert!(
            matches!(f.root.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _)))
        );
        assert!(
            matches!(ordinary.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_) | Prefix::UNC(_, _)))
        );
        let pending = f.root.join("new output").join("bundle.skill");
        assert_eq!(
            git_path(&pending)?,
            ordinary.join("new output").join("bundle.skill")
        );
        for name in ["ambiguous.", "ambiguous ", "CON", "LPT1.txt"] {
            assert!(git_path(&f.root.join(name)).is_err(), "{name}");
        }
        let mut traversal = f.root.as_os_str().to_os_string();
        traversal.push(r"\..");
        assert!(git_path(Path::new(&traversal)).is_err());
        assert!(git_path(Path::new(r"\\?\GLOBALROOT\Device\HarddiskVolume1")).is_err());
    }
    let output = f.repo.join("dist/bundle.skill");
    f.package(&output)?;
    let mut zip = zip::ZipArchive::new(fs::File::open(output)?)?;
    let mut text = String::new();
    zip.by_name("revayat-scientific/SKILL.md")?
        .read_to_string(&mut text)?;
    assert_eq!(text.as_bytes(), fs::read(f.source.join("SKILL.md"))?);
    let exported = f.root.join("exported");
    fs::create_dir(&exported)?;
    d::package(&f.source, &exported, &exported.join("bundle.skill"), None)?;
    assert!(exported.join("bundle.skill").is_file());
    assert!(d::package(&f.source, &exported, &exported.join(".git"), None).is_err());
    Ok(())
}
#[test]
fn test_metadata_resolution_failure_is_not_an_empty_allowlist() {
    let f = Fixture::new();
    fs::remove_file(f.repo.join(".git/HEAD")).unwrap();
    let target = f.repo.join("previous.skill");
    fs::write(&target, "approved delivery").unwrap();
    f.refused(&target);
    assert_eq!(fs::read(target).unwrap(), b"approved delivery");
}
#[test]
fn test_git_selected_external_index_and_object_store_are_protected() {
    let f = Fixture::new();
    let index = f.root.join("external-index");
    fs::copy(f.repo.join(".git/index"), &index).unwrap();
    let objects = f.root.join("external-objects");
    fs::create_dir(&objects).unwrap();
    for path in [index.clone(), objects.join("new.skill")] {
        let before = fs::read(&path).ok();
        let output = f.child(
            &path,
            &[
                ("GIT_INDEX_FILE", &index),
                ("GIT_OBJECT_DIRECTORY", &objects),
            ],
        );
        assert!(!output.status.success());
        assert_eq!(fs::read(path).ok(), before);
    }
    let valid = f.repo.join("dist/external-storage.skill");
    let result = f.child(
        &valid,
        &[
            ("GIT_INDEX_FILE", &index),
            ("GIT_OBJECT_DIRECTORY", &objects),
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(valid.is_file());
}
#[test]
fn test_explicit_git_dir_without_gitfile_is_protected() {
    let f = Fixture::new();
    let admin = f.root.join("explicit");
    f.git(&[
        "init",
        "--quiet",
        "--separate-git-dir",
        admin.to_str().unwrap(),
    ]);
    fs::remove_file(f.repo.join(".git")).unwrap();
    for name in ["HEAD", "objects/new.skill", "config"] {
        let target = admin.join(name);
        let before = fs::read(&target).ok();
        assert!(
            !f.child(&target, &[("GIT_DIR", &admin), ("GIT_WORK_TREE", &f.repo)])
                .status
                .success()
        );
        assert_eq!(fs::read(target).ok(), before);
    }
    let valid = f.repo.join("dist/explicit.skill");
    assert!(
        f.child(&valid, &[("GIT_DIR", &admin), ("GIT_WORK_TREE", &f.repo)])
            .status
            .success()
    );
}
#[test]
fn test_invalid_explicit_git_dir_is_not_treated_as_an_export() {
    let f = Fixture::new();
    let path = f.repo.join("previous.skill");
    fs::write(&path, "approved delivery").unwrap();
    assert!(
        !f.child(&path, &[("GIT_DIR", &f.root.join("missing"))])
            .status
            .success()
    );
    assert_eq!(fs::read(path).unwrap(), b"approved delivery");
}
