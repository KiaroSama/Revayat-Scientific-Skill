use anyhow::{Result, bail};
use revayat_scientific::{
    distribution::{self as d, NAME},
    distribution_package::{PackageBoundary as B, package_observed},
};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
};
const HEADER: &str = "---\nname: revayat-scientific\ndescription: Fixture\n---\n";
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    repo: PathBuf,
    source: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let scratch = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".scratch");
        fs::create_dir_all(&scratch).unwrap();
        let temp = tempfile::tempdir_in(scratch).unwrap();
        let root = temp.path().to_owned();
        let repo = root.join("checkout");
        let source = repo.join("skills").join(NAME);
        fs::create_dir_all(source.join("references")).unwrap();
        fs::write(
            source.join("SKILL.md"),
            format!("{HEADER}unchanged instructions"),
        )
        .unwrap();
        fs::write(source.join("LICENSE"), "GPL-3.0-or-later").unwrap();
        fs::write(
            source.join("NOTICE.md"),
            "Original authors and license notices",
        )
        .unwrap();
        fs::write(
            source.join("references/contract.md"),
            "Source-preserving contract",
        )
        .unwrap();
        let f = Self {
            _temp: temp,
            root,
            repo,
            source,
        };
        f.git(&["init", "--quiet"]);
        f.git(&["symbolic-ref", "HEAD", "refs/heads/main"]);
        f.git(&["add", "."]);
        f.git(&[
            "commit",
            "--quiet",
            "-m",
            "Synthetic fixture, never published",
        ]);
        f
    }
    fn git(&self, args: &[&str]) -> String {
        self.git_at(&self.repo, args)
    }
    fn git_at(&self, cwd: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .env("GIT_AUTHOR_NAME", "Synthetic Fixture")
            .env("GIT_COMMITTER_NAME", "Synthetic Fixture")
            .env("GIT_AUTHOR_EMAIL", "Kiaro.Sama.Dev@gmail.com")
            .env("GIT_COMMITTER_EMAIL", "Kiaro.Sama.Dev@gmail.com")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
    fn package(&self, target: &Path) -> Result<()> {
        d::package(&self.source, &self.repo, target, None)
    }
    fn refused(&self, target: &Path) {
        let before = fs::read(target).ok();
        let error = self.package(target).unwrap_err();
        assert!(!error.to_string().is_empty());
        assert_eq!(fs::read(target).ok(), before);
    }
    fn child(&self, target: &Path, env: &[(&str, &Path)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"));
        cmd.env("REVAYAT_REPOSITORY", &self.repo)
            .args(["package", "--output"])
            .arg(target);
        for (name, path) in env {
            cmd.env(name, path);
        }
        cmd.output().unwrap()
    }
    fn worktree(&self) -> PathBuf {
        let linked = self.root.join("linked worktree");
        self.git(&[
            "worktree",
            "add",
            "--quiet",
            "--detach",
            linked.to_str().unwrap(),
            "HEAD",
        ]);
        linked
    }
}
#[cfg(unix)]
fn link(source: &Path, dest: &Path) {
    std::os::unix::fs::symlink(source, dest).unwrap();
}
#[cfg(windows)]
fn link(source: &Path, dest: &Path) {
    std::os::windows::fs::symlink_file(source, dest).unwrap();
}
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
        admin.join("new.skill"),
    ] {
        f.refused(&path);
    }
    assert!(admin.join("HEAD").is_file());
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
    ] {
        assert!(d::package(&linked.join("skills").join(NAME), &linked, &path, None).is_err());
    }
    assert_eq!(
        f.git_at(&linked, &["rev-parse", "HEAD"]),
        f.git(&["rev-parse", "HEAD"])
    );
}
#[test]
fn test_legitimate_archive_and_exported_source_output_remain_available() -> Result<()> {
    let f = Fixture::new();
    let output = f.repo.join("dist/bundle.skill");
    f.package(&output)?;
    let mut zip = zip::ZipArchive::new(fs::File::open(output)?)?;
    let mut text = String::new();
    zip.by_name("revayat-scientific/SKILL.md")?
        .read_to_string(&mut text)?;
    assert!(text.contains("unchanged instructions"));
    let exported = f.root.join("exported");
    fs::create_dir(&exported)?;
    d::package(&f.source, &exported, &exported.join("bundle.skill"), None)?;
    assert!(exported.join("bundle.skill").is_file());
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
    for path in [&index, &objects.join("new.skill")] {
        let before = fs::read(path).ok();
        let output = f.child(
            path,
            &[
                ("GIT_INDEX_FILE", &index),
                ("GIT_OBJECT_DIRECTORY", &objects),
            ],
        );
        assert!(!output.status.success());
        assert_eq!(fs::read(path).ok(), before);
    }
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
    let config = admin.join("config");
    let before = fs::read(&config).unwrap();
    assert!(
        !f.child(&config, &[("GIT_DIR", &admin), ("GIT_WORK_TREE", &f.repo)])
            .status
            .success()
    );
    assert_eq!(fs::read(config).unwrap(), before);
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
#[test]
fn test_index_config_head_and_refs_remain_byte_exact() {
    let f = Fixture::new();
    for name in ["index", "config", "HEAD", "refs/heads/main"] {
        f.refused(&f.repo.join(".git").join(name));
    }
    assert!(
        f.git(&["status", "--porcelain", "--untracked-files=no"])
            .is_empty()
    );
}
#[test]
fn test_new_files_inside_git_objects_or_logs_are_refused() {
    let f = Fixture::new();
    for name in ["objects/new.skill", "logs/new.skill", "hooks/new.skill"] {
        f.refused(&f.repo.join(".git").join(name));
    }
}
#[test]
fn test_linked_worktree_gitfile_and_private_admin_directory_are_protected() {
    let f = Fixture::new();
    let linked = f.worktree();
    let admin = PathBuf::from(f.git_at(&linked, &["rev-parse", "--absolute-git-dir"]));
    for path in [
        linked.join(".git"),
        admin.join("HEAD"),
        admin.join("new.skill"),
    ] {
        let before = fs::read(&path).ok();
        assert!(d::package(&linked.join("skills").join(NAME), &linked, &path, None).is_err());
        assert_eq!(fs::read(path).ok(), before);
    }
}
#[test]
fn test_worktree_shared_common_directory_is_protected() {
    let f = Fixture::new();
    let linked = f.worktree();
    for name in ["config", "refs/heads/main", "objects/new.skill"] {
        let path = f.repo.join(".git").join(name);
        let before = fs::read(&path).ok();
        assert!(d::package(&linked.join("skills").join(NAME), &linked, &path, None).is_err());
        assert_eq!(fs::read(path).ok(), before);
    }
}
#[test]
fn test_external_separate_git_directory_is_protected() {
    let f = Fixture::new();
    let admin = f.root.join("separate");
    f.git(&[
        "init",
        "--quiet",
        "--separate-git-dir",
        admin.to_str().unwrap(),
    ]);
    for path in [
        admin.join("HEAD"),
        admin.join("index"),
        admin.join("objects/new.skill"),
    ] {
        f.refused(&path);
    }
}
#[test]
fn test_environment_selected_index_is_not_an_output() {
    let f = Fixture::new();
    let index = f.root.join("selected-index");
    fs::copy(f.repo.join(".git/index"), &index).unwrap();
    let before = fs::read(&index).unwrap();
    assert!(
        !f.child(&index, &[("GIT_INDEX_FILE", &index)])
            .status
            .success()
    );
    assert_eq!(fs::read(index).unwrap(), before);
}
#[test]
fn test_hardlinked_critical_metadata_is_not_a_package_destination() {
    let f = Fixture::new();
    for (i, name) in ["HEAD", "index", "config"].iter().enumerate() {
        let target = f.repo.join(format!("alias-{i}.skill"));
        fs::hard_link(f.repo.join(".git").join(name), &target).unwrap();
        f.refused(&target);
    }
}
#[test]
fn test_valid_output_does_not_require_mutating_repository_metadata() -> Result<()> {
    let f = Fixture::new();
    let index = fs::read(f.repo.join(".git/index"))?;
    let head = f.git(&["rev-parse", "HEAD"]);
    f.package(&f.repo.join("dist/bundle.skill"))?;
    assert_eq!(fs::read(f.repo.join(".git/index"))?, index);
    assert_eq!(f.git(&["rev-parse", "HEAD"]), head);
    Ok(())
}
#[test]
fn test_exported_source_with_no_git_metadata_remains_packagable() -> Result<()> {
    let f = Fixture::new();
    fs::remove_dir_all(f.repo.join(".git"))?;
    let target = f.repo.join("export.skill");
    f.package(&target)?;
    assert!(zip::ZipArchive::new(fs::File::open(target)?).is_ok());
    Ok(())
}
#[test]
fn test_dotgithub_and_similarly_named_outputs_are_not_metadata() -> Result<()> {
    let f = Fixture::new();
    for name in [".github/bundle.skill", "not.git/bundle.skill"] {
        f.package(&f.repo.join(name))?;
        assert!(f.repo.join(name).is_file());
    }
    Ok(())
}
#[test]
fn test_metadata_discovery_failure_preserves_previous_delivery() {
    let f = Fixture::new();
    let path = f.repo.join("previous.skill");
    fs::write(&path, "approved").unwrap();
    fs::write(f.repo.join(".git/HEAD"), "invalid revision").unwrap();
    f.refused(&path);
    assert_eq!(fs::read(path).unwrap(), b"approved");
}
#[test]
fn test_vendored_source_uses_the_parent_repository_admin_directory() {
    let f = Fixture::new();
    let vendored = f.repo.join("vendor/project");
    fs::create_dir_all(&vendored).unwrap();
    let target = f.repo.join(".git/objects/new.skill");
    assert!(d::package(&f.source, &vendored, &target, None).is_err());
    assert!(!target.exists());
}
#[test]
fn test_redirected_object_database_is_protected() {
    let f = Fixture::new();
    let objects = f.root.join("redirected-objects");
    fs::create_dir(&objects).unwrap();
    let target = objects.join("new.skill");
    assert!(
        !f.child(&target, &[("GIT_OBJECT_DIRECTORY", &objects)])
            .status
            .success()
    );
    assert!(!target.exists());
}
#[test]
fn test_configured_external_hooks_directory_is_protected() {
    let f = Fixture::new();
    let hooks = f.root.join("external-hooks");
    fs::create_dir(&hooks).unwrap();
    f.git(&["config", "core.hooksPath", hooks.to_str().unwrap()]);
    let target = hooks.join("new.skill");
    f.refused(&target);
    assert!(!target.exists());
}
#[test]
fn test_explicit_repository_environment_without_a_dotgit_marker_is_respected() {
    let f = Fixture::new();
    let admin = f.root.join("selected-admin");
    f.git(&[
        "init",
        "--quiet",
        "--separate-git-dir",
        admin.to_str().unwrap(),
    ]);
    fs::remove_file(f.repo.join(".git")).unwrap();
    let target = admin.join("HEAD");
    let before = fs::read(&target).unwrap();
    assert!(
        !f.child(&target, &[("GIT_DIR", &admin), ("GIT_WORK_TREE", &f.repo)])
            .status
            .success()
    );
    assert_eq!(fs::read(target).unwrap(), before);
}
#[test]
fn test_ambiguous_admin_paths_fail_without_publishing() {
    let f = Fixture::new();
    fs::write(f.repo.join(".git/commondir"), "missing-common\nother\n").unwrap();
    let path = f.repo.join("approved.skill");
    fs::write(&path, "approved").unwrap();
    f.refused(&path);
}
#[test]
fn test_index_relocation_during_staging_is_rechecked() {
    let f = Fixture::new();
    let selected = f.root.join("late-index");
    fs::copy(f.repo.join(".git/index"), &selected).unwrap();
    let before = fs::read(&selected).unwrap();
    let result = package_observed(&f.source, &f.repo, &selected, None, |at, _| {
        if at == B::Staged {
            f.git(&["config", "core.hooksPath", selected.to_str().unwrap()]);
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(fs::read(selected).unwrap(), before);
}
#[test]
fn test_external_index_shared_storage_and_hardlink_remain_unchanged() {
    let f = Fixture::new();
    let index = f.root.join("external-index");
    fs::copy(f.repo.join(".git/index"), &index).unwrap();
    let alias = f.root.join("alias.skill");
    fs::hard_link(&index, &alias).unwrap();
    let before = fs::read(&index).unwrap();
    assert!(
        !f.child(&alias, &[("GIT_INDEX_FILE", &index)])
            .status
            .success()
    );
    assert_eq!(fs::read(index).unwrap(), before);
    assert_eq!(fs::read(alias).unwrap(), before);
}
#[test]
fn test_reserved_case_variant_git_component_is_refused() {
    let f = Fixture::new();
    for name in [".GIT", ".Git"] {
        f.refused(&f.repo.join(name).join("new.skill"));
    }
}
#[test]
fn test_output_cannot_overwrite_distributed_source() {
    let f = Fixture::new();
    for path in [
        f.source.join("SKILL.md"),
        f.source.join("LICENSE"),
        f.source.join("references/contract.md"),
    ] {
        f.refused(&path);
    }
}
#[test]
fn test_output_symlink_cannot_replace_or_follow_another_file() {
    let f = Fixture::new();
    let outside = f.root.join("outside");
    fs::write(&outside, "owner bytes").unwrap();
    let alias = f.repo.join("alias.skill");
    link(&outside, &alias);
    assert!(f.package(&alias).is_err());
    assert_eq!(fs::read(outside).unwrap(), b"owner bytes");
    assert!(revayat_scientific::identity::is_link(&alias).unwrap());
}
#[test]
fn test_hardlink_alias_of_source_is_refused() {
    let f = Fixture::new();
    let alias = f.repo.join("alias.skill");
    fs::hard_link(f.source.join("SKILL.md"), &alias).unwrap();
    f.refused(&alias);
}
#[test]
fn test_case_variant_and_directory_destinations_fail_without_side_effects() {
    let f = Fixture::new();
    let dir = f.repo.join("directory.skill");
    fs::create_dir(&dir).unwrap();
    assert!(f.package(&dir).is_err());
    let existing = f.repo.join("Bundle.skill");
    fs::write(&existing, "owner edition").unwrap();
    assert!(f.package(&f.repo.join("bundle.skill")).is_err());
    assert_eq!(fs::read(existing).unwrap(), b"owner edition");
}
#[test]
fn test_valid_archive_and_repeat_build_preserve_payload() -> Result<()> {
    let f = Fixture::new();
    let target = f.repo.join("bundle.skill");
    for _ in 0..2 {
        f.package(&target)?;
        let mut archive = zip::ZipArchive::new(fs::File::open(&target)?)?;
        for row in d::Payload::collect(&f.source, None)?.files {
            let mut bytes = Vec::new();
            archive
                .by_name(&format!(
                    "{NAME}/{}",
                    row.relative.to_string_lossy().replace('\\', "/")
                ))?
                .read_to_end(&mut bytes)?;
            assert_eq!(bytes, fs::read(row.source)?);
        }
    }
    Ok(())
}
#[test]
fn test_tracked_nonpayload_document_is_protected() {
    let f = Fixture::new();
    let path = f.repo.join("private-notes.md");
    fs::write(&path, "tracked owner document").unwrap();
    f.git(&["add", "private-notes.md"]);
    f.refused(&path);
    assert_eq!(fs::read(path).unwrap(), b"tracked owner document");
}
#[test]
fn test_new_output_inside_implementation_directories_is_rejected() {
    let f = Fixture::new();
    for name in ["tools/new.skill", "install/new.skill", "crates/new.skill"] {
        let path = f.repo.join(name);
        f.refused(&path);
        assert!(!path.exists());
    }
}
#[test]
fn test_missing_skill_and_late_archive_failure_keep_previous_output() {
    let f = Fixture::new();
    let path = f.repo.join("approved.skill");
    fs::write(&path, "approved").unwrap();
    fs::remove_file(f.source.join("SKILL.md")).unwrap();
    f.refused(&path);
    fs::write(f.source.join("SKILL.md"), HEADER).unwrap();
    assert!(
        package_observed(&f.source, &f.repo, &path, None, |at, _| {
            if at == B::Staged {
                bail!("controlled late archive failure");
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fs::read(path).unwrap(), b"approved");
}
#[test]
fn test_publication_failure_keeps_approved_archive() {
    let f = Fixture::new();
    let target = f.repo.join("approved.skill");
    fs::write(&target, "approved").unwrap();
    assert!(
        package_observed(&f.source, &f.repo, &target, None, |at, _| {
            if at == B::BeforePublish {
                bail!("controlled publication failure");
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fs::read(target).unwrap(), b"approved");
}
#[test]
fn test_unreadable_git_index_refuses_before_packaging() {
    let f = Fixture::new();
    let path = f.repo.join("approved.skill");
    fs::write(&path, "approved").unwrap();
    fs::write(f.repo.join(".git/index"), "invalid index data").unwrap();
    f.refused(&path);
}
#[test]
fn test_metadata_and_references() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    revayat_scientific::validation::validate_family_layout(root)?;
    for name in [
        ".codex-plugin/plugin.json",
        ".claude-plugin/plugin.json",
        ".cursor-plugin/plugin.json",
    ] {
        let value: serde_json::Value = serde_json::from_slice(&fs::read(root.join(name))?)?;
        assert_eq!(value["version"], "2.0.0");
        assert!(
            value["keywords"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "rust")
        );
    }
    Ok(())
}
#[test]
fn test_install_launchers_replacement_and_logs() -> Result<()> {
    let f = Fixture::new();
    let target = f.root.join("installed");
    let output = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .env("REVAYAT_REPOSITORY", &f.repo)
        .args(["install", "--dest"])
        .arg(&target)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let executable = target.join("bin").join(if cfg!(windows) {
        "revayat-scientific.exe"
    } else {
        "revayat-scientific"
    });
    let output = Command::new(executable).arg("--version").output()?;
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("2.0.0"));
    assert!(target.join("LICENSE").is_file());
    Ok(())
}
#[test]
fn test_archive_is_self_contained() -> Result<()> {
    let f = Fixture::new();
    let binary = f.root.join("native-binary");
    fs::write(&binary, b"synthetic executable payload")?;
    let target = f.repo.join("bundle.skill");
    d::package(&f.source, &f.repo, &target, Some(&binary))?;
    let mut archive = zip::ZipArchive::new(fs::File::open(target)?)?;
    for name in ["SKILL.md", "LICENSE", "NOTICE.md", "references/contract.md"] {
        assert!(archive.by_name(&format!("{NAME}/{name}")).is_ok());
    }
    let name = format!(
        "{NAME}/bin/{}",
        if cfg!(windows) {
            "revayat-scientific.exe"
        } else {
            "revayat-scientific"
        }
    );
    let mut file = archive.by_name(&name)?;
    assert_eq!(file.unix_mode().unwrap() & 0o777, 0o755);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"synthetic executable payload");
    Ok(())
}
#[test]
fn archive_corruption_is_rejected_before_previous_delivery_changes() {
    let f = Fixture::new();
    let target = f.repo.join("approved.skill");
    fs::write(&target, "approved").unwrap();
    assert!(
        package_observed(&f.source, &f.repo, &target, None, |at, path| {
            if at == B::Staged {
                let mut file = fs::OpenOptions::new().write(true).open(path)?;
                file.write_all(b"damaged archive")?;
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fs::read(target).unwrap(), b"approved");
}
