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
        let root = temp.path().canonicalize().unwrap();
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
        if let Some(parent) = target.parent().filter(|path| path.is_dir()) {
            assert!(!fs::read_dir(parent).unwrap().any(|entry| {
                let name = entry.unwrap().file_name();
                let name = name.to_string_lossy();
                name.starts_with(".revayat-package-") || name.starts_with(".revayat-publish-")
            }));
        }
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
include!("support/distribution_package_git.rs");
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
        admin.join("index"),
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
        admin.join("config"),
        admin.join("objects/new.skill"),
        admin.join("new.skill"),
    ] {
        f.refused(&path);
    }
    f.git(&["status", "--porcelain"]);
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
    for target in [
        f.repo.join("dist/bundle.skill"),
        f.root.join("outside.skill"),
    ] {
        f.package(&target)?;
        let mut archive = zip::ZipArchive::new(fs::File::open(target)?)?;
        let mut bytes = Vec::new();
        archive
            .by_name(&format!("{NAME}/SKILL.md"))?
            .read_to_end(&mut bytes)?;
        assert_eq!(bytes, fs::read(f.source.join("SKILL.md"))?);
    }
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
    assert!(!f.repo.join(".git").exists());
    Ok(())
}
#[test]
fn test_dotgithub_and_similarly_named_outputs_are_not_metadata() -> Result<()> {
    let f = Fixture::new();
    for target in [
        f.repo.join(".github/bundle.skill"),
        f.repo.join("not.git/bundle.skill"),
        f.root.join(".git-notes.skill"),
    ] {
        f.package(&target)?;
        assert!(zip::ZipArchive::new(fs::File::open(target)?).is_ok());
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
    let valid = vendored.join("dist/result.skill");
    d::package(&f.source, &vendored, &valid, None).unwrap();
    assert!(valid.is_file());
    let nested_source = vendored.join("skills").join(NAME);
    fs::create_dir_all(&nested_source).unwrap();
    fs::write(nested_source.join("SKILL.md"), HEADER).unwrap();
    let external = f.root.join("external metadata");
    f.git(&[
        "init",
        "--quiet",
        "--separate-git-dir",
        external.to_str().unwrap(),
    ]);
    let index = external.join("index");
    let before = fs::read(&index).unwrap();
    assert!(d::package(&nested_source, &vendored, &index, None).is_err());
    assert_eq!(fs::read(index).unwrap(), before);
    let valid = vendored.join("dist/relocated.skill");
    d::package(&nested_source, &vendored, &valid, None).unwrap();
    let mut archive = zip::ZipArchive::new(fs::File::open(valid).unwrap()).unwrap();
    let mut bytes = Vec::new();
    archive
        .by_name(&format!("{NAME}/SKILL.md"))
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, fs::read(nested_source.join("SKILL.md")).unwrap());
    f.git_at(&vendored, &["status", "--porcelain"]);
}
#[test]
fn test_redirected_object_database_is_protected() {
    let f = Fixture::new();
    let objects = f.root.join("redirected-objects");
    fs::create_dir(&objects).unwrap();
    for existing in [false, true] {
        let target = objects.join(if existing {
            "existing-object"
        } else {
            "new.skill"
        });
        if existing {
            fs::write(&target, b"untouched object sentinel").unwrap();
        }
        let before = fs::read(&target).ok();
        assert!(
            !f.child(&target, &[("GIT_OBJECT_DIRECTORY", &objects)])
                .status
                .success()
        );
        assert_eq!(fs::read(target).ok(), before);
    }
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
    let existing = hooks.join("pre-commit");
    fs::write(&existing, b"untouched hook sentinel").unwrap();
    f.refused(&existing);
    assert_eq!(fs::read(existing).unwrap(), b"untouched hook sentinel");
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
    // Exercise the exact production parser, not an invented broken repository
    // response. Actual Git invocation remains covered by the controls above.
    use revayat_scientific::distribution_paths::parse_git_paths;
    let absolute = f.repo.join(".git").to_str().unwrap().to_owned();
    let valid = format!("{0}\n{0}\n{0}\n{0}\n{0}\n", absolute);
    assert_eq!(parse_git_paths(valid.as_bytes()).unwrap().len(), 5);
    assert_eq!(
        parse_git_paths(format!("{valid}\n").as_bytes())
            .unwrap()
            .len(),
        5
    );
    assert_eq!(
        parse_git_paths(format!("{valid}{absolute}\n").as_bytes())
            .unwrap()
            .len(),
        6
    );
    let malformed = [
        format!("relative\n{0}\n{0}\n{0}\n{0}\n", absolute).into_bytes(),
        format!("\n{0}\n{0}\n{0}\n{0}\n", absolute).into_bytes(),
        format!("{0}\n{0}\n", absolute).into_bytes(),
        format!("{valid}relative-shared-index\n").into_bytes(),
        [valid.as_bytes(), &[0xff, b'\n']].concat(),
    ];
    for raw in malformed {
        assert!(parse_git_paths(&raw).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"approved");
    }
}
#[test]
fn test_index_relocation_during_staging_is_rechecked() {
    let f = Fixture::new();
    let selected = f.root.join("late-index");
    fs::copy(f.repo.join(".git/index"), &selected).unwrap();
    let before = fs::read(&selected).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_revayat-test-tool"))
        .arg("package-relocated-index")
        .arg(&f.source)
        .arg(&f.repo)
        .arg(&selected)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("staged=true"));
    assert_eq!(fs::read(&selected).unwrap(), before);
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
    assert_eq!(fs::read(&index).unwrap(), before);
    assert_eq!(fs::read(alias).unwrap(), before);
    let output = Command::new("git")
        .args(["update-index", "--split-index"])
        .current_dir(&f.repo)
        .env("GIT_INDEX_FILE", &index)
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--shared-index-path"])
        .current_dir(&f.repo)
        .env("GIT_INDEX_FILE", &index)
        .output()
        .unwrap();
    assert!(output.status.success());
    let shared = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    assert!(shared.is_file());
    let previous = fs::read(&shared).unwrap();
    let linked = f.root.join("shared-alias.skill");
    fs::hard_link(&shared, &linked).unwrap();
    for target in [&shared, &linked] {
        let output = f.child(target, &[("GIT_INDEX_FILE", &index)]);
        assert!(!output.status.success());
    }
    assert_eq!(fs::read(shared).unwrap(), previous);
}
#[test]
fn test_reserved_case_variant_git_component_is_refused() {
    let f = Fixture::new();
    for name in [".GIT", ".Git"] {
        f.refused(&f.repo.join(name).join("new.skill"));
    }
    let target = f.root.join(".GIT/index");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, b"protected metadata sentinel").unwrap();
    f.refused(&target);
    assert_eq!(fs::read(target).unwrap(), b"protected metadata sentinel");
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
    assert_eq!(
        revayat_scientific::identity::path_object_id(&alias).unwrap(),
        revayat_scientific::identity::path_object_id(&f.source.join("SKILL.md")).unwrap()
    );
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
    for newline in [
        b"retained reference\n".as_slice(),
        b"retained reference\r\n".as_slice(),
    ] {
        fs::write(f.source.join("references/contract.md"), newline)?;
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
            assert_eq!(fs::read(f.source.join("references/contract.md"))?, newline);
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
    for path in [
        f.repo.join("tools/new.skill"),
        f.repo.join("install/new.skill"),
        f.repo.join("crates/new.skill"),
        f.source.join("new-package.skill"),
    ] {
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
    assert_eq!(fs::read(&path).unwrap(), b"approved");
    for foreign in [false, true] {
        let mut reached = false;
        let error = package_observed(&f.source, &f.repo, &path, None, |at, source| {
            if at == B::BeforeArchiveEntry(1) {
                reached = true;
                if foreign {
                    let replacement = f.root.join("foreign entry");
                    let original = fs::metadata(source)?.modified()?;
                    fs::write(&replacement, fs::read(source)?)?;
                    fs::File::options()
                        .write(true)
                        .open(&replacement)?
                        .set_times(fs::FileTimes::new().set_modified(original))?;
                    assert_ne!(
                        revayat_scientific::identity::path_object_id(source)?,
                        revayat_scientific::identity::path_object_id(&replacement)?
                    );
                    fs::rename(replacement, source)?;
                } else {
                    fs::OpenOptions::new()
                        .append(true)
                        .open(source)?
                        .write_all(b" growth")?;
                }
            }
            Ok(())
        })
        .unwrap_err();
        assert!(reached);
        assert!(
            error
                .to_string()
                .contains("payload changed before archive write")
        );
        assert_eq!(fs::read(&path).unwrap(), b"approved");
    }
    let mut entry_reached = false;
    let error = package_observed(&f.source, &f.repo, &path, None, |at, source| {
        if at == B::BeforeArchiveEntry(1) {
            entry_reached = true;
            fs::remove_file(source)?;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(entry_reached);
    // The callback succeeds; the subsequent actual entry File::open fails.
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(fs::read(&path).unwrap(), b"approved");
    assert!(!fs::read_dir(&f.repo).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-package-")
    }));
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
    assert_eq!(fs::read(&target).unwrap(), b"approved");
    for native_failure in [false, true] {
        let mut reached = false;
        let error = package_observed(&f.source, &f.repo, &target, None, |at, path| {
            let event = if native_failure {
                revayat_scientific::publication::Boundary::BeforeReplace
            } else {
                revayat_scientific::publication::Boundary::AfterCommit
            };
            if at == B::Publication(event) {
                reached = true;
                assert_eq!(path, target);
                if native_failure {
                    let stage = fs::read_dir(&f.repo)?
                        .map(|e| e.unwrap().path())
                        .find(|p| {
                            p.file_name()
                                .unwrap()
                                .to_string_lossy()
                                .starts_with(".revayat-package-")
                        })
                        .unwrap();
                    fs::remove_file(stage)?;
                } else {
                    assert!(zip::ZipArchive::new(fs::File::open(path)?).is_ok());
                    bail!("controlled failure inside actual archive publisher");
                }
            }
            Ok(())
        })
        .unwrap_err();
        assert!(reached);
        if native_failure {
            // Callback succeeds; the actual rename then fails on the missing stage.
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::NotFound
            );
        } else {
            assert!(
                error
                    .to_string()
                    .contains("inside actual archive publisher")
            );
        }
        assert_eq!(fs::read(&target).unwrap(), b"approved");
    }
    assert!(!fs::read_dir(&f.repo).unwrap().any(|entry| {
        let name = entry.unwrap().file_name();
        let name = name.to_string_lossy();
        name.starts_with(".revayat-package-") || name.starts_with(".revayat-publish-")
    }));
}
#[test]
fn test_unreadable_git_index_refuses_before_packaging() {
    let f = Fixture::new();
    let path = f.repo.join("approved.skill");
    fs::write(&path, "approved").unwrap();
    fs::write(f.repo.join(".git/index"), "invalid index data").unwrap();
    f.refused(&path);
}
include!("support/distribution_package_delivery.rs");
