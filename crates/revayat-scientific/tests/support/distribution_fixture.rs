#![allow(dead_code)]
use anyhow::Result;
use revayat_scientific::{
    distribution::{self as d, InstallBoundary as B, NAME, Payload},
    distribution_paths as paths,
};
use std::{
    fs,
    path::{Path, PathBuf},
};
pub const HEADER: &str = "---\nname: revayat-scientific\ndescription: Fixture\n---\n";
pub struct Fixture {
    _temp: tempfile::TempDir,
    pub root: PathBuf,
    pub repo: PathBuf,
    pub source: PathBuf,
    pub first: PathBuf,
    pub second: PathBuf,
}
impl Fixture {
    pub fn new() -> Self {
        let scratch = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".scratch");
        fs::create_dir_all(&scratch).unwrap();
        let temp = tempfile::tempdir_in(scratch).unwrap();
        let root = temp.path().to_owned();
        let repo = root.join("repo");
        let source = repo.join("skills/revayat-scientific");
        fs::create_dir_all(source.join("references")).unwrap();
        fs::write(source.join("SKILL.md"), format!("{HEADER}candidate")).unwrap();
        fs::write(source.join("LICENSE"), "GPL-3.0-or-later").unwrap();
        fs::write(source.join("references/helper.md"), "retained reference").unwrap();
        Self {
            _temp: temp,
            first: root.join("project/.a/skills").join(NAME),
            second: root.join("project/.b/skills").join(NAME),
            root,
            repo,
            source,
        }
    }
    pub fn payload(&self) -> Payload {
        Payload::collect(&self.source, None).unwrap()
    }
    pub fn old(&self, path: &Path, edition: &str) -> Vec<u8> {
        fs::create_dir_all(path).unwrap();
        let data = format!("{HEADER}{edition}").into_bytes();
        fs::write(path.join("SKILL.md"), &data).unwrap();
        fs::write(path.join("retained"), edition).unwrap();
        data
    }
    pub fn install(&self, targets: &[PathBuf], force: bool) -> Result<Vec<PathBuf>> {
        d::install_targets(targets, force, &self.source, &self.repo, &self.payload())
    }
    pub fn observed(
        &self,
        targets: &[PathBuf],
        force: bool,
        hook: impl FnMut(B, &Path) -> Result<()>,
    ) -> Result<Vec<PathBuf>> {
        d::install_observed(
            targets,
            force,
            &self.source,
            &self.repo,
            &self.payload(),
            hook,
        )
    }
    pub fn assert_old(&self, path: &Path, bytes: &[u8]) {
        assert_eq!(fs::read(path.join("SKILL.md")).unwrap(), bytes);
    }
    pub fn journals(&self) -> Vec<PathBuf> {
        fn visit(p: &Path, out: &mut Vec<PathBuf>) {
            if p.is_dir() {
                for e in fs::read_dir(p).unwrap() {
                    let p = e.unwrap().path();
                    if p.file_name().is_some_and(|n| n == "recovery.json") {
                        out.push(p);
                    } else if p.is_dir() {
                        visit(&p, out);
                    }
                }
            }
        }
        let mut out = vec![];
        visit(&self.root, &mut out);
        out
    }
    pub fn lock(&self, path: &Path) -> PathBuf {
        use sha2::{Digest, Sha256};
        let hash = format!("{:x}", Sha256::digest(paths::key(path).as_bytes()));
        path.parent()
            .unwrap()
            .join(format!(".revayat-install-{}.lock", &hash[..24]))
    }
}
#[cfg(unix)]
pub fn link(source: &Path, dest: &Path) {
    std::os::unix::fs::symlink(source, dest).unwrap();
}
#[cfg(windows)]
#[path = "windows_junction.rs"]
mod windows_junction;
#[cfg(windows)]
pub fn link(source: &Path, dest: &Path) {
    if source.is_dir() {
        windows_junction::create(dest, source).unwrap();
    } else {
        fs::hard_link(source, dest).unwrap();
    }
}
