use anyhow::Result;
use revayat_scientific::{
    build::{BuildGuard, document_inputs},
    tex_container::{self as tex, RuntimeConfig, TexBoundary},
};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};
#[path = "tex_backend.rs"]
mod backend;
pub(crate) use backend::Backend;

pub(super) struct Fixture {
    pub(super) _temp: tempfile::TempDir,
    pub(super) root: PathBuf,
    pub(super) source: PathBuf,
    pub(super) child: PathBuf,
    pub(super) image: PathBuf,
    pub(super) font: PathBuf,
    pub(super) output: PathBuf,
}
impl Fixture {
    pub(super) fn new() -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        fs::create_dir(root.join("fonts"))?;
        let f = Self {
            _temp: temp,
            source: root.join("doc.tex"),
            child: root.join("child.tex"),
            image: root.join("image.png"),
            font: root.join("fonts/synthetic.ttf"),
            output: root.join("result.pdf"),
            root,
        };
        fs::write(&f.source,b"\\documentclass{article}\\begin{document}\\input{child}\\includegraphics{image.png}\\end{document}")?;
        fs::write(&f.child, b"original checked revision\n")?;
        fs::write(&f.image, b"synthetic image")?;
        fs::write(&f.font, b"synthetic font")?;
        fs::write(&f.output, b"previous approved output")?;
        Ok(f)
    }
    pub(super) fn originals(&self) -> Vec<PathBuf> {
        vec![
            self.source.clone(),
            self.child.clone(),
            self.image.clone(),
            self.font.clone(),
        ]
    }
    pub(super) fn unchanged(&self) -> Result<()> {
        assert_eq!(fs::read(&self.output)?, b"previous approved output");
        Ok(())
    }
    pub(super) fn assert_copies(&self, directory: &Path) -> Result<()> {
        for original in self.originals() {
            assert_eq!(
                fs::read(
                    directory
                        .join("input")
                        .join(original.strip_prefix(&self.root)?)
                )?,
                fs::read(&original)?
            );
        }
        assert!(!directory.join("input/result.pdf").exists());
        Ok(())
    }
    pub(super) fn clean_staging(&self) -> Result<()> {
        assert!(!fs::read_dir(&self.root)?.any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".revayat-tex-")
        }));
        Ok(())
    }
    pub(super) fn guard(&self) -> Result<PathBuf> {
        let terms = self.root.join("terms.tsv");
        let manifest = self.root.join("manifest.txt");
        fs::write(&terms, b"source\toutput\n")?;
        fs::write(&manifest, b"image.png\n")?;
        let path = self.root.join("build.json");
        BuildGuard::create(
            &path,
            &document_inputs(&self.source, &[terms, manifest], None)?,
            &[self.output.clone(), self.root.join("delivered.pdf")],
        )?;
        Ok(path)
    }
}
pub(super) fn config() -> RuntimeConfig {
    RuntimeConfig {
        base: vec!["docker".into()],
        kind: "docker".into(),
        image: format!("sha256:{}", "a".repeat(64)),
    }
}
pub(super) fn compile(
    f: &Fixture,
    backend: &mut Backend,
    guard: Option<&Path>,
    hook: impl FnMut(TexBoundary, &Path, &Path) -> Result<()>,
) -> Result<()> {
    tex::compile_document_with_lifecycle(
        &f.source,
        &f.output,
        config(),
        guard,
        &mut |args, timeout| backend.execute(args, timeout),
        hook,
        (
            |_: &RuntimeConfig, _: &Path, _: &str| Ok(None),
            |_: Option<&Path>| Ok(()),
            recovery,
        ),
    )
}
pub(super) fn recovery(directory: &Path, run: &str) -> Result<()> {
    fs::write(
        directory.join("recovery.json"),
        serde_json::to_vec(&json!({"run_id":run,"status":"cleanup_not_verified"}))?,
    )?;
    Ok(())
}
