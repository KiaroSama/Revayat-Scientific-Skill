use anyhow::{Result, bail};
use revayat_scientific::{
    build::{BuildGuard, document_inputs},
    tex_container::{self as tex, RuntimeConfig, TexBoundary},
};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};
pub(super) fn pdf(path: &Path) -> Result<()> {
    use lopdf::{Document, Object, Stream, dictionary};
    let mut d = Document::with_version("1.7");
    let pages = d.new_object_id();
    let font =
        d.add_object(dictionary! {"Type"=>"Font","Subtype"=>"Type1","BaseFont"=>"Helvetica"});
    let stream = d.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 20 250 Td (Staged revision) Tj ET".to_vec(),
    ));
    let page=d.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"MediaBox"=>vec![Object::from(0),Object::from(0),Object::from(250),Object::from(360)],"Contents"=>stream,"Resources"=>dictionary!{"Font"=>dictionary!{"F1"=>font}}});
    d.objects.insert(
        pages,
        dictionary! {"Type"=>"Pages","Kids"=>vec![Object::Reference(page)],"Count"=>1}.into(),
    );
    let catalog = d.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
    d.trailer.set("Root", catalog);
    d.save(path)?;
    Ok(())
}
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
pub(super) struct Backend {
    pub(super) alive: bool,
    pub(super) run: String,
    pub(super) calls: usize,
    pub(super) cleanup_calls: usize,
    pub(super) code: i32,
    pub(super) invalid: bool,
    pub(super) cleanup_fail: bool,
    pub(super) timeout: bool,
}
impl Backend {
    pub(super) fn new() -> Self {
        Self {
            alive: false,
            run: String::new(),
            calls: 0,
            cleanup_calls: 0,
            code: 0,
            invalid: false,
            cleanup_fail: false,
            timeout: false,
        }
    }
    pub(super) fn execute(&mut self, args: &[String], _: u64) -> Result<(i32, String)> {
        if args.iter().any(|s| s == "run") {
            self.calls += 1;
            self.alive = true;
            self.run = args[args.iter().position(|s| s == "--name").unwrap() + 1]
                .trim_start_matches("revayat-tex-")
                .into();
            let directory =
                Path::new(&args[args.iter().position(|s| s == "--cidfile").unwrap() + 1])
                    .parent()
                    .unwrap();
            fs::write(directory.join("container.cid"), "a".repeat(64))?;
            if self.timeout {
                return Err(revayat_scientific::runtime::DeadlineExceeded {
                    idle: false,
                    limit: std::time::Duration::from_secs(150),
                }
                .into());
            }
            let output = directory.join("output/document.pdf");
            if self.invalid {
                fs::write(output, b"%PDF-1.7\ntruncated")?;
            } else {
                pdf(&output)?;
            }
            if self.code != 0 {
                fs::write(
                    directory.join("output/console-pass-1.log"),
                    b"Undefined control sequence\nl.9 PRIVATE_MANUSCRIPT_LINE",
                )?;
            }
            return Ok((self.code, String::new()));
        }
        if args.iter().any(|s| s == "ps") {
            if self.cleanup_fail {
                bail!("daemon unavailable");
            }
            return Ok((
                0,
                if self.alive {
                    "a".repeat(64)
                } else {
                    String::new()
                },
            ));
        }
        if args.iter().any(|s| s == "inspect") {
            return Ok((0,json!([{"Id":"a".repeat(64),"Name":format!("/revayat-tex-{}",self.run),"Config":{"Labels":{tex::RUN_LABEL:self.run}}}]).to_string()));
        }
        if args.iter().any(|s| s == "rm") {
            self.cleanup_calls += 1;
            self.alive = false;
            return Ok((0, String::new()));
        }
        bail!("unexpected fake runtime query")
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
