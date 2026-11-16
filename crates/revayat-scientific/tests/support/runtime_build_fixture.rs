use anyhow::Result;
use std::{
    fs,
    path::{Path, PathBuf},
};
pub(super) fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}
pub(super) struct Fixture {
    pub(super) _temp: tempfile::TempDir,
    pub(super) root: PathBuf,
    pub(super) source: PathBuf,
    pub(super) output: PathBuf,
}
impl Fixture {
    pub(super) fn new() -> Result<Self> {
        let scratch = repo().join(".scratch");
        fs::create_dir_all(&scratch)?;
        let temp = tempfile::Builder::new()
            .prefix("native-build-فارسی-")
            .tempdir_in(scratch)?;
        let root = temp.path().canonicalize()?;
        let source = root.join("doc.html");
        fs::write(
            &source,
            fs::read(repo().join("tests/fixtures/build-smoke.html"))?,
        )?;
        fs::copy(
            repo().join("tests/fixtures/terms-empty.tsv"),
            root.join("terms.tsv"),
        )?;
        fs::write(root.join("manifest.txt"), b"")?;
        fs::create_dir(root.join("delivered"))?;
        let output = root.join("delivered/article.pdf");
        fs::write(&output, b"previous approved delivery")?;
        Ok(Self {
            _temp: temp,
            root,
            source,
            output,
        })
    }
    pub(super) fn args(&self, verify: bool) -> Vec<String> {
        let mut args = vec![
            self.source.display().to_string(),
            "article".into(),
            "--engine".into(),
            "chromium".into(),
            "--output-dir".into(),
            self.root.join("delivered").display().to_string(),
        ];
        if verify {
            args.push("--verify".into());
        }
        args
    }
    pub(super) fn fonts(&self) -> Result<()> {
        let bundled = repo().join("fonts");
        let destination = self.root.join("fonts");
        if revayat_scientific::fonts::validate_bundle(&bundled, "33.003", true).is_ok() {
            fs::create_dir(&destination)?;
            for name in [
                "Vazirmatn-Regular.ttf",
                "Vazirmatn-Bold.ttf",
                "OFL.txt",
                "font-provenance.json",
            ] {
                fs::copy(bundled.join(name), destination.join(name))?;
            }
        } else {
            let cache = repo().join(".scratch/native-font-cache");
            revayat_scientific::fonts::fetch_with_cache(&destination, "33.003", false, &cache)?;
        }
        let html=fs::read_to_string(&self.source)?.replace("font-family: Tahoma, sans-serif", "font-family: Vazirmatn, sans-serif").replace("<style>","<style>\n@font-face{font-family:Vazirmatn;src:url('fonts/Vazirmatn-Regular.ttf');font-weight:400}\n@font-face{font-family:Vazirmatn;src:url('fonts/Vazirmatn-Bold.ttf');font-weight:700}\n");
        fs::write(&self.source, html)?;
        Ok(())
    }
    pub(super) fn unchanged(&self) -> Result<()> {
        assert_eq!(fs::read(&self.output)?, b"previous approved delivery");
        self.clean()
    }
    pub(super) fn clean(&self) -> Result<()> {
        for directory in [&self.root, self.output.parent().unwrap()] {
            assert!(!fs::read_dir(directory)?.any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".revayat-")
            }));
        }
        Ok(())
    }
    pub(super) fn samples(&self) -> Vec<PathBuf> {
        ["first", "last", "mid"]
            .into_iter()
            .map(|role| self.root.join(format!("verify-article-{role}.png")))
            .collect()
    }
    pub(super) fn asset(&self, name: &str, css: bool) -> Result<PathBuf> {
        let path = self.root.join(name);
        image::RgbImage::from_pixel(80, 80, image::Rgb([220, 240, 250])).save(&path)?;
        let html = fs::read_to_string(&self.source)?;
        let html = if css {
            fs::write(
                self.root.join("local.css"),
                format!("body{{background-image:url('{name}')}}"),
            )?;
            html.replace(
                "</head>",
                "<link rel=\"stylesheet\" href=\"local.css\"></head>",
            )
        } else {
            fs::write(self.root.join("manifest.txt"), format!("{name}\n"))?;
            html.replace(
                "<body>",
                &format!("<body><img dir=\"ltr\" src=\"{name}\" alt=\"شکل پژوهش\">"),
            )
        };
        fs::write(&self.source, html)?;
        Ok(path)
    }
    pub(super) fn snapshots(&self) -> Result<Vec<(PathBuf, Vec<u8>)>> {
        let mut paths = vec![
            self.source.clone(),
            self.root.join("terms.tsv"),
            self.root.join("manifest.txt"),
        ];
        for name in [
            "local.css",
            "figure.png",
            "verify-article-first.png",
            "verify-article-last.png",
            "verify-article-mid.png",
        ] {
            let path = self.root.join(name);
            if path.is_file() {
                paths.push(path);
            }
        }
        paths
            .into_iter()
            .map(|p| Ok((p.clone(), fs::read(p)?)))
            .collect()
    }
    pub(super) fn preserved(&self, snapshots: &[(PathBuf, Vec<u8>)]) -> Result<()> {
        for (path, bytes) in snapshots {
            assert_eq!(fs::read(path)?, *bytes, "{}", path.display());
        }
        self.clean()
    }
    pub(super) fn run(
        &self,
        args: Vec<std::ffi::OsString>,
        timeout: u64,
        env: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    ) -> Result<revayat_scientific::runtime::CommandOutput> {
        let mut spec =
            revayat_scientific::runtime::CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific"));
        spec.args = args;
        spec.cwd = Some(self.root.clone());
        spec.timeout = std::time::Duration::from_secs(timeout);
        spec.env.extend(env);
        spec.env.insert(
            "REVAYAT_LOG_DIR".into(),
            self.root.join("logs").into_os_string(),
        );
        revayat_scientific::runtime::run_supervised(&spec)
    }
}
