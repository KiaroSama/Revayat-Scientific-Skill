//! Bind checked input snapshots, reserved destinations and exact renderer bytes.
use crate::{
    identity::{file_identity, is_link, path_object_id},
    publication::{publish_files, validate_destination},
};
use anyhow::{Context, Result, ensure};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const MAX_FILES: usize = 8192;
pub const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;

pub fn file_hash(path: &Path) -> Result<String> {
    Ok(file_identity(path, Some(MAX_FILE_BYTES))?.sha256)
}

fn unique_map<'de, D: de::Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<PathBuf, String>, D::Error> {
    struct Unique;
    impl<'de> Visitor<'de> for Unique {
        type Value = BTreeMap<PathBuf, String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a bounded unique fingerprint map")
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((path, digest)) = map.next_entry::<PathBuf, String>()? {
                if result.len() >= MAX_FILES || result.insert(path, digest).is_some() {
                    return Err(de::Error::custom(
                        "duplicate or excessive build fingerprint",
                    ));
                }
            }
            Ok(result)
        }
    }
    d.deserialize_map(Unique)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildGuard {
    pub schema: u8,
    #[serde(deserialize_with = "unique_map")]
    pub inputs: BTreeMap<PathBuf, String>,
    pub outputs: Vec<PathBuf>,
    #[serde(deserialize_with = "unique_map")]
    pub rendered: BTreeMap<PathBuf, String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryBoundary {
    BeforeCopy,
    AfterCopy,
    BeforePublication,
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn destinations(outputs: &[PathBuf], sources: &[PathBuf]) -> Result<()> {
    ensure!(
        (2..=5).contains(&outputs.len()),
        "build needs two PDF outputs and at most three previews"
    );
    let mut keys = BTreeSet::new();
    let mut ids = Vec::new();
    let mut preview_names = BTreeSet::new();
    for (index, path) in outputs.iter().enumerate() {
        ensure!(path.is_absolute(), "build output paths must be absolute");
        let selected = validate_destination(path, sources)?;
        ensure!(
            keys.insert(selected.to_string_lossy().to_lowercase()),
            "build output paths collide"
        );
        if selected.try_exists()? {
            let id = path_object_id(&selected)?;
            ensure!(!ids.contains(&id), "build output paths alias each other");
            ids.push(id);
        }
        if index >= 2 {
            ensure!(
                preview_names.insert(
                    path.file_name()
                        .context("preview has no basename")?
                        .to_string_lossy()
                        .to_lowercase()
                ),
                "build preview basenames must be unique"
            );
        }
    }
    Ok(())
}

impl BuildGuard {
    pub fn create(path: &Path, inputs: &[PathBuf], outputs: &[PathBuf]) -> Result<Self> {
        ensure!(
            !inputs.is_empty() && inputs.len() <= MAX_FILES,
            "invalid bounded build input count"
        );
        let mut snapshots = BTreeMap::new();
        for input in inputs {
            let input = input.canonicalize()?;
            snapshots.insert(input.clone(), file_hash(&input)?);
        }
        let outputs = outputs
            .iter()
            .map(std::path::absolute)
            .collect::<std::io::Result<Vec<_>>>()?;
        let guard = Self {
            schema: 1,
            inputs: snapshots,
            outputs,
            rendered: BTreeMap::new(),
        };
        guard.validate(path)?;
        guard.save(path, true)?;
        Self::check(path, None)
    }
    pub fn load(path: &Path) -> Result<Self> {
        validate_destination(path, &[])?;
        ensure!(
            fs::metadata(path)?.len() <= MAX_RECORD_BYTES,
            "build record exceeds 4 MiB"
        );
        let raw = fs::read(path)?;
        ensure!(
            raw.len() as u64 <= MAX_RECORD_BYTES,
            "build record grew beyond 4 MiB"
        );
        let guard: Self = serde_json::from_slice(&raw).context("invalid build record")?;
        guard.validate(path)?;
        Ok(guard)
    }
    pub fn validate(&self, path: &Path) -> Result<()> {
        ensure!(
            self.schema == 1 && !self.inputs.is_empty() && self.inputs.len() <= MAX_FILES,
            "invalid build record schema"
        );
        ensure!(self.rendered.len() <= 1, "invalid rendered artifact count");
        for (name, digest) in self.inputs.iter().chain(&self.rendered) {
            ensure!(
                name.is_absolute() && valid_hash(digest),
                "invalid build path or fingerprint"
            );
        }
        let mut protected = vec![std::path::absolute(path)?];
        protected.extend(self.inputs.keys().cloned());
        destinations(&self.outputs, &protected)?;
        ensure!(
            self.rendered
                .keys()
                .all(|p| Some(p) == self.outputs.first()),
            "invalid rendered artifact identity"
        );
        Ok(())
    }
    fn save(&self, path: &Path, new: bool) -> Result<()> {
        validate_destination(path, &[])?;
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "build record exceeds 4 MiB"
        );
        if new {
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            return Ok(());
        }
        let pending = path.with_file_name(format!(
            "{}.pending",
            path.file_name()
                .context("guard filename missing")?
                .to_string_lossy()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&pending, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&pending);
        }
        result
    }
    pub fn check(path: &Path, resources: Option<&BTreeMap<PathBuf, String>>) -> Result<Self> {
        let mut guard = Self::load(path)?;
        let before = guard.inputs.len();
        if let Some(resources) = resources {
            ensure!(resources.len() <= MAX_FILES, "invalid resource map");
            for (name, digest) in resources {
                ensure!(
                    name.is_absolute() && valid_hash(digest),
                    "invalid resource identity"
                );
                if let Some(previous) = guard.inputs.get(name) {
                    ensure!(
                        previous == digest,
                        "renderer consumed a different checked input revision"
                    );
                } else {
                    guard.inputs.insert(name.clone(), digest.clone());
                }
            }
        }
        guard.validate(path)?;
        for (name, digest) in guard.inputs.iter().chain(&guard.rendered) {
            ensure!(
                file_hash(name)? == *digest,
                "checked build input or rendered artifact changed; rerun all build checks"
            );
        }
        if guard.inputs.len() != before {
            guard.save(path, false)?;
        }
        Ok(guard)
    }
    pub fn seal(path: &Path, output: &Path, digest: &str) -> Result<()> {
        let mut guard = Self::check(path, None)?;
        let output = std::path::absolute(output)?;
        ensure!(
            Some(&output) == guard.outputs.first() && valid_hash(digest),
            "renderer output differs from planned working PDF"
        );
        ensure!(
            file_hash(&output)? == digest,
            "working PDF changed during renderer publication"
        );
        guard.rendered.insert(output, digest.into());
        guard.save(path, false)?;
        Self::check(path, None)?;
        Ok(())
    }
    pub fn protected(&self, path: &Path) -> Vec<PathBuf> {
        let mut result = vec![path.to_path_buf()];
        result.extend(self.inputs.keys().cloned());
        result
    }
    pub fn deliver(path: &Path) -> Result<()> {
        Self::deliver_observed(path, |_, _, _| Ok(()))
    }
    pub fn deliver_observed(
        path: &Path,
        mut boundary: impl FnMut(DeliveryBoundary, &Path, &Path) -> Result<()>,
    ) -> Result<()> {
        let guard = Self::check(path, None)?;
        let working = &guard.outputs[0];
        let target = &guard.outputs[1];
        let digest = file_hash(working)?;
        ensure!(
            guard.rendered.get(working) == Some(&digest),
            "working PDF has not been sealed by renderer"
        );
        fs::create_dir_all(target.parent().context("delivery parent missing")?)?;
        let directory = tempfile::Builder::new()
            .prefix(".revayat-delivery-")
            .tempdir_in(target.parent().unwrap())?;
        let stage = directory.path().join("document.pdf");
        boundary(DeliveryBoundary::BeforeCopy, working, &stage)?;
        fs::copy(working, &stage)?;
        boundary(DeliveryBoundary::AfterCopy, working, &stage)?;
        ensure!(
            file_hash(working)? == digest && file_hash(&stage)? == digest,
            "PDF changed during delivery staging"
        );
        Self::check(path, None)?;
        boundary(DeliveryBoundary::BeforePublication, working, &stage)?;
        ensure!(
            file_hash(&stage)? == digest,
            "delivery staging changed before publication"
        );
        publish_files(
            &[(stage, target.clone())],
            &guard.protected(path),
            Some(MAX_FILE_BYTES),
        )?;
        ensure!(
            file_hash(target)? == digest,
            "published PDF differs from sealed renderer output"
        );
        Ok(())
    }
    pub fn publish_previews(path: &Path, staged: &[PathBuf]) -> Result<()> {
        Self::publish_previews_observed(path, staged, |_, _| Ok(()))
    }
    pub fn publish_previews_observed(
        path: &Path,
        staged: &[PathBuf],
        boundary: impl FnMut(crate::publication::Boundary, &Path) -> Result<()>,
    ) -> Result<()> {
        let guard = Self::check(path, None)?;
        ensure!(
            !guard.rendered.is_empty(),
            "preview publication requires a sealed rendered PDF"
        );
        ensure!(
            staged.len() == guard.outputs.len() - 2 && !staged.is_empty(),
            "preview batch must contain every planned role"
        );
        let mut entries = vec![];
        for (input, output) in staged.iter().zip(&guard.outputs[2..]) {
            ensure!(
                std::path::absolute(input)?.parent() == std::path::absolute(path)?.parent()
                    && input.file_name() == output.file_name(),
                "unexpected or outside verification sample"
            );
            ensure!(
                !is_link(input)? && input.is_file(),
                "preview staging must be a regular file"
            );
            let bytes = fs::read(input)?;
            ensure!(
                bytes.len() <= 128 * 1024 * 1024,
                "preview exceeds size limit"
            );
            let image = image::load_from_memory_with_format(&bytes, image::ImageFormat::Png)
                .context("preview is not a complete PNG")?;
            ensure!(
                image.width() > 0
                    && image.height() > 0
                    && u64::from(image.width()) * u64::from(image.height()) <= 50_000_000,
                "empty or oversized preview"
            );
            entries.push((input.clone(), output.clone()));
        }
        crate::publication::publish_observed(
            &entries,
            &guard.protected(path),
            Some(128 * 1024 * 1024),
            boundary,
        )
    }
}

pub fn document_inputs(
    source: &Path,
    sidecars: &[PathBuf],
    requested: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let source = source.canonicalize()?;
    let mut inputs = vec![];
    if source
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("tex"))
    {
        let model = crate::source::TexSource::load(&source)?;
        inputs.extend(model.closure.sources.clone());
        for (_, reference) in model.image_references() {
            inputs.push(resolve_asset(&source, &reference)?);
        }
    } else {
        inputs.push(source.clone());
        let html = crate::html::ParsedHtml::parse(&fs::read_to_string(&source)?)?;
        for (_, reference) in html.image_references() {
            if !reference.starts_with("data:") {
                inputs.push(resolve_asset(&source, &reference)?);
            }
        }
    }
    inputs.extend(
        sidecars
            .iter()
            .map(|p| p.canonicalize())
            .collect::<std::io::Result<Vec<_>>>()?,
    );
    if let Some(path) = requested {
        inputs.push(path.canonicalize()?);
    }
    inputs.sort();
    inputs.dedup();
    ensure!(inputs.len() <= MAX_FILES, "build input count exceeds 8192");
    Ok(inputs)
}

pub fn resolve_asset(source: &Path, reference: &str) -> Result<PathBuf> {
    let root = source
        .parent()
        .context("source root unavailable")?
        .canonicalize()?;
    let selected = crate::lint::resolve_asset(&root, reference)?;
    for path in selected.ancestors() {
        ensure!(!is_link(path)?, "asset path contains links");
        if path == root {
            break;
        }
    }
    ensure!(selected.starts_with(root), "asset leaves approved job root");
    Ok(selected)
}

#[derive(Clone, Debug)]
pub struct Selection {
    pub source: PathBuf,
    pub engine: String,
    pub browser: Option<PathBuf>,
    pub container: Option<crate::tex_container::RuntimeConfig>,
}

pub fn select_source_with_available(
    source: &Path,
    requested: Option<&str>,
    available: &BTreeSet<String>,
) -> Result<(PathBuf, String)> {
    let mut source = source.canonicalize()?;
    let tex = source
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("tex"));
    ensure!(
        tex || source
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm")),
        "expected existing .tex or .html source"
    );
    if let Some(engine) = requested {
        ensure!(
            engine == "tex" || engine == "chromium",
            "native PDF engine must be tex or chromium"
        );
        ensure!(
            available.contains(engine),
            "explicit PDF engine unavailable: {engine}"
        );
    }
    ensure!(
        tex || requested != Some("tex"),
        "tex engine requires TeX source"
    );
    if tex {
        if requested == Some("tex") || (requested.is_none() && available.contains("tex")) {
            return Ok((source, "tex".into()));
        }
        source = source.with_extension("html");
        ensure!(
            source.is_file(),
            "HTML rendering requires existing sibling .html source"
        );
    }
    let engine = requested
        .or_else(|| available.contains("chromium").then_some("chromium"))
        .context("no compatible PDF renderer available")?;
    Ok((source, engine.into()))
}

/// Resolve readiness only for the explicitly requested backend. Auto selection
/// falls back on absence, while a selected backend's render failure is final.
pub fn select_source(
    source: &Path,
    engine: Option<&str>,
    browser: Option<&str>,
) -> Result<Selection> {
    let source = source.canonicalize()?;
    let tex = source
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("tex"));
    ensure!(
        tex || source
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm")),
        "expected existing .tex or .html source"
    );
    if let Some(engine) = engine {
        ensure!(
            engine == "tex" || engine == "chromium",
            "native PDF engine must be tex or chromium"
        );
    }
    if engine == Some("tex") {
        ensure!(tex, "tex engine requires TeX source");
        let config = crate::tex_container::runtime_config()?;
        let (source, engine) =
            select_source_with_available(&source, engine, &BTreeSet::from(["tex".into()]))?;
        return Ok(Selection {
            source,
            engine,
            browser: None,
            container: Some(config),
        });
    }
    if tex
        && engine.is_none()
        && let Ok(config) = crate::tex_container::runtime_config()
    {
        let (source, engine) =
            select_source_with_available(&source, engine, &BTreeSet::from(["tex".into()]))?;
        return Ok(Selection {
            source,
            engine,
            browser: None,
            container: Some(config),
        });
    }
    let browser = crate::render::discover_browser(browser)?;
    let (source, engine) =
        select_source_with_available(&source, engine, &BTreeSet::from(["chromium".into()]))?;
    Ok(Selection {
        source,
        engine,
        browser: Some(browser),
        container: None,
    })
}

#[derive(clap::Parser)]
#[command(
    name = "build",
    about = "Check source snapshots, render privately and publish a verified scientific PDF"
)]
struct BuildArgs {
    source: PathBuf,
    slug: Option<String>,
    #[arg(long)]
    verify: bool,
    #[arg(long)]
    engine: Option<String>,
    #[arg(long)]
    browser: Option<String>,
    #[arg(long, default_value = "system-docs")]
    level: String,
    #[arg(long)]
    terms: Option<PathBuf>,
    #[arg(long)]
    manifest: Option<PathBuf>,
    #[arg(long)]
    output_dir: Option<PathBuf>,
    #[arg(long)]
    out: Option<PathBuf>,
}

pub fn cli_build(args: &[String]) -> Result<i32> {
    use clap::Parser;
    let args =
        BuildArgs::try_parse_from(std::iter::once("build".to_owned()).chain(args.iter().cloned()))?;
    let requested = args.source.canonicalize()?;
    let root = requested.parent().context("source has no parent")?;
    let slug = args.slug.unwrap_or_else(|| {
        requested
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    });
    ensure!(
        !slug.is_empty()
            && slug != "."
            && slug != ".."
            && !slug.contains(['/', '\\', '\0', '\r', '\n']),
        "slug must be a filename"
    );
    let terms = args.terms.unwrap_or_else(|| root.join("terms.tsv"));
    let manifest = args.manifest.unwrap_or_else(|| root.join("manifest.txt"));
    ensure!(
        terms.is_file() && manifest.is_file(),
        "build requires checked terms.tsv and manifest.txt sidecars"
    );
    let selection = select_source(&requested, args.engine.as_deref(), args.browser.as_deref())?;
    let source = &selection.source;
    let working = requested.with_extension("pdf");
    let output = if let Some(output) = args.out {
        std::path::absolute(output)?
    } else {
        let directory = if let Some(directory) = args.output_dir {
            directory
        } else {
            PathBuf::from(
                std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                    .context("home directory unavailable; specify --output-dir")?,
            )
            .join("Documents/books")
        };
        std::path::absolute(directory.join(format!("{slug}.pdf")))?
    };
    let private = tempfile::Builder::new()
        .prefix(".revayat-build-")
        .tempdir_in(root)?;
    let record = private.path().join("build.json");
    let mut outputs = vec![working.clone(), output.clone()];
    if args.verify {
        for role in ["first", "last", "mid"] {
            outputs.push(root.join(format!("verify-{slug}-{role}.png")));
        }
    }
    let inputs = document_inputs(source, &[terms.clone(), manifest.clone()], Some(&requested))?;
    BuildGuard::create(&record, &inputs, &outputs)?;
    let options = crate::lint::LintOptions {
        level: args.level,
        terms: Some(terms),
        manifest: Some(manifest),
        strict: true,
        ..Default::default()
    };
    let findings = crate::lint::lint_file(source, &options)?;
    for finding in &findings {
        eprintln!(
            "{}:{}: {} [{}] {}",
            finding.path.display(),
            finding.line,
            finding.level,
            finding.check,
            finding.message
        );
    }
    ensure!(
        findings.is_empty(),
        "strict source lint failed; delivery preserved"
    );
    for path in &inputs {
        if path.extension().is_some_and(|e| {
            ["png", "jpg", "jpeg", "gif", "webp", "tif", "tiff"]
                .iter()
                .any(|ext| e.eq_ignore_ascii_case(ext))
        }) {
            let inspection = crate::images::inspect(path)?;
            ensure!(
                !inspection.requires_review,
                "figure requires reviewed light-background original"
            );
        }
    }
    BuildGuard::check(&record, None)?;
    if selection.engine == "tex" {
        crate::tex_container::compile_document(
            source,
            &working,
            selection.container,
            Some(&record),
        )?;
    } else {
        crate::render::render_html(
            source,
            &working,
            selection
                .browser
                .as_deref()
                .context("selected browser unavailable")?,
            Some(&record),
        )?;
    }
    crate::render::validate_pdf(&working)?;
    BuildGuard::check(&record, None)?;
    if args.verify {
        verify_pdf(&working, source)?;
        let document = crate::pdf::open_pdf(&working, false)?;
        let pages = crate::pdf::geometry(&document)?.len();
        let mut stages = vec![];
        for (index, page) in [1, pages, pages.div_ceil(2)].into_iter().enumerate() {
            let stage = private.path().join(outputs[index + 2].file_name().unwrap());
            crate::pdf::render_page(&working, page, 110, &stage)?;
            stages.push(stage);
        }
        BuildGuard::publish_previews(&record, &stages)?;
    }
    BuildGuard::deliver(&record)?;
    println!("{}", output.display());
    Ok(0)
}

pub fn verify_pdf(pdf: &Path, source: &Path) -> Result<()> {
    crate::render::validate_pdf(pdf)?;
    let mut spec = crate::runtime::CommandSpec::new(crate::runtime::executable("pdffonts")?);
    spec.args.push(pdf.as_os_str().into());
    spec.timeout = std::time::Duration::from_secs(30);
    let output = crate::runtime::run(&spec)?;
    ensure!(output.success(), "embedded font inspection failed");
    verify_font_table(&String::from_utf8(output.stdout)?)?;
    crate::text_order::verify_source(pdf, source)?;
    Ok(())
}
pub fn verify_font_table(text: &str) -> Result<()> {
    let rows = text
        .lines()
        .skip(2)
        .filter(|l| !l.trim().is_empty())
        .collect::<Vec<_>>();
    ensure!(
        !rows.is_empty()
            && rows.iter().all(|row| {
                let fields = row.split_whitespace().collect::<Vec<_>>();
                fields.len() >= 6 && fields[fields.len() - 5] == "yes"
            }),
        "PDF fonts are missing or not embedded"
    );
    Ok(())
}

pub fn cli_doctor(args: &[String]) -> Result<i32> {
    ensure!(args.is_empty(), "doctor takes no arguments");
    let browser = crate::render::discover_browser(None);
    let container = crate::tex_container::runtime_config();
    let browser_reason = browser.as_ref().err().map(ToString::to_string);
    let container_reason = container.as_ref().err().map(ToString::to_string);
    let tools = ["pdfinfo", "pdffonts", "pdftoppm", "pdftotext", "tesseract"]
        .into_iter()
        .map(|name| (name, crate::runtime::executable(name).is_ok()))
        .collect::<BTreeMap<_, _>>();
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"runtime":"rust","version":env!("CARGO_PKG_VERSION"),"chromium":{"available":browser.is_ok(),"path":browser.ok(),"reason":browser_reason},"tex":{"available":container.is_ok(),"runtime":container.ok(),"reason":container_reason},"tools":tools})
        )?
    );
    Ok(0)
}
