//! Bind checked input snapshots, reserved destinations and exact renderer bytes.
#[path = "build_guard.rs"]
mod guard;
use crate::identity::{file_identity, is_link};
use anyhow::{Context, Result, ensure};
pub use guard::{BuildGuard, DeliveryBoundary};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

pub const MAX_FILES: usize = 8192;
pub const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;

pub fn file_hash(path: &Path) -> Result<String> {
    Ok(file_identity(path, Some(MAX_FILE_BYTES))?.sha256)
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

pub fn validate_assets(source: &Path) -> Result<()> {
    validate_input_assets(&document_inputs(source, &[], None)?)
}
fn validate_input_assets(inputs: &[PathBuf]) -> Result<()> {
    for path in inputs {
        if path.extension().is_some_and(|e| {
            ["png", "jpg", "jpeg", "gif", "webp", "tif", "tiff"]
                .iter()
                .any(|ext| e.eq_ignore_ascii_case(ext))
        }) {
            ensure!(
                !crate::images::inspect(path)?.requires_review,
                "figure requires reviewed light-background original"
            );
        }
    }
    Ok(())
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
    cli_build_with(
        args,
        select_source,
        |selection, working, record| {
            if selection.engine == "tex" {
                crate::tex_container::compile_document(
                    &selection.source,
                    working,
                    selection.container.clone(),
                    Some(record),
                )
            } else {
                crate::render::render_html(
                    &selection.source,
                    working,
                    selection
                        .browser
                        .as_deref()
                        .context("selected browser unavailable")?,
                    Some(record),
                )
            }
        },
        |finding| {
            eprintln!(
                "{}:{}: {} [{}] {}",
                finding.path.display(),
                finding.line,
                finding.level,
                finding.check,
                finding.message
            )
        },
    )
}
/// Shared production build body with per-call external renderer/diagnostic adapters.
pub fn cli_build_with(
    args: &[String],
    select: impl FnOnce(&Path, Option<&str>, Option<&str>) -> Result<Selection>,
    mut render: impl FnMut(&Selection, &Path, &Path) -> Result<()>,
    mut diagnostic: impl FnMut(&crate::lint::Finding),
) -> Result<i32> {
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
    let selection = select(&requested, args.engine.as_deref(), args.browser.as_deref())?;
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
        diagnostic(finding);
    }
    ensure!(
        findings.is_empty(),
        "strict source lint failed; delivery preserved"
    );
    validate_input_assets(&inputs)?;
    BuildGuard::check(&record, None)?;
    render(&selection, &working, &record)?;
    crate::render::validate_pdf(&working)?;
    BuildGuard::check(&record, None)?;
    if args.verify {
        verify_fonts(&working)?;
        let document = crate::pdf::open_pdf(&working, false)?;
        let pages = crate::pdf::geometry(&document)?.len();
        let mut stages = vec![];
        for (index, page) in [1, pages, pages.div_ceil(2)].into_iter().enumerate() {
            let stage = private.path().join(outputs[index + 2].file_name().unwrap());
            crate::pdf::render_page(&working, page, 110, &stage)?;
            stages.push(stage);
        }
        BuildGuard::publish_previews(&record, &stages)?;
        crate::text_order::verify_source(&working, source)?;
    }
    BuildGuard::deliver(&record)?;
    println!("{}", output.display());
    Ok(0)
}

pub fn verify_pdf(pdf: &Path, source: &Path) -> Result<()> {
    verify_fonts(pdf)?;
    crate::text_order::verify_source(pdf, source)
}
fn verify_fonts(pdf: &Path) -> Result<()> {
    crate::render::validate_pdf(pdf)?;
    let mut spec = crate::runtime::CommandSpec::new(crate::runtime::executable("pdffonts")?);
    spec.args.push(pdf.as_os_str().into());
    spec.timeout = std::time::Duration::from_secs(30);
    let output = crate::runtime::run(&spec)?;
    ensure!(output.success(), "embedded font inspection failed");
    verify_font_table(&String::from_utf8(output.stdout)?)
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
