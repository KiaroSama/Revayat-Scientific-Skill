//! Real browser/TeX/container gates are explicitly ignored during the portable
//! suite and explicitly required by their native CI jobs; absence never passes.
use anyhow::{Context, Result, bail};
use revayat_scientific::{
    build, render,
    runtime::{self, CommandSpec},
    tex_container as tex,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
mod runtime_support;
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    source: PathBuf,
    output: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self> {
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
    fn args(&self, verify: bool) -> Vec<String> {
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
    fn fonts(&self) -> Result<()> {
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
    fn unchanged(&self) -> Result<()> {
        assert_eq!(fs::read(&self.output)?, b"previous approved delivery");
        Ok(())
    }
    fn samples(&self) -> Vec<PathBuf> {
        ["first", "last", "mid"]
            .into_iter()
            .map(|role| self.root.join(format!("verify-article-{role}.png")))
            .collect()
    }
    fn asset(&self, name: &str, css: bool) -> Result<PathBuf> {
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
}
#[test]
fn test_each_source_preview_collision_is_rejected_before_any_output_changes() -> Result<()> {
    for role in ["first", "last", "mid"] {
        let f = Fixture::new()?;
        let asset = f.asset(&format!("verify-article-{role}.png"), false)?;
        let before = fs::read(&asset)?;
        assert!(build::cli_build(&f.args(true)).is_err());
        assert_eq!(fs::read(asset)?, before);
        f.unchanged()?;
        assert!(!f.source.with_extension("pdf").exists());
    }
    Ok(())
}
#[test]
fn test_terms_and_manifest_with_pdf_suffix_are_never_delivery_targets() -> Result<()> {
    for field in ["terms", "manifest"] {
        let f = Fixture::new()?;
        let mut args = f.args(false);
        args.extend([format!("--{field}"), f.output.display().to_string()]);
        assert!(build::cli_build(&args).is_err());
        f.unchanged()?;
    }
    Ok(())
}
#[test]
#[ignore = "requires sandboxed Chromium and Poppler"]
fn test_css_only_preview_resource_is_preserved_and_cannot_replace_working_pdf() -> Result<()> {
    let f = Fixture::new()?;
    f.fonts()?;
    let asset = f.asset("verify-article-first.png", true)?;
    let before = fs::read(&asset)?;
    let working = f.source.with_extension("pdf");
    fs::write(&working, b"previous working PDF")?;
    assert!(build::cli_build(&f.args(true)).is_err());
    assert_eq!(fs::read(asset)?, before);
    assert_eq!(fs::read(working)?, b"previous working PDF");
    f.unchanged()
}
#[test]
#[ignore = "requires sandboxed Chromium"]
fn test_noverify_does_not_reserve_unused_preview_paths() -> Result<()> {
    let f = Fixture::new()?;
    f.fonts()?;
    let asset = f.asset("verify-article-first.png", false)?;
    let before = fs::read(&asset)?;
    assert_eq!(build::cli_build(&f.args(false))?, 0);
    assert_eq!(fs::read(asset)?, before);
    assert_eq!(
        fs::read(&f.output)?,
        fs::read(f.source.with_extension("pdf"))?
    );
    assert!(!f.samples()[1].exists());
    Ok(())
}
#[test]
#[ignore = "requires sandboxed Chromium, embedded static fonts and Poppler"]
fn test_successful_three_to_one_page_rebuild_refreshes_every_preview_role() -> Result<()> {
    let f = Fixture::new()?;
    f.fonts()?;
    f.asset("figure.png", false)?;
    build::cli_build(&f.args(true))?;
    assert_eq!(
        revayat_scientific::pdf::geometry(&revayat_scientific::pdf::open_pdf(&f.output, false)?)?
            .len(),
        3
    );
    for p in f.samples() {
        image::open(p)?;
    }
    let shorter = fs::read_to_string(&f.source)?.replace("class=\"page\"", "class=\"continuous\"");
    fs::write(&f.source, shorter)?;
    build::cli_build(&f.args(true))?;
    assert_eq!(
        revayat_scientific::pdf::geometry(&revayat_scientific::pdf::open_pdf(&f.output, false)?)?
            .len(),
        1
    );
    let images = f
        .samples()
        .iter()
        .map(image::open)
        .collect::<image::ImageResult<Vec<_>>>()?;
    assert_eq!(images[0].to_rgb8(), images[1].to_rgb8());
    assert_eq!(images[0].to_rgb8(), images[2].to_rgb8());
    Ok(())
}
#[test]
#[ignore = "requires sandboxed Chromium and Poppler"]
fn test_late_raster_failure_preserves_entire_previous_preview_batch() -> Result<()> {
    let f = Fixture::new()?;
    f.fonts()?;
    for p in f.samples() {
        fs::write(p, b"previous approved preview")?;
    }
    let tools = f.root.join("tools");
    fs::create_dir(&tools)?;
    let name = if cfg!(windows) {
        "pdftoppm.exe"
    } else {
        "pdftoppm"
    };
    fs::copy(env!("CARGO_BIN_EXE_revayat-test-tool"), tools.join(name))?;
    let mut paths = vec![tools];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let path = std::env::join_paths(paths)?;
    let output = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args(["build"])
        .args(f.args(true))
        .env("PATH", path)
        .env("REVAYAT_REAL_PDFTOPPM", runtime::executable("pdftoppm")?)
        .env("REVAYAT_TEST_RASTER_STATE", f.root.join("raster-state"))
        .output()?;
    assert!(!output.status.success());
    for p in f.samples() {
        assert_eq!(fs::read(p)?, b"previous approved preview");
    }
    f.unchanged()
}
#[test]
fn test_explicit_engine_discovery_does_not_probe_other_backends() -> Result<()> {
    let f = Fixture::new()?;
    let selection = build::select_source(
        &f.source,
        Some("chromium"),
        Some(env!("CARGO_BIN_EXE_revayat-test-tool")),
    )?;
    assert_eq!(selection.engine, "chromium");
    assert!(selection.container.is_none());
    assert!(selection.browser.unwrap().is_absolute());
    Ok(())
}
#[test]
fn test_both_native_shells_preserve_colliding_source_inputs() -> Result<()> {
    let f = Fixture::new()?;
    let mut args = f.args(false);
    args.extend([
        "--out".into(),
        f.root.join("terms.tsv").display().to_string(),
    ]);
    assert!(build::cli_build(&args).is_err());
    let output = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .arg("build")
        .args(args)
        .output()?;
    assert!(!output.status.success());
    assert_eq!(
        fs::read(f.root.join("terms.tsv"))?,
        fs::read(repo().join("tests/fixtures/terms-empty.tsv"))?
    );
    f.unchanged()
}
#[test]
fn test_path_browser_is_a_resolved_executable() -> Result<()> {
    let f = Fixture::new()?;
    let tools = f.root.join("browser tools");
    fs::create_dir(&tools)?;
    let browser = tools.join(if cfg!(windows) {
        "google-chrome.exe"
    } else {
        "google-chrome"
    });
    fs::copy(env!("CARGO_BIN_EXE_revayat-test-tool"), &browser)?;
    let selected = render::discover_browser(Some(browser.to_str().unwrap()))?;
    assert_eq!(selected, browser.canonicalize()?);
    let found = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .arg("doctor")
        .current_dir(&f.root)
        .env("PATH", "browser tools")
        .env_remove("REVAYAT_BROWSER")
        .env_remove("REVAYAT_CHROMIUM")
        .output()?;
    assert!(
        found.status.success(),
        "{}",
        String::from_utf8_lossy(&found.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&found.stdout)?;
    assert_eq!(
        Path::new(report["chromium"]["path"].as_str().unwrap()),
        browser.canonicalize()?
    );
    assert!(render::discover_browser(Some("missing browser")).is_err());
    Ok(())
}
#[test]
fn test_selected_browser_survives_the_source_directory_change() -> Result<()> {
    let f = Fixture::new()?;
    let selected = render::discover_browser(Some(env!("CARGO_BIN_EXE_revayat-test-tool")))?;
    let marker = f.root.join("marker");
    let mut spec = CommandSpec::new(selected).args(["fake-browser"]);
    spec.cwd = Some(f.root.clone());
    spec.env.insert(
        "REVAYAT_TEST_BROWSER_MARKER".into(),
        marker.as_os_str().into(),
    );
    assert_eq!(runtime::run(&spec)?.code, 42);
    assert_eq!(fs::read_to_string(marker)?, f.root.to_string_lossy());
    Ok(())
}
#[test]
fn test_failed_or_invalid_renderer_cannot_replace_delivery() -> Result<()> {
    for outcome in [
        "nonzero-valid",
        "zero-missing",
        "zero-truncated",
        "changed-source",
    ] {
        let f = Fixture::new()?;
        let result = render::render_html_with(&f.source, &f.output, None, |_, stage| {
            if outcome != "zero-missing" {
                runtime_support::pdf(stage)?;
            }
            if outcome == "zero-truncated" {
                fs::write(stage, b"%PDF-1.7\ntruncated")?;
            }
            if outcome == "nonzero-valid" {
                bail!("renderer nonzero");
            }
            if outcome == "changed-source" {
                fs::write(&f.source, b"<html>changed</html>")?;
            }
            Ok(())
        });
        assert!(result.is_err());
        f.unchanged()?;
    }
    Ok(())
}
#[test]
#[ignore = "requires sandboxed Chromium"]
fn test_real_chromium_resource_denial_preserves_previous_delivery() -> Result<()> {
    let f = Fixture::new()?;
    f.fonts()?;
    let browser = render::discover_browser(None)?;
    render::render_html(&f.source, &f.output, &browser, None)?;
    let approved = fs::read(&f.output)?;
    let outside = f
        ._temp
        .path()
        .parent()
        .unwrap()
        .join(format!("outside-{}.css", std::process::id()));
    fs::write(&outside, b"body{color:red}")?;
    let url = url::Url::from_file_path(&outside).unwrap();
    fs::write(
        &f.source,
        format!("<html><link rel=\"stylesheet\" href=\"{url}\"><p>متن علمی</p></html>"),
    )?;
    assert!(render::render_html(&f.source, &f.output, &browser, None).is_err());
    assert_eq!(fs::read(&f.output)?, approved);
    fs::remove_file(outside)?;
    Ok(())
}
#[test]
fn test_presentation_forms_preserve_logical_order() -> Result<()> {
    let source = revayat_scientific::text_order::source_plain(
        &repo().join("tests/fixtures/build-smoke-body.tex"),
    )?;
    let windows = revayat_scientific::text_order::persian_windows(&source, 12)?;
    let extracted = fs::read_to_string(repo().join("tests/fixtures/pdf-text-presentation.txt"))?;
    assert_eq!(
        revayat_scientific::text_order::classify(&windows, &extracted, 12),
        "logical"
    );
    Ok(())
}
#[test]
fn test_unicode_font_flag_is_not_embedding() -> Result<()> {
    let table = "name type encoding emb sub uni object ID\n--------------------------------\nExample CID TrueType Identity-H no no yes 4 0\n";
    assert!(build::verify_font_table(table).is_err());
    assert!(build::verify_font_table(&table.replace("no no yes", "yes yes yes")).is_ok());
    Ok(())
}
#[test]
fn test_extraction_uses_utf8() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args(["text-order", "--source"])
        .arg(repo().join("tests/fixtures/good.tex"))
        .arg("--extracted")
        .arg(repo().join("tests/fixtures/pdf-text-logical.txt"))
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(std::str::from_utf8(&output.stderr)?.contains("logical"));
    Ok(())
}
#[cfg(windows)]
#[test]
fn test_windows_shells_refuse_missing_container_without_changing_delivery() -> Result<()> {
    let f = Fixture::new()?;
    let source = f.root.join("document.tex");
    fs::copy(
        repo().join("skills/revayat-scientific/assets/rtl-document.tex"),
        &source,
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args(["build"])
        .arg(source)
        .args(["article", "--engine", "tex", "--output-dir"])
        .arg(f.root.join("delivered"))
        .env(
            "REVAYAT_CONTAINER_RUNTIME",
            f.root.join("missing-container.exe"),
        )
        .output()?;
    assert!(!output.status.success());
    f.unchanged()
}
#[cfg(windows)]
#[test]
#[ignore = "requires installed sandboxed Chromium on native Windows"]
fn test_windows_build_preserves_destination_on_failure() -> Result<()> {
    let f = Fixture::new()?;
    f.fonts()?;
    fs::remove_file(f.root.join("terms.tsv"))?;
    assert!(build::cli_build(&f.args(false)).is_err());
    f.unchanged()?;
    fs::copy(
        repo().join("tests/fixtures/terms-empty.tsv"),
        f.root.join("terms.tsv"),
    )?;
    build::cli_build(&f.args(false))?;
    let previous = fs::read(&f.output)?;
    fs::write(&f.source, "<html>اين متن باید رد شود.</html>")?;
    assert!(build::cli_build(&f.args(false)).is_err());
    assert_eq!(fs::read(&f.output)?, previous);
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires prepared local Docker image and effective cgroup controls"]
fn test_production_launch_enforces_isolation_and_cleans_owned_container() -> Result<()> {
    let proof = revayat_scientific::sandbox::probe()?;
    assert_eq!(proof["verified"], true);
    assert_eq!(proof["checks"], 29);
    assert_eq!(proof["container_cleanup"], "verified");
    Ok(())
}

#[test]
#[ignore = "requires prepared isolated XeLaTeX image and Poppler"]
fn test_multipart_geometry_images_math_and_verified_delivery() -> Result<()> {
    let f = Fixture::new()?;
    fs::create_dir(f.root.join("chapters"))?;
    fs::create_dir(f.root.join("figures"))?;
    image::RgbImage::from_pixel(600, 300, image::Rgb([120, 180, 220]))
        .save(f.root.join("figures/plot.png"))?;
    let template =
        fs::read_to_string(repo().join("skills/revayat-scientific/assets/rtl-document.tex"))?
            .replace(
                "paperwidth=210mm,paperheight=297mm",
                "paperwidth=180mm,paperheight=240mm",
            )
            .replace("\\maketitle", "\\maketitle\n\\input{chapters/body}");
    let source = f.root.join("document.tex");
    fs::write(&source, template)?;
    let figure = "\n\\begin{LTR}\\includegraphics[width=50mm]{figures/plot.png}\\end{LTR}\n\\begin{tabular}{ll}کمیت & مقدار \\\\ دما & \\en{23.5 C} \\\\ \\end{tabular}\n\\begin{latin}La mesure dépend des conditions expérimentales.\\end{latin}\n";
    let body = fs::read_to_string(repo().join("tests/fixtures/build-smoke-body.tex"))?.replacen(
        "\\clearpage",
        &format!("{figure}\\clearpage"),
        1,
    );
    fs::write(f.root.join("chapters/body.tex"), body)?;
    fs::write(f.root.join("manifest.txt"), b"plot.png\n")?;
    let args = vec![
        source.display().to_string(),
        "article".into(),
        "--engine".into(),
        "tex".into(),
        "--level".into(),
        "journal".into(),
        "--verify".into(),
        "--output-dir".into(),
        f.root.join("delivered").display().to_string(),
    ];
    if let Err(error) = build::cli_build(&args) {
        let evidence = repo().join(".scratch/native-render-evidence");
        fs::create_dir_all(&evidence)?;
        if source.with_extension("pdf").is_file() {
            fs::copy(source.with_extension("pdf"), evidence.join("multipart.pdf"))?;
        }
        fs::write(
            evidence.join("multipart-source.txt"),
            revayat_scientific::text_order::source_plain(&source)?,
        )?;
        return Err(error);
    }
    let document = revayat_scientific::pdf::open_pdf(&f.output, false)?;
    let pages = revayat_scientific::pdf::geometry(&document)?;
    assert!(pages.len() >= 3);
    for page in &pages {
        assert!((page.rect[2] - 180.0 * 72.0 / 25.4).abs() < 0.5);
        assert!((page.rect[3] - 240.0 * 72.0 / 25.4).abs() < 0.5);
    }
    let first = revayat_scientific::pdf::page_text(&document, 1)?;
    let compact = first.split_whitespace().collect::<String>();
    for number in ["3.14", "2.5", "0.25"] {
        assert!(
            compact.contains(number),
            "missing mathematical value {number}"
        );
    }
    assert!((1..=pages.len()).any(|p| {
        revayat_scientific::pdf_content::artwork(&document, p)
            .is_ok_and(|(_, images)| images.iter().any(|i| i.width == 600 && i.height == 300))
    }));
    let approved = fs::read(&f.output)?;
    let mut body = fs::read_to_string(f.root.join("chapters/body.tex"))?;
    body.push_str("\nاين متن باید رد شود.\n");
    fs::write(f.root.join("chapters/body.tex"), body)?;
    assert!(build::cli_build(&args).is_err());
    assert_eq!(fs::read(&f.output)?, approved);
    Ok(())
}
#[test]
#[ignore = "requires prepared isolated XeLaTeX image"]
fn test_container_host_sentinel_and_shortened_internal_deadline() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let job = temp.path().join("job");
    fs::create_dir(&job)?;
    let sentinel = temp.path().join("outside.txt");
    fs::write(&sentinel, b"HOST_SENTINEL_MUST_NOT_BE_READ")?;
    let source = job.join("paper.tex");
    let output = job.join("paper.pdf");
    fs::write(
        &source,
        format!(
            "\\documentclass{{article}}\n\\begin{{document}}\n\\newread\\probe\n\\openin\\probe=\"{}\"\n\\ifeof\\probe SAFE\\else\\errmessage{{Host file was accessible}}\\fi\n\\closein\\probe\n\\end{{document}}",
            sentinel.display()
        ),
    )?;
    let config = tex::runtime_config()?;
    tex::compile_document(&source, &output, Some(config.clone()), None)?;
    let approved = fs::read(&output)?;
    fs::write(
        &source,
        b"\\documentclass{article}\\begin{document}\\loop\\iftrue\\repeat\\end{document}",
    )?;
    let result = tex::compile_document_observed(
        &source,
        &output,
        config,
        None,
        &mut |args, timeout| {
            let args = args
                .iter()
                .map(|a| if a == "120s" { "2s".into() } else { a.clone() })
                .collect::<Vec<_>>();
            tex::call(&args, timeout)
        },
        |_, _, _| Ok(()),
    );
    assert!(result.is_err());
    assert_eq!(fs::read(output)?, approved);
    assert!(!fs::read_dir(job)?.any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-tex-")
    }));
    Ok(())
}
fn receipts(root: &Path, result: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            receipts(&path, result)?;
        } else if path.file_name().is_some_and(|n| {
            n.to_string_lossy().starts_with("container-") && n.to_string_lossy().ends_with(".json")
        }) {
            result.push(path);
        }
    }
    Ok(())
}
#[test]
#[ignore = "requires real local Docker cancellation seam"]
fn test_surviving_owner_reaps_container_after_controller_is_killed() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("paper.tex");
    let output = temp.path().join("paper.pdf");
    fs::write(
        &source,
        b"\\documentclass{article}\\begin{document}\\loop\\iftrue\\repeat\\end{document}",
    )?;
    fs::write(&output, b"previous approved delivery")?;
    let config = tex::runtime_config()?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args([
            "--timeout",
            "45",
            "run-check",
            "--timeout",
            "120",
            "--",
            env!("CARGO_BIN_EXE_revayat-scientific"),
            "--timeout",
            "120",
            "tex-container",
        ])
        .arg(&source)
        .arg(&output)
        .current_dir(temp.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    let mut run = None;
    while std::time::Instant::now() < deadline {
        let mut paths = vec![];
        receipts(temp.path(), &mut paths)?;
        if let Some(path) = paths.first() {
            let receipt: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
            let identity = receipt["run_id"]
                .as_str()
                .context("receipt omitted run identity")?
                .to_owned();
            let mut listing = config.base.clone();
            listing.extend([
                "ps".into(),
                "--no-trunc".into(),
                "--filter".into(),
                format!("label={}= {identity}", tex::RUN_LABEL).replace("= ", "="),
                "--format".into(),
                "{{.ID}}".into(),
            ]);
            if tex::call(&listing, 5)?.1.trim().len() == 64 {
                run = Some(identity);
                break;
            }
        }
        if child.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let result = child.wait_with_output()?;
    if result.status.code() != Some(124) {
        let retained = temp.keep();
        bail!(
            "global cancellation failed; retained fixture {}: {}",
            retained.display(),
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let run = run.context("container did not start before real cancellation seam")?;
    assert_eq!(fs::read(output)?, b"previous approved delivery");
    let mut listing = config.base;
    listing.extend([
        "ps".into(),
        "-a".into(),
        "--filter".into(),
        format!("label={}= {run}", tex::RUN_LABEL).replace("= ", "="),
        "--format".into(),
        "{{.ID}}".into(),
    ]);
    let (code, remaining) = tex::call(&listing, 15)?;
    assert_eq!(code, 0);
    assert!(remaining.trim().is_empty());
    let mut paths = vec![];
    receipts(temp.path(), &mut paths)?;
    assert!(paths.is_empty());
    Ok(())
}
#[test]
#[ignore = "requires sandboxed native Chromium resource interception"]
fn test_native_html_resource_denial_preserves_previous_output() -> Result<()> {
    let f = Fixture::new()?;
    f.fonts()?;
    let browser = render::discover_browser(None)?;
    fs::write(
        &f.source,
        "<html lang=\"fa\" dir=\"rtl\"><style>@page{size:160mm 240mm}</style><p>این متن علمی برای بررسی است.</p></html>",
    )?;
    render::render_html(&f.source, &f.output, &browser, None)?;
    let document = revayat_scientific::pdf::open_pdf(&f.output, false)?;
    let page = &revayat_scientific::pdf::geometry(&document)?[0];
    assert!((page.rect[2] - 160.0 * 72.0 / 25.4).abs() < 0.5);
    let approved = fs::read(&f.output)?;
    let outside = f
        ._temp
        .path()
        .parent()
        .unwrap()
        .join(format!("denied-{}.css", std::process::id()));
    fs::write(&outside, b"body{color:red}")?;
    let url = url::Url::from_file_path(&outside).unwrap();
    fs::write(
        &f.source,
        format!("<html><style>@import url('{url}');</style><p>متن علمی</p></html>"),
    )?;
    assert!(render::render_html(&f.source, &f.output, &browser, None).is_err());
    assert_eq!(fs::read(&f.output)?, approved);
    fs::remove_file(outside)?;
    Ok(())
}
