//! Real browser/TeX/container gates are explicitly ignored during the portable
//! suite and explicitly required by their native CI jobs; absence never passes.
use anyhow::{Result, bail};
use revayat_scientific::{
    build, render,
    runtime::{self, CommandSpec},
    tex_container as tex,
};
use std::{fs, path::Path, time::Duration};
#[path = "support/runtime_cancellation.rs"]
mod cancellation;
#[path = "support/runtime_build_fixture.rs"]
mod fixture;
mod runtime_support;
#[path = "support/runtime_scientific.rs"]
mod scientific;
use fixture::{Fixture, repo};
#[test]
fn test_each_source_preview_collision_is_rejected_before_any_output_changes() -> Result<()> {
    for role in ["first", "last", "mid"] {
        let f = Fixture::new()?;
        let asset = f.asset(&format!("verify-article-{role}.png"), false)?;
        let before = fs::read(&asset)?;
        let snapshots = f.snapshots()?;
        let mut args = f.args(true);
        args.extend([
            "--browser".into(),
            env!("CARGO_BIN_EXE_revayat-test-tool").into(),
        ]);
        let error = build::cli_build(&args).unwrap_err();
        assert!(error.to_string().contains("protected source"));
        assert_eq!(fs::read(asset)?, before);
        f.preserved(&snapshots)?;
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
        args.extend([
            format!("--{field}"),
            f.output.display().to_string(),
            "--browser".into(),
            env!("CARGO_BIN_EXE_revayat-test-tool").into(),
        ]);
        let snapshots = f.snapshots()?;
        assert!(
            build::cli_build(&args)
                .unwrap_err()
                .to_string()
                .contains("protected source")
        );
        f.preserved(&snapshots)?;
        assert!(!f.source.with_extension("pdf").exists());
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
    let snapshots = f.snapshots()?;
    assert!(
        build::cli_build(&f.args(true))
            .unwrap_err()
            .to_string()
            .contains("protected source")
    );
    f.preserved(&snapshots)?;
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
    let snapshots = f.snapshots()?;
    assert_eq!(build::cli_build(&f.args(false))?, 0);
    f.preserved(&snapshots)?;
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
    let snapshots = f.snapshots()?;
    build::cli_build(&f.args(true))?;
    f.preserved(&snapshots)?;
    assert_eq!(
        fs::read(&f.output)?,
        fs::read(f.source.with_extension("pdf"))?
    );
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
    assert_eq!(
        fs::read(&f.output)?,
        fs::read(f.source.with_extension("pdf"))?
    );
    assert_eq!(fs::read_to_string(&f.source)?, shorter);
    for (path, bytes) in snapshots.iter().filter(|(path, _)| *path != f.source) {
        assert_eq!(fs::read(path)?, *bytes);
    }
    f.clean()
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
    let snapshots = f.snapshots()?;
    let state = f.root.join("raster-state");
    let mut args = vec![std::ffi::OsString::from("build")];
    args.extend(f.args(true).into_iter().map(Into::into));
    let output = f.run(
        args,
        75,
        [
            ("PATH".into(), path),
            (
                "REVAYAT_REAL_PDFTOPPM".into(),
                runtime::executable("pdftoppm")?.into_os_string(),
            ),
            (
                "REVAYAT_TEST_RASTER_STATE".into(),
                state.clone().into_os_string(),
            ),
        ],
    )?;
    assert!(!output.success());
    assert_eq!(
        fs::read(&state)?,
        b"first raster",
        "actual initial raster must run before injected late failure"
    );
    f.preserved(&snapshots)?;
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
    let asset = f.asset("verify-article-first.png", false)?;
    let before = f.snapshots()?;
    let mut args = f.args(true);
    args.extend([
        "--browser".into(),
        env!("CARGO_BIN_EXE_revayat-test-tool").into(),
    ]);
    assert!(
        build::cli_build(&args)
            .unwrap_err()
            .to_string()
            .contains("protected source")
    );
    let mut public = vec![std::ffi::OsString::from("build")];
    public.extend(args.into_iter().map(Into::into));
    let output = f.run(public, 30, [])?;
    assert!(!output.success());
    assert!(output.stderr_text().contains("protected source"));
    f.preserved(&before)?;
    assert!(asset.is_file());
    assert!(!f.source.with_extension("pdf").exists());
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
    let found = f.run(
        vec!["doctor".into()],
        10,
        [
            ("PATH".into(), "browser tools".into()),
            ("REVAYAT_BROWSER".into(), "".into()),
            ("REVAYAT_CHROMIUM".into(), "".into()),
        ],
    )?;
    assert!(
        found.success(),
        "{}",
        String::from_utf8_lossy(&found.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&found.stdout)?;
    assert_eq!(
        Path::new(report["chromium"]["path"].as_str().unwrap()),
        browser.canonicalize()?
    );
    assert!(render::discover_browser(Some("missing browser")).is_err());
    let invalid = f.run(
        vec!["doctor".into()],
        10,
        [
            ("PATH".into(), "browser tools".into()),
            ("REVAYAT_BROWSER".into(), "missing browser".into()),
            ("REVAYAT_CHROMIUM".into(), "".into()),
        ],
    )?;
    let invalid: serde_json::Value = serde_json::from_slice(&invalid.stdout)?;
    assert_eq!(invalid["chromium"]["available"], false);
    Ok(())
}
#[test]
fn test_selected_browser_survives_the_source_directory_change() -> Result<()> {
    let f = Fixture::new()?;
    let selected = render::discover_browser(Some(env!("CARGO_BIN_EXE_revayat-test-tool")))?;
    let marker = f.root.join("marker");
    let source_dir = f.root.join("source");
    fs::create_dir(&source_dir)?;
    let mut spec = CommandSpec::new(selected).args(["fake-browser"]);
    spec.cwd = Some(source_dir.clone());
    spec.timeout = Duration::from_secs(10);
    spec.env.insert(
        "REVAYAT_TEST_BROWSER_MARKER".into(),
        marker.as_os_str().into(),
    );
    assert_eq!(runtime::run(&spec)?.code, 42);
    assert_eq!(fs::read_to_string(marker)?, source_dir.to_string_lossy());
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
    fs::write(
        &f.source,
        "<html lang=\"fa\" dir=\"rtl\"><style>@page{size:180mm 240mm}</style><p>این متن فارسی برای بررسی خروجی است.</p></html>",
    )?;
    render::render_html(&f.source, &f.output, &browser, None)?;
    let document = revayat_scientific::pdf::open_pdf(&f.output, false)?;
    let pages = revayat_scientific::pdf::geometry(&document)?;
    assert_eq!(pages.len(), 1);
    assert!((pages[0].rect[2] - 180. * 72. / 25.4).abs() < 1.);
    assert!((pages[0].rect[3] - 240. * 72. / 25.4).abs() < 1.);
    let approved = fs::read(&f.output)?;
    let outside_owner = tempfile::tempdir()?;
    let outside = outside_owner.path().join("outside.css");
    fs::write(&outside, b"body{color:red}")?;
    let url = url::Url::from_file_path(&outside).unwrap();
    fs::write(
        &f.source,
        format!("<html><link rel=\"stylesheet\" href=\"{url}\"><p>متن علمی</p></html>"),
    )?;
    assert!(render::render_html(&f.source, &f.output, &browser, None).is_err());
    assert_eq!(fs::read(&f.output)?, approved);
    fs::remove_file(outside)?;
    f.clean()
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
    assert!(
        build::verify_font_table(table)
            .unwrap_err()
            .to_string()
            .contains("not embedded")
    );
    assert!(build::verify_font_table(&table.replace("no no yes", "yes yes yes")).is_ok());
    Ok(())
}
#[test]
fn test_extraction_uses_utf8() -> Result<()> {
    let f = Fixture::new()?;
    let output = f.run(
        vec![
            "text-order".into(),
            "--source".into(),
            repo().join("tests/fixtures/good.tex").into_os_string(),
            "--extracted".into(),
            repo()
                .join("tests/fixtures/pdf-text-logical.txt")
                .into_os_string(),
        ],
        10,
        [],
    )?;
    assert!(
        output.success(),
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
    let output = f.run(
        vec![
            "build".into(),
            source.clone().into_os_string(),
            "article".into(),
            "--engine".into(),
            "tex".into(),
            "--output-dir".into(),
            f.root.join("delivered").into_os_string(),
        ],
        20,
        [(
            "REVAYAT_CONTAINER_RUNTIME".into(),
            f.root.join("missing-container.exe").into_os_string(),
        )],
    )?;
    assert!(!output.success());
    assert!(
        output
            .stderr_text()
            .contains("external tool is not available:")
    );
    assert!(!source.with_extension("pdf").exists());
    f.unchanged()
}
#[cfg(windows)]
#[test]
#[ignore = "requires installed sandboxed Chromium on native Windows"]
fn test_windows_build_preserves_destination_on_failure() -> Result<()> {
    let f = Fixture::new()?;
    f.fonts()?;
    fs::remove_file(f.root.join("terms.tsv"))?;
    assert!(
        build::cli_build(&f.args(false))
            .unwrap_err()
            .to_string()
            .contains("terms.tsv")
    );
    f.unchanged()?;
    fs::copy(
        repo().join("tests/fixtures/terms-empty.tsv"),
        f.root.join("terms.tsv"),
    )?;
    build::cli_build(&f.args(false))?;
    let document = revayat_scientific::pdf::open_pdf(&f.output, false)?;
    assert_eq!(revayat_scientific::pdf::geometry(&document)?.len(), 3);
    let previous = fs::read(&f.output)?;
    let ordered = f.run(
        vec![
            "text-order".into(),
            f.output.clone().into_os_string(),
            "--source".into(),
            f.source.clone().into_os_string(),
            "--json".into(),
        ],
        20,
        [],
    )?;
    assert!([0, 2, 3].contains(&ordered.code));
    assert!(!std::str::from_utf8(&ordered.stderr)?.contains("UnicodeDecodeError"));
    let order: serde_json::Value = serde_json::from_slice(&ordered.stdout)?;
    let verified = build::cli_build(&f.args(true));
    if order["status"] == "passed" {
        verified?;
    } else {
        assert!(
            verified
                .unwrap_err()
                .to_string()
                .contains("text-order verification")
        );
        assert_eq!(fs::read(&f.output)?, previous);
    }
    for sample in f.samples() {
        assert!(sample.is_file());
    }
    let latest = fs::read(&f.output)?;
    fs::write(&f.source, "<html>اين متن باید رد شود.</html>")?;
    assert!(build::cli_build(&f.args(false)).is_err());
    assert_eq!(fs::read(&f.output)?, latest);
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires prepared local Docker image and effective cgroup controls"]
fn test_production_launch_enforces_isolation_and_cleans_owned_container() -> Result<()> {
    scientific::probe_output_integrity()?;
    let proof = revayat_scientific::sandbox::probe()?;
    assert_eq!(proof["verified"], true);
    assert_eq!(proof["checks"], 29);
    assert_eq!(proof["container_cleanup"], "verified");
    Ok(())
}

#[test]
#[ignore = "requires prepared isolated XeLaTeX image and Poppler"]
fn test_multipart_geometry_images_math_and_verified_delivery() -> Result<()> {
    scientific::multipart_geometry_images_math_and_verified_delivery()
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
#[test]
#[ignore = "requires real local Docker cancellation seam"]
fn test_surviving_owner_reaps_container_after_controller_is_killed() -> Result<()> {
    cancellation::surviving_owner_reaps_container()
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
    assert!((page.rect[3] - 240.0 * 72.0 / 25.4).abs() < 0.5);
    let approved = fs::read(&f.output)?;
    let outside_owner = tempfile::tempdir()?;
    let outside = outside_owner.path().join("outside.css");
    fs::write(&outside, b"body{color:red}")?;
    let url = url::Url::from_file_path(&outside).unwrap();
    fs::write(
        &f.source,
        format!("<html><style>@import url('{url}');</style><p>متن علمی</p></html>"),
    )?;
    assert!(render::render_html(&f.source, &f.output, &browser, None).is_err());
    assert_eq!(fs::read(&f.output)?, approved);
    fs::remove_file(outside)?;
    f.clean()
}
