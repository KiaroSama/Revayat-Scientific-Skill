//! The 37 original standalone upstream checks, retained as registered Rust
//! scenarios in addition to the 583 public-test migration inventory.
use anyhow::Result;
use read_fonts::TableProvider;
use revayat_scientific::{build, fonts, pdf_font, tex};
use std::{
    fs,
    path::{Path, PathBuf},
};
#[path = "support/upstream_build.rs"]
mod build_checks;
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned()
}
fn fixture(name: &str) -> PathBuf {
    repo().join("tests/fixtures").join(name)
}
use revayat_scientific::runtime::{self, CommandOutput as Output, CommandSpec};
fn invoke(args: &[String]) -> Output {
    invoke_environment(args, &[])
}
fn invoke_environment(args: &[String], environment: &[(&str, std::ffi::OsString)]) -> Output {
    let logs = tempfile::tempdir().unwrap();
    let mut command =
        CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific")).args(args.iter().cloned());
    command.cwd = Some(repo());
    command.timeout = std::time::Duration::from_secs(180);
    command.max_output = 4 * 1024 * 1024;
    command.env.extend(
        environment
            .iter()
            .map(|(key, value)| ((*key).into(), value.clone())),
    );
    command
        .env
        .insert("REVAYAT_LOG_DIR".into(), logs.path().into());
    runtime::run_supervised(&command).unwrap()
}
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}
fn text(output: &Output) -> String {
    let mut bytes = output.stdout.clone();
    bytes.extend_from_slice(&output.stderr);
    String::from_utf8(bytes).expect("native diagnostics must always be UTF-8")
}
fn lint(name: &str, extra: &[&str]) -> Output {
    let mut args = vec!["lint".into(), fixture(name).display().to_string()];
    args.extend(strings(extra));
    invoke(&args)
}
fn strict(name: &str, level: &str, manifest: &str) -> Output {
    lint(
        name,
        &[
            "--strict",
            "--level",
            level,
            "--terms",
            fixture("terms-empty.tsv").to_str().unwrap(),
            "--manifest",
            fixture(manifest).to_str().unwrap(),
        ],
    )
}
fn clean(output: Output) {
    assert!(output.success(), "{}", text(&output));
}
fn contains(output: Output, checks: &[&str]) {
    assert!(!output.success());
    let text = text(&output);
    for check in checks {
        assert!(text.contains(check), "missing {check}: {text}");
    }
}
struct Work {
    _temp: tempfile::TempDir,
    root: PathBuf,
    source: PathBuf,
    working: PathBuf,
    output: PathBuf,
}
impl Work {
    fn new() -> Self {
        let scratch = repo().join(".scratch");
        fs::create_dir_all(&scratch).unwrap();
        let temp = tempfile::tempdir_in(scratch).unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = root.join("doc.tex");
        fs::write(
            &source,
            fs::read(repo().join("skills/revayat-scientific/assets/rtl-document.tex")).unwrap(),
        )
        .unwrap();
        fs::copy(fixture("terms-empty.tsv"), root.join("terms.tsv")).unwrap();
        fs::write(root.join("manifest.txt"), b"").unwrap();
        let working = root.join("doc.pdf");
        let output = root.join("delivered/article.pdf");
        fs::create_dir(output.parent().unwrap()).unwrap();
        fs::write(&output, b"previous approved delivery").unwrap();
        Self {
            _temp: temp,
            root,
            source,
            working,
            output,
        }
    }
    fn unchanged(&self) {
        assert_eq!(
            fs::read(&self.output).unwrap(),
            b"previous approved delivery"
        );
    }
    fn args(&self) -> Vec<String> {
        vec![
            "build".into(),
            self.source.display().to_string(),
            "--out".into(),
            self.output.display().to_string(),
            "--engine".into(),
            "tex".into(),
        ]
    }
    fn compile(&self, body: &str) -> Result<()> {
        let source = fs::read_to_string(&self.source)?
            .replace("\\end{document}", &format!("{body}\n\\end{{document}}"));
        fs::write(&self.source, source)?;
        fonts::fetch_with_cache(
            &self.root.join("fonts"),
            "33.003",
            true,
            &self.root.join("font-cache/33.003"),
        )?;
        let output = invoke(&self.args());
        assert!(output.success(), "{}", text(&output));
        let delivered_name = self.output.file_name().unwrap().to_str().unwrap();
        assert!(text(&output).contains(delivered_name), "{}", text(&output));
        revayat_scientific::pdf::validate_pdf(&self.output)?;
        Ok(())
    }
}
#[test]
fn good_tex_lints_clean() {
    clean(strict("good.tex", "system-docs", "manifest-good.txt"));
}
#[test]
fn good_html_lints_clean() {
    clean(strict("good.html", "system-docs", "manifest-good.txt"));
}
#[test]
fn journal_tex_lints_clean_at_journal_level() {
    clean(strict("journal.tex", "journal", "manifest-empty.txt"));
}
#[test]
fn shipped_tex_template_has_no_errors() {
    let output = invoke(&[
        "lint".into(),
        repo()
            .join("skills/revayat-scientific/assets/rtl-document.tex")
            .display()
            .to_string(),
    ]);
    assert!(output.success(), "{}", text(&output));
}
#[test]
fn shipped_html_template_has_no_errors() {
    let output = invoke(&[
        "lint".into(),
        repo()
            .join("skills/revayat-scientific/assets/rtl-document.html")
            .display()
            .to_string(),
    ]);
    assert!(output.success(), "{}", text(&output));
}
#[test]
fn bad_tex_reports_all_original_rule_ids() {
    contains(
        lint("bad.tex", &[]),
        &[
            "arabic-letters",
            "eastern-digits",
            "zwnj-verb",
            "zwnj-plural",
            "latin-punct",
            "forbidden-fa",
            "half-translation",
            "fa-morphology",
            "en-plural",
            "split-isolate",
            "unisolated-latin",
            "unisolated-number",
            "code-direction",
            "missing-image",
            "bookmark-guard",
            "figure-direction",
            "full-page-figure",
        ],
    );
}
#[test]
fn bad_html_reports_all_original_rule_ids() {
    contains(
        lint("bad.html", &[]),
        &[
            "arabic-letters",
            "eastern-digits",
            "zwnj-verb",
            "forbidden-fa",
            "half-translation",
            "fa-morphology",
            "en-plural",
            "split-isolate",
            "unisolated-latin",
            "unisolated-number",
            "code-direction",
            "html-root",
            "mirrored-image",
            "missing-image",
            "print-css",
            "figure-direction",
            "full-page-figure",
        ],
    );
}
#[test]
fn journal_terms_are_forbidden_at_default_system_docs_level() {
    contains(lint("journal.tex", &[]), &["forbidden-fa"]);
}
#[test]
fn extra_pairs_merge_instead_of_replacing_house_terms() {
    let w = Work::new();
    let pairs = w.root.join("extra.tsv");
    fs::write(
        &pairs,
        "english\tforbidden_fa\tscope\tlevels\nfoo\tبار\tuniversal\tall\n",
    )
    .unwrap();
    contains(
        lint("journal.tex", &["--pairs", pairs.to_str().unwrap()]),
        &["forbidden-fa", "گره"],
    );
}
#[test]
fn strict_requires_terms_ledger() {
    let output = lint("nginx-calque.tex", &["--strict"]);
    assert_eq!(Some(output.code), Some(2));
    assert!(text(&output).contains("--terms"));
}
#[test]
fn strict_requires_figure_manifest() {
    let output = lint(
        "nginx-calque.tex",
        &[
            "--strict",
            "--terms",
            fixture("terms-empty.tsv").to_str().unwrap(),
        ],
    );
    assert_eq!(Some(output.code), Some(2));
    assert!(text(&output).contains("--manifest"));
}
#[test]
fn incomplete_keep_english_rows_fail_closed() {
    let output = lint(
        "nginx-calque.tex",
        &[
            "--terms",
            fixture("terms-incomplete.tsv").to_str().unwrap(),
            "--manifest",
            fixture("manifest-empty.txt").to_str().unwrap(),
        ],
    );
    assert_eq!(Some(output.code), Some(2));
    assert!(text(&output).contains("terms-calque"));
    assert!(text(&output).contains("proxy_pass"));
}
#[test]
fn job_ledger_calques_are_reported() {
    contains(
        lint(
            "nginx-calque.tex",
            &[
                "--terms",
                fixture("terms-nginx.tsv").to_str().unwrap(),
                "--manifest",
                fixture("manifest-empty.txt").to_str().unwrap(),
                "--strict",
            ],
        ),
        &["forbidden-fa", "مکان", "بالادست"],
    );
}
#[test]
fn deprecated_ledger_forms_are_forbidden() {
    let output = lint(
        "terms-deprecated.tex",
        &[
            "--terms",
            fixture("terms-nginx.tsv").to_str().unwrap(),
            "--manifest",
            fixture("manifest-empty.txt").to_str().unwrap(),
        ],
    );
    assert!(!output.success());
    let text = text(&output);
    assert!(
        ["کد مبدأ", "بالادست", "مکان"]
            .iter()
            .any(|term| text.contains(term))
    );
}
#[test]
fn job_ledger_keeps_house_term_pairs() {
    contains(
        lint(
            "journal.tex",
            &["--terms", fixture("terms-nginx.tsv").to_str().unwrap()],
        ),
        &["گره"],
    );
}
#[test]
fn manifest_reports_figures_missing_from_translation() {
    contains(
        strict("journal.tex", "journal", "manifest-missing.txt"),
        &["missing-image", "fig-never.png"],
    );
}
#[test]
fn figure_check_rejects_unflattened_alpha() {
    let w = Work::new();
    let path = w.root.join("alpha.png");
    image::RgbaImage::from_pixel(4, 2, image::Rgba([0, 0, 0, 0]))
        .save(&path)
        .unwrap();
    let output = invoke(&[
        "figures".into(),
        path.display().to_string(),
        "--check".into(),
    ]);
    assert!(!output.success());
    assert!(text(&output).contains("alpha"));
    assert!(image::open(path).unwrap().color().has_alpha());
}
#[test]
fn figure_preparation_flattens_alpha_to_white_rgb() {
    let w = Work::new();
    let path = w.root.join("alpha.png");
    image::RgbaImage::from_pixel(4, 2, image::Rgba([0, 0, 0, 0]))
        .save(&path)
        .unwrap();
    clean(invoke(&["figures".into(), path.display().to_string()]));
    let image = image::open(path).unwrap();
    assert_eq!(image.color(), image::ColorType::Rgb8);
    assert!(!image.color().has_alpha());
    assert_eq!(image.to_rgb8().get_pixel(0, 0).0, [255, 255, 255]);
}
#[test]
fn build_requires_terms_before_engine_selection() {
    let w = Work::new();
    fs::remove_file(w.root.join("terms.tsv")).unwrap();
    let output = invoke(&w.args());
    assert!(!output.success());
    assert!(text(&output).contains("terms.tsv"));
    w.unchanged();
}
#[test]
fn crop_public_command_help_works() {
    let output = invoke(&strings(&["crop", "--help"]));
    assert!(output.success(), "{}", text(&output));
    assert!(text(&output).to_lowercase().contains("crop"));
}
#[test]
fn pages_public_command_help_works() {
    let output = invoke(&strings(&["pages", "--help"]));
    assert!(output.success(), "{}", text(&output));
    assert!(text(&output).to_lowercase().contains("page"));
}
#[test]
#[ignore = "requires prepared production Linux TeX container and effective containment"]
fn build_uses_actual_isolated_controller() -> Result<()> {
    let w = Work::new();
    w.compile("\\begin{latin}NativeControllerMarker\\end{latin}")?;
    assert_ne!(fs::read(&w.output)?, b"previous approved delivery");
    assert_eq!(fs::read(&w.output)?, fs::read(&w.working)?);
    Ok(())
}
#[test]
fn unavailable_explicit_container_preserves_delivery() {
    let w = Work::new();
    let stale = b"%PDF-1.7 stale working output\n%%EOF\n";
    fs::write(&w.working, stale).unwrap();
    let missing = w.root.join("missing-container");
    let output = invoke_environment(
        &w.args(),
        &[(
            "REVAYAT_CONTAINER_RUNTIME",
            missing.clone().into_os_string(),
        )],
    );
    assert!(!output.success());
    assert!(
        text(&output).contains("external tool is not available:"),
        "{}",
        text(&output)
    );
    assert!(text(&output).contains(missing.to_str().unwrap()));
    assert_eq!(fs::read(&w.working).unwrap(), stale);
    w.unchanged();
}
#[test]
fn failed_controller_cannot_deliver_stale_working_pdf() {
    build_checks::controller_mode("error").unwrap();
}
#[test]
fn failed_controller_cannot_deliver_valid_unsealed_pdf() {
    build_checks::controller_mode("failed-valid").unwrap();
}
#[test]
fn truncated_controller_output_is_not_publishable() {
    build_checks::controller_mode("truncated").unwrap();
}
#[test]
fn lint_gate_prevents_compiler_execution_and_delivery() {
    build_checks::tex_ledger_gate().unwrap();
    let w = Work::new();
    let source = w.root.join("bad.html");
    fs::write(&source,"<!doctype html><html lang=\"fa\" dir=\"rtl\"><head><style>pre{white-space:pre-wrap}</style></head><body><p>كتاب در دیوار آتش</p></body></html>").unwrap();
    let marker = w.root.join("engine-invoked");
    let output = invoke_environment(
        &strings(&[
            "build",
            source.to_str().unwrap(),
            "--engine",
            "chromium",
            "--browser",
            env!("CARGO_BIN_EXE_revayat-test-tool"),
            "--out",
            w.output.to_str().unwrap(),
        ]),
        &[(
            "REVAYAT_TEST_BROWSER_MARKER",
            marker.clone().into_os_string(),
        )],
    );
    assert!(!output.success());
    assert!(text(&output).contains("lint failed"), "{}", text(&output));
    assert!(!marker.exists());
    w.unchanged();
}
fn template_code() -> String {
    let source =
        fs::read_to_string(repo().join("skills/revayat-scientific/assets/rtl-document.tex"))
            .unwrap();
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with('%'))
        .collect::<Vec<_>>()
        .join("\n")
}
#[test]
fn monospace_template_retains_windows_fallback() {
    let live = template_code();
    assert!(live.contains(r"\setmonofont"));
    assert!(
        ["Consolas", "Courier New"]
            .iter()
            .any(|face| live.contains(face))
    );
}
#[test]
fn monospace_template_checks_consolas_before_cursor() {
    let live = template_code();
    let native = live
        .lines()
        .position(|line| line.contains("Consolas"))
        .unwrap();
    let fallback = live
        .lines()
        .position(|line| line.contains("TeX Gyre Cursor"))
        .unwrap();
    assert!(native < fallback);
}
#[test]
fn persian_font_chain_has_actual_static_regular_and_bold_faces() {
    let live = template_code();
    assert!(live.contains("\\settextfont"));
    assert!(
        ["Tahoma", "Segoe UI", "Arial"]
            .iter()
            .any(|face| live.contains(face))
    );
    let regular = read_fonts::FontRef::new(pdf_font::REGULAR).unwrap();
    let bold = read_fonts::FontRef::new(pdf_font::BOLD).unwrap();
    assert_eq!(regular.os2().unwrap().us_weight_class(), 400);
    assert_eq!(bold.os2().unwrap().us_weight_class(), 700);
    for c in "فارسیپژوهش".chars() {
        assert!(regular.cmap().unwrap().map_codepoint(c).is_some());
        assert!(bold.cmap().unwrap().map_codepoint(c).is_some());
    }
}
#[test]
fn latin_font_contract_has_western_ascii_glyphs() {
    let live = template_code();
    assert!(live.contains("\\setlatintextfont"));
    assert!(
        ["Times New Roman", "Cambria", "Arial"]
            .iter()
            .any(|face| live.contains(face))
    );
    for data in [pdf_font::REGULAR, pdf_font::BOLD] {
        let face = read_fonts::FontRef::new(data).unwrap();
        for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".chars() {
            assert!(face.cmap().unwrap().map_codepoint(c).is_some());
        }
    }
}
#[test]
#[ignore = "requires prepared production TeX image and native PDF font inspection"]
fn monospace_font_contract_renders_actual_code() -> Result<()> {
    let w = Work::new();
    w.compile("\\begin{latin}\\texttt{NativeCode\\_123}\\end{latin}")?;
    let output = revayat_scientific::pdf::pdf_text(&w.output)?;
    assert!(output.contains("NativeCode_123"), "{output}");
    Ok(())
}
#[test]
fn latin_font_selection_keeps_western_and_persian_digits_distinct() {
    let live = template_code();
    let native = live
        .lines()
        .position(|line| line.contains("Times New Roman"))
        .unwrap();
    let fallback = live
        .lines()
        .position(|line| line.contains("TeX Gyre Termes"))
        .unwrap();
    assert!(native < fallback);
    for data in [pdf_font::REGULAR, pdf_font::BOLD] {
        let face = read_fonts::FontRef::new(data).unwrap();
        for (western, persian) in "0123456789".chars().zip("۰۱۲۳۴۵۶۷۸۹".chars()) {
            assert_ne!(
                face.cmap().unwrap().map_codepoint(western),
                face.cmap().unwrap().map_codepoint(persian)
            );
        }
    }
    let live = tex::live_tex(
        &fs::read_to_string(repo().join("skills/revayat-scientific/assets/rtl-document.tex"))
            .unwrap(),
    )
    .unwrap();
    assert!(live.contains("mathdigits=default"));
}
#[test]
#[ignore = "requires prepared production TeX image and native Poppler font inspection"]
fn monospace_selection_uses_embedded_code_font() -> Result<()> {
    let w = Work::new();
    w.compile("\\begin{latin}\\texttt{Code\\_Token: 1234}\\end{latin}")?;
    let mut spec =
        revayat_scientific::runtime::CommandSpec::new("pdffonts").args([w.output.as_os_str()]);
    spec.timeout = std::time::Duration::from_secs(20);
    let output = revayat_scientific::runtime::run(&spec)?;
    assert!(output.success());
    let table = output.stdout_text();
    assert!(
        table.contains("Mono") || table.contains("Cursor") || table.contains("Consolas"),
        "{table}"
    );
    build::verify_font_table(&table)?;
    Ok(())
}
#[test]
fn local_static_font_files_precede_family_name_lookup() {
    let source =
        fs::read_to_string(repo().join("skills/revayat-scientific/assets/rtl-document.tex"))
            .unwrap();
    let live = tex::live_tex(&source).unwrap();
    assert!(live.find("fonts/Vazirmatn-Regular.ttf").unwrap() < live.find("{Vazirmatn}").unwrap());
    assert!(live.contains("BoldFont=Vazirmatn-Bold.ttf"));
    assert!(
        read_fonts::FontRef::new(pdf_font::REGULAR)
            .unwrap()
            .fvar()
            .is_err()
    );
    assert!(
        read_fonts::FontRef::new(pdf_font::BOLD)
            .unwrap()
            .fvar()
            .is_err()
    );
}
#[test]
fn native_diagnostics_remain_utf8_under_non_utf8_locale() {
    let output = invoke_environment(
        &strings(&[
            "lint",
            fixture("bad.tex").to_str().unwrap(),
            "--level",
            "system-docs",
        ]),
        &[("LC_ALL", "C".into())],
    );
    assert!(!output.success());
    let text = text(&output);
    assert!(text.contains("full-page-figure"));
    assert!(text.chars().any(|c| ('آ'..='ی').contains(&c)));
}
fn order(name: &str) -> Output {
    invoke(&[
        "text-order".into(),
        "--extracted".into(),
        fixture(name).display().to_string(),
        "--source".into(),
        fixture("good.tex").display().to_string(),
    ])
}
#[test]
fn text_order_reports_logical_dump() {
    let output = order("pdf-text-logical.txt");
    assert!(output.success(), "{}", text(&output));
    assert!(text(&output).contains("logical"));
}
#[test]
fn text_order_rejects_visual_dump() {
    let output = order("pdf-text-visual.txt");
    assert_eq!(Some(output.code), Some(2));
    assert!(text(&output).contains("visual"));
}
#[test]
fn text_order_rejects_visual_word_order() {
    let output = order("pdf-text-visual-words.txt");
    assert_eq!(Some(output.code), Some(2));
    assert!(text(&output).contains("visual"));
}
