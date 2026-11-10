//! Native ports of house/job terminology and source-local lint contracts.
use revayat_scientific::{
    lint::{self, LintOptions, Source},
    resource::ResourcePolicy,
    runtime::{self, CommandSpec},
    terms,
};
use std::{fs, path::PathBuf, time::Duration};
fn invoke(args: &[&str]) -> runtime::CommandOutput {
    let mut spec =
        CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific")).args(args.iter().copied());
    spec.timeout = Duration::from_secs(30);
    spec.max_output = 1024 * 1024;
    runtime::run(&spec).unwrap()
}
fn strings(paths: &[&std::path::Path]) -> Vec<String> {
    paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}
#[test]
fn test_multilingual_source_locations_and_ambiguity() {
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("source.txt");
    let ledger = d.path().join("terms.tsv");
    let text = "核融合 در متن اصلی.\nAbhängigkeit و nodes.\nnode\n";
    let data = "source\toutput\tstep\tcount\tforbidden_fa\tconcept\tstatus\tadmitted\tdeprecated\n核融合\tهمجوشی هسته‌ای\t3 subject-lexicon\t1\t\tphysics-fusion\tpreferred\t\t\nAbhängigkeit\tوابستگی\t3 subject-lexicon\t1\t\tdependency\tpreferred\t\t\nnode\tگره\t3 subject-lexicon\t1\t\tgraph-node\tpreferred\t\t\nnode\tراس\t3 subject-lexicon\t1\t\tgraph-vertex\tpreferred\t\t\nnode\tنامشخص\t3 subject-lexicon\t1\t\tundecided\t\t\t\nnodes\tگره‌ها\t3 subject-lexicon\t1\t\tgraph-nodes\trejected\t\t\n";
    fs::write(&source, text).unwrap();
    fs::write(&ledger, data).unwrap();
    let paths = strings(&[&source, &ledger]);
    let result = invoke(&[
        "term-brief",
        &paths[0],
        "--terms",
        &paths[1],
        "--language",
        "ja",
    ]);
    assert!(
        result.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: terms::Brief = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report.source_language, "ja");
    assert_eq!(
        report.source_sha256,
        revayat_scientific::resource::sha256(text.as_bytes())
    );
    assert_eq!(
        report.terms_sha256,
        revayat_scientific::resource::sha256(data.as_bytes())
    );
    assert_eq!(
        report
            .terms
            .iter()
            .map(|r| (r.source.as_str(), r.locations[0].line))
            .collect::<Vec<_>>(),
        [("核融合", 1), ("Abhängigkeit", 2), ("node", 3), ("node", 3)]
    );
    assert!(report.terms[2..].iter().all(|r| r.ambiguous));
    assert_eq!(fs::read_to_string(source).unwrap(), text);
    assert_eq!(fs::read_to_string(ledger).unwrap(), data);
}
#[test]
fn test_missing_malformed_or_binary_inputs_fail_without_mutation() {
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("source.txt");
    let ledger = d.path().join("terms.tsv");
    fs::write(&source, "علوم داده").unwrap();
    fs::write(
        &ledger,
        "source\toutput\tstep\tcount\tforbidden_fa\nعلوم داده\tعلم داده\n",
    )
    .unwrap();
    assert!(terms::term_brief(&source, &ledger, "fa").is_err());
    assert!(terms::term_brief(&source, &d.path().join("missing.tsv"), "fa").is_err());
    for selected in [&ledger, &d.path().join("missing.tsv")] {
        let paths = strings(&[&source, selected]);
        assert!(
            !invoke(&[
                "term-brief",
                &paths[0],
                "--terms",
                &paths[1],
                "--language",
                "fa"
            ])
            .success()
        );
    }
    fs::write(&ledger, "source\toutput\n").unwrap();
    fs::write(&source, b"%PDF-1.7\n").unwrap();
    assert!(terms::term_brief(&source, &ledger, "fa").is_err());
    let paths = strings(&[&source, &ledger]);
    assert!(
        !invoke(&[
            "term-brief",
            &paths[0],
            "--terms",
            &paths[1],
            "--language",
            "fa"
        ])
        .success()
    );
    assert_eq!(fs::read(source).unwrap(), b"%PDF-1.7\n");
}
#[test]
fn test_house_pairs_allow_english_as_a_real_data_term() {
    for header in ["", "english\tforbidden_fa\tscope\tlevels\n"] {
        let rows = terms::parse_pairs(
            &format!("\u{feff}{header}english\tانگلیسی\tuniversal\tall\n"),
            "journal",
        )
        .unwrap();
        assert_eq!(
            rows,
            [("english".into(), "انگلیسی".into(), "universal".into())]
        );
    }
}
#[test]
fn test_duplicate_house_header_is_not_a_term_or_silent_reset() {
    assert!(
        terms::parse_pairs(
            "english\tforbidden_fa\tscope\nnode\tگره\tuniversal\nenglish\tforbidden_fa\tscope\n",
            "journal"
        )
        .is_err()
    );
}
#[test]
fn test_cli_rejects_malformed_ledger_without_changing_inputs() {
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("source.tex");
    let ledger = d.path().join("terms.tsv");
    let text = "\\begin{document}متن درست\\end{document}";
    let data = "source\toutput\tstep\tcount\tforbidden_fa\nnode\tگره\n";
    fs::write(&source, text).unwrap();
    fs::write(&ledger, data).unwrap();
    let p = strings(&[&source, &ledger]);
    let result = invoke(&["lint", &p[0], "--terms", &p[1], "--level", "journal"]);
    assert_eq!(
        result.code,
        2,
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read_to_string(source).unwrap(), text);
    assert_eq!(fs::read_to_string(ledger).unwrap(), data);
}
#[test]
fn test_job_sidecars_are_independent_of_argument_order() {
    let d = tempfile::tempdir().unwrap();
    let mut sources = Vec::new();
    for (name, text, forbidden) in [("a", "واژه", "نمونه"), ("b", "نمونه", "داده")]
    {
        let job = d.path().join(name);
        fs::create_dir(&job).unwrap();
        let source = job.join("main.tex");
        fs::write(
            &source,
            format!("\\begin{{document}}\n{text}\n\\end{{document}}"),
        )
        .unwrap();
        fs::write(
            job.join("terms.tsv"),
            format!(
                "source\toutput\tstep\tcount\tforbidden_fa\nWidget\tWidget\tkeep\t1\t{forbidden}\n"
            ),
        )
        .unwrap();
        fs::write(job.join("manifest.txt"), "").unwrap();
        sources.push(source);
    }
    for order in [sources.clone(), sources.iter().rev().cloned().collect()] {
        let mut args = vec!["lint".to_owned()];
        args.extend(
            order
                .iter()
                .map(|p: &PathBuf| p.to_string_lossy().into_owned()),
        );
        args.extend(["--level".into(), "journal".into(), "--strict".into()]);
        let borrowed = args.iter().map(String::as_str).collect::<Vec<_>>();
        let result = invoke(&borrowed);
        assert!(
            result.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let opt = LintOptions {
        pairs: Some(d.path().join("missing.tsv")),
        ..LintOptions::default()
    };
    assert!(lint::lint_file(&sources[0], &opt).is_err());
    let sidecar = opt.pairs.as_ref().unwrap();
    assert_eq!(
        invoke(&[
            "lint",
            sources[0].to_str().unwrap(),
            "--pairs",
            sidecar.to_str().unwrap(),
        ])
        .code,
        2
    );
    fs::write(sidecar, "malformed\trow\n").unwrap();
    assert!(lint::lint_file(&sources[0], &opt).is_err());
    assert_eq!(
        invoke(&[
            "lint",
            sources[0].to_str().unwrap(),
            "--pairs",
            sidecar.to_str().unwrap(),
        ])
        .code,
        2
    );
    let md = d.path().join("notes.md");
    fs::write(&md, "text").unwrap();
    assert!(lint::lint_file(&md, &LintOptions::default()).is_err());
    assert_eq!(invoke(&["lint", md.to_str().unwrap()]).code, 2);
}
#[test]
fn test_journal_names_and_foreign_original_identity_are_preserved() {
    let d = tempfile::tempdir().unwrap();
    let tex = d.path().join("name.tex");
    fs::write(&tex, "\\begin{document}\nخوشه \\en{Abell}\n\\end{document}").unwrap();
    let html = d.path().join("original.html");
    fs::write(&html,"<html lang=\"fa\" dir=\"rtl\"><p lang=\"fr\" dir=\"ltr\">Les particules</p><p>عنوان <cite dir=\"ltr\" lang=\"en\">Deep Residual Networks</cite></p></html>").unwrap();
    for p in [tex, html] {
        let found = lint::lint_file(
            &p,
            &LintOptions {
                level: "journal".into(),
                ..LintOptions::default()
            },
        )
        .unwrap();
        assert!(found.is_empty(), "{found:?}");
        assert!(invoke(&["lint", p.to_str().unwrap(), "--level", "journal"]).success());
    }
}
#[test]
fn test_journal_terms_and_scoped_original_quote() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("journal.tex");
    let text = "\\begin{document}\nپیاده‌سازی مرجع ارائه می‌شود.\n% fa-lint: allow arabic-letters\nكتاب علمي\n\nاین متن فارسی است.\n\\end{document}\n";
    fs::write(&p, text).unwrap();
    let opts = LintOptions {
        level: "journal".into(),
        ..LintOptions::default()
    };
    assert!(lint::lint_file(&p, &opts).unwrap().is_empty());
    assert!(invoke(&["lint", p.to_str().unwrap(), "--level", "journal"]).success());
    let operational = invoke(&["lint", p.to_str().unwrap(), "--level", "system-docs"]);
    assert_eq!(operational.code, 1);
    assert!(String::from_utf8_lossy(&operational.stdout).contains("forbidden-fa"));
    assert!(
        lint::lint_file(&p, &LintOptions::default())
            .unwrap()
            .iter()
            .any(|f| f.check == "forbidden-fa")
    );
    fs::write(
        &p,
        text.replace(
            "این متن فارسی است.",
            "اين متن فارسی است.\n\\begin{LTR}\n\\includegraphics{missing.png}\n\\end{LTR}",
        ),
    )
    .unwrap();
    let findings = lint::lint_file(&p, &opts).unwrap();
    assert!(findings.iter().any(|f| f.check == "arabic-letters"));
    assert!(findings.iter().any(|f| f.check == "missing-image"));
    let broken = invoke(&["lint", p.to_str().unwrap(), "--level", "journal"]);
    assert_eq!(broken.code, 1);
    let output = String::from_utf8_lossy(&broken.stdout);
    assert!(output.contains("arabic-letters"));
    assert!(output.contains("missing-image"));
}
include!("native_terms_lint/listing.rs");
#[test]
fn test_fetch_allows_job_assets_and_denies_outside_network_and_attachments() {
    let d = tempfile::tempdir().unwrap();
    let job = d.path().join("job");
    fs::create_dir(&job).unwrap();
    let source = job.join("doc.html");
    fs::write(&source, "<html></html>").unwrap();
    fs::write(job.join("style.css"), "p { color: black }").unwrap();
    let sentinel = d.path().join("outside.css");
    fs::write(&sentinel, "private sentinel").unwrap();
    let mut p = ResourcePolicy::new(&source).unwrap();
    let (data, mime) = p.fetch("https://revayat.invalid/style.css").unwrap();
    assert_eq!(data, b"p { color: black }");
    assert_eq!(mime, "text/css");
    for url in [
        url::Url::from_file_path(sentinel).unwrap().to_string(),
        "https://example.com/style.css".into(),
        "https://revayat.invalid/../outside.css".into(),
    ] {
        assert!(p.fetch(&url).is_err(), "{url}");
    }
    assert!(p.denied);
    fs::write(
        &source,
        "<html><a rel=\"attachment\" href=\"style.css\">x</a></html>",
    )
    .unwrap();
    assert!(
        ResourcePolicy::new(&source)
            .unwrap_err()
            .to_string()
            .contains("attachment")
    );
}
#[test]
fn test_head_before_ltr_isolate_keeps_half_translation_check() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("source.html");
    for body in [
        "<p>خوشه <span dir=\"ltr\">Kubernetes</span></p>",
        "<p>خوشه <bdi dir=\"ltr\">Kubernetes</bdi></p>",
    ] {
        fs::write(
            &p,
            format!("<html lang=\"fa\" dir=\"rtl\"><body>\n{body}\n</body></html>"),
        )
        .unwrap();
        let s = Source::load(&p).unwrap();
        let found = lint::check(&s, &[], None, "system-docs").unwrap();
        let half: Vec<_> = found
            .iter()
            .filter(|f| f.check == "half-translation")
            .collect();
        assert_eq!(half.len(), 1);
        assert_eq!(half[0].line, 2);
        assert!(
            !lint::check(&s, &[], None, "journal")
                .unwrap()
                .iter()
                .any(|f| f.check == "half-translation")
        );
    }
}
#[test]
fn test_inline_formatting_does_not_hide_visible_phrase() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("source.html");
    let pairs = vec![("firewall".into(), "دیوار آتش".into(), "fixture".into())];
    for (body, count) in [
        ("<p>دیوار <b>آتش</b></p>", 1),
        ("<p><em>دیوار</em> آتش</p>", 1),
        ("<p>دیوار &#1570;<strong>تش</strong></p>", 1),
        ("<p>دیوار <span>آتش</span></p>", 1),
        ("<p>دی<b>وار</b> آتش</p>", 1),
        ("<p>دیوار آتش</p>", 1),
        ("<p>دیوار</p><p>آتش</p>", 0),
        ("<p>دیوار <span lang=\"en\">آتش</span></p>", 0),
        ("<p>دیوار <code>آتش</code></p>", 0),
        ("<p>دیوار <q>آتش</q></p>", 0),
        ("<p>دیوار <span hidden>واسط</span>آتش</p>", 0),
        (
            "<!-- fa-lint: allow forbidden-fa -->\n<p>دیوار <b>آتش</b></p>",
            0,
        ),
    ] {
        fs::write(
            &p,
            format!("<html lang=\"fa\" dir=\"rtl\"><body>\n{body}\n</body></html>"),
        )
        .unwrap();
        let found = lint::check(&Source::load(&p).unwrap(), &pairs, None, "system-docs").unwrap();
        let hits: Vec<_> = found.iter().filter(|f| f.check == "forbidden-fa").collect();
        assert_eq!(hits.len(), count, "{body}: {hits:?}");
        if count == 1 {
            assert_eq!((&hits[0].path, hits[0].line), (&p, 2));
        }
    }
}
#[test]
fn test_live_root_entities_and_comment_only_waivers() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("doc.html");
    for (body, diagnostic) in [
        (
            "<html dir=\"rtl\" lang=\"fa\"><style>p{color:black}</style>متن</html>",
            None,
        ),
        (
            "<!-- <html lang=\"fa\" dir=\"rtl\"> --><html lang=\"en\">متن</html>",
            Some("html-root"),
        ),
        (
            "<html lang=\"fa\" dir=\"rtl\"><p>&#1603;</p></html>",
            Some("arabic-letters"),
        ),
        (
            "<html lang=\"fa\" dir=\"rtl\"><p>گ&#1585;ه</p></html>",
            Some("forbidden-fa"),
        ),
        (
            "<html lang=\"fa\" dir=\"rtl\"><p data-note=\"fa-lint: allow all\">كتاب</p></html>",
            Some("arabic-letters"),
        ),
        (
            "<html lang=\"fa\" dir=\"rtl\">\n<!-- fa-lint: allow arabic-letters -->\nكتاب</html>",
            None,
        ),
        (
            "<html lang=\"fa\" dir=\"rtl\"><style>pre{white-space:pre-wrap}</style><pre dir=\"ltr\">services</pre></html>",
            None,
        ),
        (
            "<html lang=\"fa\" dir=\"rtl\"><style>code{white-space:pre-wrap}</style><code class=\"ltr\"><span dir=\"ltr\">services</span></code></html>",
            None,
        ),
        (
            "<html lang=\"fa\" dir=\"rtl\"><style>code{white-space:pre-wrap}</style><span dir=\"ltr\">value <code>services</code></span></html>",
            None,
        ),
        (
            "<html lang=\"fa\" dir=\"rtl\"><span dir=\"ltr\">services</span></html>",
            Some("en-plural"),
        ),
    ] {
        fs::write(&p, body).unwrap();
        let f = lint::lint_file(&p, &LintOptions::default()).unwrap();
        let result = invoke(&["lint", p.to_str().unwrap()]);
        assert_eq!(result.code, i32::from(diagnostic.is_some()));
        if let Some(id) = diagnostic {
            assert!(f.iter().any(|f| f.check == id), "{id}: {f:?}");
            assert!(String::from_utf8_lossy(&result.stdout).contains(id));
        } else {
            assert!(f.is_empty(), "{body}: {f:?}");
            assert!(!String::from_utf8_lossy(&result.stdout).contains("print-css"));
        }
    }
}
#[test]
fn test_encoded_and_starred_assets_share_lint_and_build_resolution() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("figures")).unwrap();
    fs::create_dir(d.path().join("chapters")).unwrap();
    let image = d.path().join("figures/figure one.png");
    image::RgbaImage::from_pixel(8, 8, image::Rgba([100, 120, 140, 128]))
        .save(&image)
        .unwrap();
    let html = d.path().join("main.html");
    let tex = d.path().join("main.tex");
    fs::write(
        &html,
        "<html lang=\"fa\" dir=\"rtl\"><img dir=\"ltr\" src=\"figures/figure%20one.png\"></html>",
    )
    .unwrap();
    fs::write(
        &tex,
        "\\begin{document}\\input{chapters/one}\\end{document}",
    )
    .unwrap();
    fs::write(
        d.path().join("chapters/one.tex"),
        "\\begin{LTR}\\includegraphics* [width=2cm] {figures/figure one.png}\\end{LTR}",
    )
    .unwrap();
    for p in [&html, &tex] {
        let s = Source::load(p).unwrap();
        assert!(
            lint::check(&s, &[], Some(&["figure one.png".into()]), "journal")
                .unwrap()
                .is_empty()
        );
        let refs = s.image_references();
        assert_eq!(refs.len(), 1);
        assert_eq!(
            lint::resolve_asset(d.path(), &refs[0].1).unwrap(),
            image.canonicalize().unwrap()
        );
        let inputs = revayat_scientific::build::document_inputs(p, &[], None).unwrap();
        let sources = [
            p.canonicalize().unwrap(),
            d.path().join("chapters/one.tex").canonicalize().unwrap(),
        ];
        let assets = inputs
            .into_iter()
            .filter(|path| !sources.contains(path))
            .collect::<Vec<_>>();
        assert_eq!(assets, vec![image.canonicalize().unwrap()]);
        assert!(revayat_scientific::build::validate_assets(p).is_err());
        assert!(
            revayat_scientific::images::inspect(&image)
                .unwrap()
                .requires_review
        );
        assert_eq!(
            invoke(&["figures", "--check", image.to_str().unwrap()]).code,
            1
        );
    }
    image::RgbImage::from_pixel(8, 8, image::Rgb([255, 255, 255]))
        .save(&image)
        .unwrap();
    assert!(
        !revayat_scientific::images::inspect(&image)
            .unwrap()
            .requires_review
    );
    assert_eq!(
        invoke(&["figures", "--check", image.to_str().unwrap()]).code,
        0
    );
    revayat_scientific::build::validate_assets(&tex).unwrap();
    fs::remove_file(&image).unwrap();
    for p in [&html, &tex] {
        let found = lint::check(
            &Source::load(p).unwrap(),
            &[],
            Some(&["figure one.png".into()]),
            "journal",
        )
        .unwrap();
        assert!(found.iter().any(|f| f.check == "missing-image"));
        assert!(revayat_scientific::build::document_inputs(p, &[], None).is_err());
        assert!(revayat_scientific::build::validate_assets(p).is_err());
    }
}
#[test]
fn resource_snapshots_and_sticky_denials_survive_source_changes() {
    let d = tempfile::tempdir().unwrap();
    let s = d.path().join("doc.html");
    fs::write(&s, "<html>original</html>").unwrap();
    fs::write(d.path().join("asset.css"), "original").unwrap();
    let mut p = ResourcePolicy::new(&s).unwrap();
    p.fetch("https://revayat.invalid/asset.css").unwrap();
    fs::write(&s, "changed source").unwrap();
    assert_eq!(
        p.fetch("https://revayat.invalid/doc.html").unwrap().0,
        b"<html>original</html>"
    );
    fs::write(d.path().join("asset.css"), "changed").unwrap();
    assert!(p.fetch("https://revayat.invalid/asset.css").is_err());
    assert!(p.denied);
    assert!(p.fetch("https://revayat.invalid/doc.html").is_ok());
    assert!(p.denied);
}
#[test]
fn resource_embedded_types_base64_and_url_authorities_are_strict() {
    let d = tempfile::tempdir().unwrap();
    let s = d.path().join("doc.html");
    fs::write(&s, "<html></html>").unwrap();
    let mut p = ResourcePolicy::new(&s).unwrap();
    assert_eq!(p.fetch("data:image/png;base64,YWJj").unwrap().0, b"abc");
    assert_eq!(
        p.fetch("data:image/svg+xml,%3Csvg%3E%3C/svg%3E").unwrap().0,
        b"<svg></svg>"
    );
    for u in [
        "data:text/html,hello",
        "data:image/png;base64,!!!",
        "https://revayat.invalid:443/doc.html",
        "https://x@revayat.invalid/doc.html",
        "file://evil/doc.html",
        "https://revayat.invalid/%00.css",
    ] {
        assert!(p.fetch(u).is_err(), "{u}");
    }
}
#[test]
fn resource_count_and_byte_budgets_are_enforced_before_publication() {
    let d = tempfile::tempdir().unwrap();
    let s = d.path().join("doc.html");
    fs::write(&s, "<html></html>").unwrap();
    let mut p = ResourcePolicy::new(&s).unwrap();
    p.requests = 2048;
    assert!(p.fetch("https://revayat.invalid/doc.html").is_err());
    let mut p = ResourcePolicy::new(&s).unwrap();
    p.total = revayat_scientific::resource::MAX_TOTAL_BYTES;
    assert!(p.fetch("https://revayat.invalid/doc.html").is_err());
    assert!(p.denied);
}
#[test]
fn term_brief_bounds_and_persian_columns_are_explicit() {
    let rows = terms::approved_rows("source\toutput\nnode\tگره\n").unwrap();
    let hits = terms::candidate_brief(&format!("متن node {}", "node ".repeat(70)), rows).unwrap();
    assert_eq!(hits[0].locations[0].column, 5);
    assert_eq!(hits[0].locations.len(), 64);
    assert!(hits[0].more_matches);
    assert!(terms::approved_rows("source\toutput\n").unwrap().is_empty());
    let data = format!(
        "source\toutput\n{}",
        (0..513)
            .map(|i| format!("node{i}\tگره\n"))
            .collect::<String>()
    );
    assert!(terms::approved_rows(&data).is_err());
}

#[test]
fn embedded_binary_images_allow_percent_encoded_zero_without_allowing_nul_paths() {
    let d = tempfile::tempdir().unwrap();
    let s = d.path().join("doc.html");
    fs::write(&s, "<html></html>").unwrap();
    let mut p = ResourcePolicy::new(&s).unwrap();
    assert_eq!(p.fetch("data:image/png,%89PNG%00").unwrap().0, b"\x89PNG\0");
    assert!(p.fetch("https://revayat.invalid/image%00.png").is_err());
}

#[test]
fn multilingual_ambiguity_uses_full_unicode_casefold() {
    let rows = terms::approved_rows(
        "source\toutput\tconcept\nStraße\tخیابان\troad\nSTRASSE\tمسیر\tpath\n",
    )
    .unwrap();
    let hits = terms::candidate_brief("Straße STRASSE", rows).unwrap();
    assert_eq!(hits.len(), 2);
    assert!(hits.iter().all(|r| r.ambiguous));
}
