use revayat_scientific::tex::{SourceClosure, plain_tex, source_closure};
use revayat_scientific::text_order::source_plain;
use std::{fs, path::Path};

fn closure_plain(closure: &SourceClosure) -> anyhow::Result<String> {
    closure.plain_text()
}

#[derive(Clone, Copy, Debug)]
enum Placement {
    Direct,
    IncludedDefinition,
    InheritedBody,
}

fn observe(
    label: &str,
    replacement: &str,
    outside_math: &str,
    placement: Placement,
    keep_replacement_marker: bool,
    failures: &mut Vec<String>,
) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    let declaration = format!("\\newcommand{{\\sample}}{{{replacement}}}");
    let candidate = match placement {
        Placement::Direct => declaration,
        Placement::IncludedDefinition => {
            fs::write(root.join("data.tex"), declaration).unwrap();
            r"\input{data}".to_owned()
        }
        Placement::InheritedBody => {
            fs::write(root.join("data.tex"), replacement).unwrap();
            r"\newcommand{\sample}{\input{data}}".to_owned()
        }
    };
    let text = format!(
        "\\documentclass{{article}}\n\\usepackage{{amsmath}}\n\\usepackage{{xepersian}}\n\\begin{{document}}\nBeforeMarker {candidate} OutsideVisible {outside_math} TailMarker\n\\end{{document}}\n"
    );
    fs::write(&main, text).unwrap();
    observe_file(label, &main, placement, keep_replacement_marker, failures);
}

fn observe_file(
    label: &str,
    main: &Path,
    placement: Placement,
    keep_replacement_marker: bool,
    failures: &mut Vec<String>,
) {
    let closure = source_closure(main, None).unwrap();
    let expected_sources = if matches!(placement, Placement::Direct) {
        1
    } else {
        2
    };
    assert_eq!(
        closure.sources.len(),
        expected_sources,
        "{label}: fixture not reached"
    );
    for (route, result) in [
        ("closure", closure_plain(&closure)),
        ("production", source_plain(main)),
        ("standalone-expanded", plain_tex(&closure.text)),
    ] {
        match result {
            Ok(plain)
                if plain.contains("BeforeMarker")
                    && plain.contains("OutsideVisible")
                    && plain.contains("TailMarker")
                    && !plain.contains("MathOnly")
                    && (!keep_replacement_marker || plain.contains("RetainedBody")) => {}
            actual => failures.push(format!("{label}/{placement:?}/{route}: {actual:?}")),
        }
    }
}

#[test]
fn review_literal_dollar_preserves_external_prose_and_real_math_exclusion() {
    let mut failures = Vec::new();
    for placement in [
        Placement::Direct,
        Placement::IncludedDefinition,
        Placement::InheritedBody,
    ] {
        observe(
            "review-literal-dollar",
            r"\verb|$|",
            "$MathOnly$",
            placement,
            false,
            &mut failures,
        );
        observe(
            "ordinary-body-control",
            "RetainedBody",
            "$MathOnly$",
            placement,
            true,
            &mut failures,
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn owned_math_and_environment_openers_cannot_pair_with_external_closers() {
    let mut failures = Vec::new();
    for placement in [Placement::Direct, Placement::InheritedBody] {
        for (open, close) in [("$", "$"), ("$$", "$$"), (r"\(", r"\)"), (r"\[", r"\]")] {
            let outside = format!("{open}MathOnly{close}");
            observe(
                &format!("owned-delimiter-{open}"),
                open,
                &outside,
                placement,
                false,
                &mut failures,
            );
            observe(
                &format!("live-delimiter-control-{open}"),
                "RetainedBody",
                &outside,
                placement,
                true,
                &mut failures,
            );
        }
        for environment in [
            "latin",
            "equation",
            "equation*",
            "align",
            "align*",
            "displaymath",
            "math",
        ] {
            let open = format!("\\begin{{{environment}}}");
            let outside = format!("{open}MathOnly\\end{{{environment}}}");
            observe(
                &format!("owned-environment-{environment}"),
                &open,
                &outside,
                placement,
                false,
                &mut failures,
            );
            observe(
                &format!("live-environment-control-{environment}"),
                "RetainedBody",
                &outside,
                placement,
                true,
                &mut failures,
            );
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn raw_body_comments_literals_and_unrelated_math_keep_existing_contracts() {
    let mut failures = Vec::new();
    for placement in [Placement::Direct, Placement::InheritedBody] {
        for (label, body, outside) in [
            ("plain-body", "RetainedBody", ""),
            ("unmatched-dollar-no-external-math", "RetainedBody$", ""),
            ("paired-owned-math", "$MathOnly$ RetainedBody", "$MathOnly$"),
            ("comment-dollar", "RetainedBody% $\n", "$MathOnly$"),
            ("escaped-dollar", r"RetainedBody\$", "$MathOnly$"),
            (
                "ordinary-literal-dollar",
                "RetainedBody",
                r"\verb|$| $MathOnly$",
            ),
        ] {
            observe(label, body, outside, placement, true, &mut failures);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn live_pairs_cross_unused_definitions_without_borrowing_owned_closers() {
    let mut pairs: Vec<(String, String)> =
        [("$", "$"), ("$$", "$$"), (r"\(", r"\)"), (r"\[", r"\]")]
            .into_iter()
            .map(|(open, close)| (open.to_owned(), close.to_owned()))
            .collect();
    pairs.extend(
        [
            "latin",
            "equation",
            "equation*",
            "align",
            "align*",
            "displaymath",
            "math",
        ]
        .into_iter()
        .map(|name| (format!("\\begin{{{name}}}"), format!("\\end{{{name}}}"))),
    );
    let mut failures = Vec::new();
    for placement in [Placement::Direct, Placement::InheritedBody] {
        for (open, close) in &pairs {
            for replacement in ["RetainedBody", close.as_str()] {
                let directory = tempfile::tempdir().unwrap();
                let root = directory.path().canonicalize().unwrap();
                let main = root.join("main.tex");
                let declaration = if matches!(placement, Placement::Direct) {
                    format!("\\newcommand{{\\sample}}{{{replacement}}}")
                } else {
                    fs::write(root.join("data.tex"), replacement).unwrap();
                    r"\newcommand{\sample}{\input{data}}".to_owned()
                };
                fs::write(&main, format!("\\documentclass{{article}}\n\\usepackage{{amsmath}}\n\\usepackage{{xepersian}}\n\\begin{{document}}\nBeforeMarker {open}MathOnly {declaration} MathOnly{close} OutsideVisible TailMarker\n\\end{{document}}\n")).unwrap();
                observe_file(
                    &format!("crossing-{open}-owned-{replacement}"),
                    &main,
                    placement,
                    false,
                    &mut failures,
                );
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn adjacent_declarations_keep_separate_owners_after_eof_continuation() {
    for continued in [false, true] {
        for (open, close) in [("$", "$"), (r"\(", r"\)"), (r"\begin{math}", r"\end{math}")] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let main = root.join("main.tex");
            let second = if continued {
                fs::write(root.join("data.tex"), r"\newcommand").unwrap();
                format!("\\input data \\second{{SecondKeep{close}}}")
            } else {
                format!("\\newcommand{{\\second}}{{SecondKeep{close}}}")
            };
            fs::write(&main, format!("\\begin{{document}}\\newcommand{{\\first}}{{{open}FirstKeep}}{second} OutsideVisible $MathOnly$ TailMarker\\end{{document}}")).unwrap();
            let closure = source_closure(&main, None).unwrap();
            for (route, result) in [
                ("closure", closure.plain_text()),
                ("production", source_plain(&main)),
                ("standalone-expanded", plain_tex(&closure.text)),
            ] {
                let plain = result.unwrap();
                for marker in ["FirstKeep", "SecondKeep", "OutsideVisible", "TailMarker"] {
                    assert!(
                        plain.contains(marker),
                        "continued={continued}, pair={open}, route={route}: {plain}"
                    );
                }
                assert!(!plain.contains("MathOnly"), "{plain}");
            }
        }
    }
}

#[test]
fn one_owner_keeps_math_pairing_across_conservative_include_segments() {
    let mut pairs: Vec<(String, String)> =
        [("$", "$"), ("$$", "$$"), (r"\(", r"\)"), (r"\[", r"\]")]
            .into_iter()
            .map(|(open, close)| (open.to_owned(), close.to_owned()))
            .collect();
    pairs.extend(
        [
            "latin",
            "equation",
            "equation*",
            "align",
            "align*",
            "displaymath",
            "math",
        ]
        .into_iter()
        .map(|name| (format!("\\begin{{{name}}}"), format!("\\end{{{name}}}"))),
    );
    for (open, close) in pairs {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let main = root.join("main.tex");
        fs::write(root.join("data.tex"), "MathOnly").unwrap();
        fs::write(&main, format!("\\begin{{document}}BeforeMarker \\newcommand{{\\sample}}{{{open}\\input{{data}}{close} RetainedBody}} OutsideVisible TailMarker\\end{{document}}")).unwrap();
        let mut failures = Vec::new();
        observe_file(&open, &main, Placement::InheritedBody, true, &mut failures);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}

#[test]
fn public_snapshot_fallback_preserves_adjacent_owner_boundaries() {
    use revayat_scientific::tex::{Segment, Snapshot};
    use std::sync::Arc;
    let text = "\\begin{document}پیش \\newcommand{\\first}{$FirstKeep}\\newcommand{\\second}{SecondKeep$} OutsideVisible $MathOnly$ TailMarker\\end{document}";
    for step in [1, 7, 31] {
        let path = std::path::PathBuf::from("main.tex");
        let snapshot = Arc::new(Snapshot::new(path.clone(), Arc::from(text)).unwrap());
        let closure = SourceClosure {
            text: text.to_owned(),
            segments: (0..text.len())
                .step_by(step)
                .map(|start| Segment {
                    start,
                    original_offset: start,
                    snapshot: snapshot.clone(),
                })
                .collect(),
            sources: vec![path],
        };
        let plain = closure.plain_text().unwrap();
        for marker in [
            "پیش",
            "FirstKeep",
            "SecondKeep",
            "OutsideVisible",
            "TailMarker",
        ] {
            assert!(plain.contains(marker), "step={step}: {plain}");
        }
        assert!(!plain.contains("MathOnly"), "{plain}");
    }
}

#[test]
fn dense_valid_owners_keep_extraction_and_math_exclusion_compatible() {
    let count = 4096;
    let declarations = r"\renewcommand{\sample}{$MathOnly$ RetainedBody}".repeat(count);
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    let text = format!(
        "\\newcommand{{\\sample}}{{Initial}}\n\\begin{{document}}BeforeMarker{declarations} OutsideVisible $MathOnly$ TailMarker\\end{{document}}"
    );
    fs::write(&main, &text).unwrap();
    let closure = source_closure(&main, None).unwrap();
    for plain in [
        closure.plain_text().unwrap(),
        source_plain(&main).unwrap(),
        plain_tex(&text).unwrap(),
    ] {
        assert_eq!(plain.matches("RetainedBody").count(), count);
        assert!(
            plain.contains("BeforeMarker")
                && plain.contains("OutsideVisible")
                && plain.contains("TailMarker")
        );
        assert!(!plain.contains("MathOnly"));
    }
}

#[test]
fn escaped_math_tokens_preserve_live_and_owned_delimiter_boundaries() {
    for (source, expected) in [
        (r"Before $MathOnly \$ MoreMath$ Tail", "Before Tail"),
        (r"Before $$MathOnly \$ MoreMath$$ Tail", "Before Tail"),
        (r"Before \(MathOnly \$ MoreMath\) Tail", "Before Tail"),
        (r"Before \$ Tail", "Before $ Tail"),
        (r"Before \$$MathOnly$ Tail", "Before $ Tail"),
        (r"Before \$$$MathOnly$$ Tail", "Before $ Tail"),
        (r"Before $$MathOnly \$$$ Tail", "Before Tail"),
        (
            r"\newcommand{\sample}{$MathOnly \$ MoreMath$ RetainedBody} Before $RealMath$ Tail",
            "RetainedBody Before Tail",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let main = root.join("main.tex");
        fs::write(&main, source).unwrap();
        let closure = source_closure(&main, None).unwrap();
        for (route, actual) in [
            ("closure", closure.plain_text()),
            ("production", source_plain(&main)),
            ("standalone", plain_tex(source)),
        ] {
            assert_eq!(actual.unwrap(), expected, "route={route}, source={source}");
        }
    }
}
