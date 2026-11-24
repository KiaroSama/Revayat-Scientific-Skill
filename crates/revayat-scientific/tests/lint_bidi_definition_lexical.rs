use revayat_scientific::lint::{self, Source};
use revayat_scientific::tex::plain_tex;
use revayat_scientific::text_order::source_plain;
use std::fs;

fn observe(
    label: &str,
    child: Option<&str>,
    preamble: &str,
    candidate: &str,
    owns_end: bool,
    allow_malformed_plain: bool,
    failures: &mut Vec<String>,
) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    if let Some(child) = child {
        fs::write(root.join("declaration.tex"), child).unwrap();
    }
    let tail = if owns_end {
        "\nExpectedTail\n\\end{document}\n\\input{missing-after-real-end}\n"
    } else {
        "\n\\input{missing-after-real-end}\nUnexpectedTail\n\\end{document}\n"
    };
    fs::write(&main, format!("\\documentclass{{article}}\n{preamble}\n\\begin{{document}}\n\u{2067}VisibleBefore\\par after\u{2069}\n{candidate}{tail}")).unwrap();
    assert!(!root.join("missing-after-real-end.tex").exists());
    match Source::load(&main) {
        Ok(source) => {
            let Source::Tex(model) = &source else {
                unreachable!()
            };
            let expected_sources = if child.is_some() {
                vec![main.clone(), root.join("declaration.tex")]
            } else {
                vec![main.clone()]
            };
            if model.closure.sources != expected_sources {
                failures.push(format!(
                    "{label}: wrong admitted sources: {:?}",
                    model.closure.sources
                ));
            }
            let actual: Vec<_> = lint::check(&source, &[], None, "system-docs")
                .unwrap()
                .into_iter()
                .filter(|finding| finding.check == "bidi-isolate")
                .map(|finding| (finding.path, finding.line))
                .collect();
            if actual != [(main.clone(), 4), (main.clone(), 4)] {
                failures.push(format!(
                    "{label}: expected two live findings at main:4, got {actual:?}"
                ));
            }
        }
        Err(error) => failures.push(format!(
            "{label}: source loading crossed the real end: {error:#}"
        )),
    }
    match source_plain(&main) {
        Ok(plain)
            if plain.contains("VisibleBefore")
                && plain.contains("ExpectedTail") == owns_end
                && !plain.contains("UnexpectedTail") => {}
        Err(error)
            if allow_malformed_plain && error.to_string() == "unbalanced TeX prose argument" => {}
        actual => failures.push(format!("{label}: wrong production extraction: {actual:?}")),
    }
    if child.is_none() {
        match plain_tex(&fs::read_to_string(&main).unwrap()) {
            Ok(plain)
                if plain.contains("VisibleBefore")
                    && plain.contains("ExpectedTail") == owns_end
                    && !plain.contains("UnexpectedTail") => {}
            actual => failures.push(format!("{label}: wrong standalone extraction: {actual:?}")),
        }
    }
}

#[test]
fn malformed_outer_argument_cannot_export_nested_pending_state() {
    let mut failures = Vec::new();
    // General TeX extraction may reject this malformed argument, but source
    // closure must not let its nested pending token hide the caller's real end.
    observe(
        "malformed outer",
        Some(r"\newcommand{\outer}{\newcommand"),
        r"\newcommand{\sample}[1]{#1}",
        r"\input declaration \sample{\end{document}}",
        false,
        true,
        &mut failures,
    );
    observe(
        "complete outer",
        Some(r"\newcommand{\outer}{unused}"),
        "",
        r"\input declaration {\end{document}}",
        false,
        false,
        &mut failures,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn malformed_braced_name_cannot_claim_following_group() {
    let mut failures = Vec::new();
    observe(
        "ordinary-name",
        None,
        "",
        r"\newcommand{ordinary}{\end{document}}",
        false,
        false,
        &mut failures,
    );
    observe(
        "control-name",
        None,
        "",
        r"\newcommand{\sample}{\end{document}}",
        true,
        false,
        &mut failures,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn blank_line_is_a_replacement_token_instead_of_skippable_space() {
    let mut failures = Vec::new();
    observe(
        "blank-line",
        Some(r"\newcommand{\sample}"),
        "",
        "\\input declaration \n\n{\\end{document}}",
        false,
        false,
        &mut failures,
    );
    observe(
        "ordinary-space",
        Some(r"\newcommand{\sample}"),
        "",
        r"\input declaration {\end{document}}",
        true,
        false,
        &mut failures,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn literal_token_between_name_and_body_is_not_comment_whitespace() {
    let mut failures = Vec::new();
    observe(
        "literal",
        Some(r"\newcommand{\sample}"),
        "",
        r"\input declaration \verb|x|{\end{document}}",
        false,
        false,
        &mut failures,
    );
    observe(
        "comment",
        Some(r"\newcommand{\sample}"),
        "",
        "\\input declaration % comment\n{\\end{document}}",
        true,
        false,
        &mut failures,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn continued_definition_replaces_stale_local_ownership() {
    let mut failures = Vec::new();
    observe(
        "definition-command-name",
        Some(r"\renewcommand"),
        r"\newcommand{\initialized}{Initial}",
        r"\input declaration \newcommand{\relax}{\end{document}}",
        false,
        false,
        &mut failures,
    );
    observe(
        "ordinary-command-name",
        Some(r"\renewcommand"),
        r"\newcommand{\sample}{Initial}",
        r"\input declaration \sample{\relax}{\end{document}}",
        false,
        false,
        &mut failures,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn blank_lines_and_comment_only_lines_keep_distinct_tokens() {
    let mut failures = Vec::new();
    for newline in ["\n", "\r\n"] {
        for (gap, owns_end) in [
            ("\n\n", false),
            ("\n  \n", false),
            ("\n", true),
            ("\n% comment-only\n", true),
        ] {
            for included in [false, true] {
                let head = if included {
                    r"\input declaration "
                } else {
                    r"\newcommand{\sample}"
                };
                let child = included.then_some(r"\newcommand{\sample}");
                let candidate =
                    format!("{head}{}{{\\end{{document}}}}", gap.replace('\n', newline));
                observe(
                    &format!("included={included}, gap={gap:?}, newline={newline:?}"),
                    child,
                    "",
                    &candidate,
                    owns_end,
                    false,
                    &mut failures,
                );
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn literal_barriers_apply_to_local_and_continued_definitions() {
    let mut failures = Vec::new();
    for included in [false, true] {
        let head = if included {
            r"\input declaration "
        } else {
            r"\newcommand{\sample}"
        };
        let child = included.then_some(r"\newcommand{\sample}");
        for literal in [r"\verb|x|", r"\verb*|x|"] {
            observe(
                &format!("included={included}, literal={literal}"),
                child,
                "",
                &format!("{head}{literal}{{\\end{{document}}}}"),
                false,
                false,
                &mut failures,
            );
        }
        observe(
            &format!("owned-literal included={included}"),
            child,
            "",
            &format!("{head}{{\\verb|x| \\end{{document}}}}"),
            true,
            false,
            &mut failures,
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn invalid_braced_continuation_names_stay_unowned() {
    let mut failures = Vec::new();
    observe(
        "continued ordinary-name",
        Some(r"\newcommand"),
        "",
        r"\input declaration {ordinary}{\end{document}}",
        false,
        false,
        &mut failures,
    );
    observe(
        "continued control-name",
        Some(r"\newcommand"),
        "",
        r"\input declaration {\sample}{\end{document}}",
        true,
        false,
        &mut failures,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn ownership_reselection_retains_complete_following_declarations() {
    let mut failures = Vec::new();
    observe(
        "same-file consumed-name",
        None,
        r"\newcommand{\initialized}{Initial}",
        r"\renewcommand\newcommand{\relax}{\end{document}}",
        false,
        false,
        &mut failures,
    );
    for included in [false, true] {
        let head = if included {
            r"\input declaration "
        } else {
            r"\renewcommand"
        };
        let child = included.then_some(r"\renewcommand");
        observe(
            &format!("nested recovery included={included}"),
            child,
            r"\newcommand{\initialized}{Initial}",
            &format!(
                "{head}\\renewcommand{{\\relax}}{{\\newcommand{{\\sample}}{{\\end{{document}}}}}}"
            ),
            true,
            false,
            &mut failures,
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn unexpanded_literal_spelling_cannot_change_definition_group_boundaries() {
    let mut failures = Vec::new();
    for included in [false, true] {
        let head = if included {
            r"\input declaration "
        } else {
            r"\newcommand{\sample}"
        };
        let child = included.then_some(r"\newcommand{\sample}");
        for (body, owns_end) in [
            (r"{\verb|}{|\end{document}}", false),
            (r"{\verb|x|\end{document}}", true),
            ("{\\verb|{%}|\n}\\end{document}}", true),
        ] {
            observe(
                &format!("included={included}, body={body}"),
                child,
                "",
                &format!("{head}{body}"),
                owns_end,
                false,
                &mut failures,
            );
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn single_token_replacements_are_inert_without_owning_following_tokens() {
    for included in [false, true] {
        for (replacement, closing, expected) in [
            ("\n\n{ordinary}", "\u{2069}", 0),
            (r"\par", "\u{2069}", 0),
            (r"\verb|x|", "\u{2069}", 0),
            (r"x{\par}", "\u{2069}", 2),
            (r"\relax{\par}", "\u{2069}", 2),
            ("x\u{2069}", "", 0),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let main = root.join("main.tex");
            fs::write(root.join("declaration.tex"), r"\newcommand{\sample}").unwrap();
            let head = if included {
                r"\input declaration "
            } else {
                r"\newcommand{\sample}"
            };
            fs::write(&main, format!("\\begin{{document}}\n\u{2067}before {head}{replacement} after{closing}\n\\end{{document}}\n")).unwrap();
            let actual: Vec<_> =
                lint::check(&Source::load(&main).unwrap(), &[], None, "system-docs")
                    .unwrap()
                    .into_iter()
                    .filter(|finding| finding.check == "bidi-isolate")
                    .map(|finding| (finding.path, finding.line))
                    .collect();
            assert_eq!(
                actual,
                vec![(main, 2); expected],
                "included={included}, replacement={replacement:?}"
            );
        }
    }
}

#[test]
fn original_physical_lines_preserve_real_paragraphs_across_input_boundaries() {
    let definition = r"\newcommand{\sample}{unused}";
    for (child, boundary, lines) in [
        (definition, " ", vec![]),
        (definition, "\n", vec![]),
        (definition, "\n\n", vec![2, 4]),
        (definition, "\r\n", vec![]),
        (definition, "\r", vec![]),
        (definition, "\r\n\r\n", vec![2, 4]),
        (definition, "\r\r", vec![2, 2]),
        ("\nVisible", " ", vec![2, 2]),
        ("\r\nVisible", " ", vec![2, 2]),
        ("\rVisible", " ", vec![2, 2]),
        ("   ", " ", vec![2, 2]),
        ("Visible", " ", vec![]),
        (concat!(r"\newcommand{\sample}{unused}", "\n"), "\n", vec![]),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let main = root.join("main.tex");
        fs::write(root.join("declaration.tex"), child).unwrap();
        fs::write(&main, format!("\\begin{{document}}\n\u{2067}Before \\input declaration{boundary}After\u{2069}\n\\end{{document}}\n")).unwrap();
        let actual: Vec<_> = lint::check(&Source::load(&main).unwrap(), &[], None, "system-docs")
            .unwrap()
            .into_iter()
            .filter(|finding| finding.check == "bidi-isolate")
            .map(|finding| (finding.path, finding.line))
            .collect();
        let expected: Vec<_> = lines.into_iter().map(|line| (main.clone(), line)).collect();
        assert_eq!(actual, expected, "child={child:?}, boundary={boundary:?}");
        let plain = source_plain(&main).unwrap();
        assert!(plain.contains("Before") && plain.contains("After"));
    }
}
