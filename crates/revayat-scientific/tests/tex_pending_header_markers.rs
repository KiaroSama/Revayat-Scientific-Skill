use revayat_scientific::lint::{self, Source};
use revayat_scientific::text_order::source_plain;
use std::fs;

#[test]
fn completed_count_headers_keep_document_markers_unexpanded_across_returns() {
    // LaTeX accepts count expressions whose number expansion is one digit.
    // The skipped conditional arm is valid raw argument data, not a live end.
    let mut failures = Vec::new();
    for command in ["newcommand", "renewcommand"] {
        for count in [
            r"\iftrue1\else\end{document}\fi",
            r"\iftrue1\else\begin{document}\fi",
            r"\iftrue1\else\begin{document}\end{document}\fi",
            r"\iftrue1\else\end{document}\begin{document}\fi",
        ] {
            for mode in [
                "local",
                "direct",
                "command-return",
                "name-return",
                "empty-return",
            ] {
                for in_preamble in [false, true] {
                    let label = format!("{command}/{count}/{mode}/preamble={in_preamble}");
                    let directory = tempfile::tempdir().unwrap();
                    let root = directory.path().canonicalize().unwrap();
                    let main = root.join("main.tex");
                    let header = root.join("header.tex");
                    let declaration = root.join("declaration.tex");
                    let upper = root.join("upper.tex");
                    let visible = root.join("visible.tex");
                    let mut expected = vec![main.clone()];
                    let local_header = format!("\\{command}\\sample[{count}]");
                    let selected = match mode {
                        "local" => local_header.clone(),
                        "direct" => {
                            fs::write(&header, &local_header).unwrap();
                            expected.push(header.clone());
                            r"\input header ".to_owned()
                        }
                        _ => {
                            let declaration_text = if mode == "name-return" {
                                format!("\\{command}\\sample")
                            } else {
                                format!("\\{command}")
                            };
                            fs::write(&declaration, declaration_text).unwrap();
                            let name = if mode == "name-return" {
                                ""
                            } else {
                                r"\sample"
                            };
                            fs::write(&header, format!("\\input declaration {name}[{count}]"))
                                .unwrap();
                            if mode == "empty-return" {
                                fs::write(&upper, r"\input header ").unwrap();
                                expected.push(upper.clone());
                            }
                            expected.extend([header.clone(), declaration.clone()]);
                            if mode == "empty-return" {
                                r"\input upper ".to_owned()
                            } else {
                                r"\input header ".to_owned()
                            }
                        }
                    };
                    expected.push(visible.clone());
                    fs::write(
                        &visible,
                        "\u{2067}VisibleBefore\\par after\u{2069} VisibleTail\n",
                    )
                    .unwrap();
                    let initial = if command == "renewcommand" {
                        "\\newcommand\\sample[1]{#1}\n"
                    } else {
                        ""
                    };
                    let (before, after) = if in_preamble {
                        ("", "\\begin{document}\n")
                    } else {
                        ("\\begin{document}\n", "")
                    };
                    fs::write(&main, format!("\\documentclass{{article}}\n{initial}{before}{selected}{{#1}}\n{after}\\input{{visible}}\n\\end{{document}}\n\\input{{missing-after-real-end}}\nUnexpectedTail\n")).unwrap();
                    match Source::load(&main) {
                        Ok(source) => {
                            let Source::Tex(model) = &source else {
                                unreachable!()
                            };
                            if model.closure.sources != expected {
                                failures.push(format!(
                                    "{label}: wrong dependency closure {:?}",
                                    model.closure.sources
                                ));
                            }
                            if model.body_end != model.text().rfind(r"\end{document}").unwrap() {
                                failures.push(format!(
                                    "{label}: a raw count marker ended the document"
                                ));
                            }
                            let findings: Vec<_> = lint::check(&source, &[], None, "system-docs")
                                .unwrap()
                                .into_iter()
                                .filter(|finding| finding.check == "bidi-isolate")
                                .map(|finding| (finding.path, finding.line))
                                .collect();
                            if findings != [(visible.clone(), 1), (visible.clone(), 1)] {
                                failures.push(format!(
                                    "{label}: wrong original-location findings {findings:?}"
                                ));
                            }
                        }
                        Err(error) => failures.push(format!("{label}: source failed: {error:#}")),
                    }
                    match source_plain(&main) {
                        Ok(plain)
                            if plain.contains("VisibleTail")
                                && !plain.contains("UnexpectedTail") => {}
                        actual => failures.push(format!("{label}: extraction {actual:?}")),
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn unresolved_headers_at_root_eof_retain_conservative_original_boundaries() {
    for command in ["newcommand", "renewcommand"] {
        for mode in ["local", "direct", "empty-return"] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let main = root.join("main.tex");
            let header = root.join("header.tex");
            let upper = root.join("upper.tex");
            let declaration = format!("\\{command}\\sample[\\iftrue1\\else\\end{{document}}\\fi]");
            fs::write(&header, &declaration).unwrap();
            fs::write(&upper, r"\input header ").unwrap();
            let mut expected = vec![main.clone()];
            let (selected, marker_path, marker_line) = match mode {
                "local" => (declaration, main.clone(), 2),
                "direct" => {
                    expected.push(header.clone());
                    (r"\input header ".to_owned(), header.clone(), 1)
                }
                _ => {
                    expected.extend([upper.clone(), header.clone()]);
                    (r"\input upper ".to_owned(), header.clone(), 1)
                }
            };
            fs::write(&main, format!("\\begin{{document}}\n{selected}")).unwrap();
            let Source::Tex(model) = Source::load(&main).unwrap() else {
                unreachable!()
            };
            assert_eq!(model.closure.sources, expected, "{command}/{mode}");
            assert_eq!(
                model.body_end,
                model.text().find(r"\end{document}").unwrap()
            );
            assert_eq!(
                model.closure.location(model.body_end as isize),
                (marker_path, marker_line)
            );
        }
    }
}

#[test]
fn rejected_default_or_body_continuations_settle_earlier_count_markers() {
    for command in ["newcommand", "renewcommand"] {
        for suffix in ["[default]", "[", "{", "}", "[\\newcommand"] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let main = root.join("main.tex");
            let header = root.join("header.tex");
            let middle = root.join("middle.tex");
            fs::write(
                &header,
                format!("\\{command}\\sample[\\iftrue1\\else\\end{{document}}\\fi]"),
            )
            .unwrap();
            fs::write(&middle, format!("\\input header {suffix}")).unwrap();
            fs::write(&main, "\\begin{document}\n\\input middle {UnusedBody}\\input{missing-after-rejected-header}\\end{document}").unwrap();
            let Source::Tex(model) = Source::load(&main).unwrap() else {
                unreachable!()
            };
            assert_eq!(
                model.closure.sources,
                [main, middle, header.clone()],
                "{command}/{suffix}"
            );
            assert_eq!(
                model.body_end,
                model.text().find(r"\end{document}").unwrap()
            );
            assert_eq!(model.closure.location(model.body_end as isize), (header, 1));
        }
    }
}

#[test]
fn rejected_headers_do_not_replay_commented_or_escaped_marker_spellings() {
    for (initially_started, count) in [
        (true, "1% \\end{document}\n"),
        (true, r"1\\end{document}"),
        (false, "1% \\begin{document}\n\\end{document}"),
        (false, r"1\\begin{document}\end{document}"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let main = root.join("main.tex");
        let header = root.join("header.tex");
        let visible = root.join("visible.tex");
        fs::write(&header, format!("\\newcommand\\sample[{count}]")).unwrap();
        fs::write(&visible, "VisibleAfterHeader").unwrap();
        let (before, after) = if initially_started {
            ("\\begin{document}\n", "")
        } else {
            ("", "\\begin{document}\n")
        };
        fs::write(&main, format!("{before}\\input{{header}}\n{after}\\input{{visible}}\n\\end{{document}}\n\\input{{missing-after-real-end}}")).unwrap();
        let Source::Tex(model) = Source::load(&main).unwrap() else {
            unreachable!()
        };
        assert_eq!(
            model.closure.sources,
            [main, header, visible],
            "{initially_started}/{count:?}"
        );
        assert_eq!(
            model.body_end,
            model.text().rfind(r"\end{document}").unwrap()
        );
    }
}
