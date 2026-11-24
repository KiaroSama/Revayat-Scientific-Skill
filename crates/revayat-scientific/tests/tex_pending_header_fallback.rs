//! Independent recovery controls for deferred pending-header document markers.
use revayat_scientific::lint::Source;
use std::fs;
use std::path::Path;

fn inspect(files: &[(&str, &str)], check: impl FnOnce(&Path, &Source)) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    for &(name, text) in files {
        fs::write(root.join(name), text).unwrap();
    }
    let source = Source::load(&root.join("main.tex")).unwrap();
    check(&root, &source);
}

#[test]
fn rejected_header_marker_order_preserves_initial_document_state() {
    for recursive in [false, true] {
        for (markers, should_read) in [
            (r"\end{document}\begin{document}", true),
            (r"\begin{document}\end{document}", false),
        ] {
            let direct = format!("\\newcommand{{\\sample}}[{markers}]");
            let middle = format!("\\input declaration [{markers}]");
            let main = if recursive {
                "\\input{middle}\n\\input{visible}\n\\end{document}\n\\input{missing-after-end}"
            } else {
                "\\input{declaration}\n\\input{visible}\n\\end{document}\n\\input{missing-after-end}"
            };
            let declaration = if recursive {
                r"\newcommand{\sample}"
            } else {
                &direct
            };
            inspect(
                &[
                    ("main.tex", main),
                    ("declaration.tex", declaration),
                    ("middle.tex", &middle),
                    ("visible.tex", "VisibleAfterRejectedHeader"),
                ],
                |root, source| {
                    let Source::Tex(model) = source else {
                        unreachable!()
                    };
                    let mut expected = vec![root.join("main.tex")];
                    if recursive {
                        expected.push(root.join("middle.tex"));
                    }
                    expected.push(root.join("declaration.tex"));
                    if should_read {
                        expected.push(root.join("visible.tex"));
                    }
                    assert_eq!(model.closure.sources, expected, "{recursive}/{markers}");
                    assert_eq!(
                        model.text().contains("VisibleAfterRejectedHeader"),
                        should_read,
                        "{recursive}/{markers}"
                    );
                },
            );
        }
    }
}

#[test]
fn refused_continuations_commit_pending_end_before_reading_more_inputs() {
    for (prefix, include, following) in [
        ("", r"\input{declaration}", ""),
        ("", r"\include{declaration}", ""),
        ("", r"\input declaration ", "}"),
        (
            r"\newcommand{\unfinished}{",
            r"\input declaration ",
            "{body}",
        ),
    ] {
        let main = format!(
            "\\begin{{document}}\n{prefix}{include}{following}\n\\input{{missing-after-end}}\n"
        );
        inspect(
            &[
                ("main.tex", &main),
                ("declaration.tex", r"\newcommand{\sample}[\end{document}]"),
            ],
            |root, source| {
                let Source::Tex(model) = source else {
                    unreachable!()
                };
                assert_eq!(
                    model.closure.sources,
                    [root.join("main.tex"), root.join("declaration.tex")],
                    "{main}"
                );
                assert_eq!(
                    model.body_end,
                    model.text().find(r"\end{document}").unwrap()
                );
            },
        );
    }
}

#[test]
fn inherited_definition_data_cannot_commit_pending_document_markers() {
    for include in [r"\input{owned}", r"\input owned "] {
        let main = format!(
            "\\begin{{document}}\n\\newcommand{{\\outer}}{{{include}}}\n\\input{{visible}}\n\\end{{document}}\n\\input{{missing-after-end}}"
        );
        inspect(
            &[
                ("main.tex", &main),
                (
                    "owned.tex",
                    r"\newcommand{\sample}[\begin{document}\end{document}]",
                ),
                ("visible.tex", "VisibleAfterOwnedHeader"),
            ],
            |root, source| {
                let Source::Tex(model) = source else {
                    unreachable!()
                };
                assert_eq!(
                    model.closure.sources,
                    [
                        root.join("main.tex"),
                        root.join("owned.tex"),
                        root.join("visible.tex")
                    ],
                    "{main}"
                );
                assert!(model.text().contains("VisibleAfterOwnedHeader"));
                assert!(model.body_end > model.text().find("VisibleAfterOwnedHeader").unwrap());
            },
        );
    }
}

#[test]
fn real_end_before_a_pending_header_remains_terminal() {
    inspect(
        &[
            (
                "main.tex",
                "\\begin{document}\n\\input declaration {body}\n\\input{missing-after-end}",
            ),
            (
                "declaration.tex",
                "\\end{document}\n\\newcommand{\\sample}[\\begin{document}]",
            ),
        ],
        |root, source| {
            let Source::Tex(model) = source else {
                unreachable!()
            };
            assert_eq!(
                model.closure.sources,
                [root.join("main.tex"), root.join("declaration.tex")]
            );
            assert_eq!(
                model.body_end,
                model.text().find(r"\end{document}").unwrap()
            );
        },
    );
}
