use revayat_scientific::lint::{self, Source};
use revayat_scientific::text_order::source_plain;
use std::fs;
use std::path::{Path, PathBuf};

fn findings(source: &Source) -> Vec<(PathBuf, usize)> {
    lint::check(source, &[], None, "system-docs")
        .unwrap()
        .into_iter()
        .filter(|finding| finding.check == "bidi-isolate")
        .map(|finding| (finding.path, finding.line))
        .collect()
}

fn write_document(main: &Path, command: &str, body: &str) {
    let initial = if command == "renewcommand" {
        r"\newcommand{\sample}{Initial}"
    } else {
        ""
    };
    fs::write(main, format!("\\documentclass{{article}}\n{initial}\n\\begin{{document}}\n{body}\n\\end{{document}}\n")).unwrap();
}

#[test]
fn unbraced_input_resumes_only_complete_definition_syntax() {
    for command in ["newcommand", "renewcommand"] {
        for (ending, following, expected) in [
            ("", r"\sample{\par}", 0),
            ("\n", r"\sample{\par}", 0),
            (r"\sample", r"{\par}", 0),
            (r"{\sample}", r"[1]{\par #1}", 0),
            (r"\sample[1]", r"{\par #1}", 0),
            ("", r"*\sample{\par}", 0),
            ("", r"\sample{unused}\par", 2),
            (r"\sample{\par}", "", 0),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let main = root.join("main.tex");
            fs::write(root.join("declaration.tex"), format!("\\{command}{ending}")).unwrap();
            write_document(
                &main,
                command,
                &format!("\u{2067}before \\input declaration {following} after\u{2069}"),
            );
            let actual = findings(&Source::load(&main).unwrap());
            assert_eq!(
                actual,
                vec![(main, 4); expected],
                "{command}, ending={ending:?}, following={following:?}"
            );
        }
    }
}

#[test]
fn continued_markers_and_owned_dependencies_preserve_later_prose() {
    for command in ["newcommand", "renewcommand"] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let main = root.join("main.tex");
        let chapter = root.join("chapter.tex");
        fs::write(root.join("declaration.tex"), format!("\\{command}")).unwrap();
        fs::write(
            root.join("owned.tex"),
            "}\n\\end{document}\n{\n\\input{deep}\n",
        )
        .unwrap();
        fs::write(root.join("deep.tex"), "\u{2067}UnusedDefinitionData").unwrap();
        fs::write(
            &chapter,
            "Header\n\u{2067}before\\par after\u{2069} VisibleTail",
        )
        .unwrap();
        write_document(
            &main,
            command,
            "\\input declaration \\sample{\\end{document}\\input{owned}}\n\\input{chapter}",
        );
        let mut text = fs::read_to_string(&main).unwrap();
        text.push_str("\\input{missing-after-real-end}\n");
        fs::write(&main, text).unwrap();
        let source = Source::load(&main).unwrap();
        let Source::Tex(model) = &source else {
            unreachable!()
        };
        assert_eq!(
            model.closure.sources,
            [
                main.clone(),
                root.join("declaration.tex"),
                root.join("owned.tex"),
                root.join("deep.tex"),
                chapter.clone()
            ]
        );
        assert!(model.closure.text.contains("}\n\\end{document}\n{"));
        assert_eq!(findings(&source), [(chapter.clone(), 2), (chapter, 2)]);
        assert!(source_plain(&main).unwrap().contains("VisibleTail"));
    }
}

#[test]
fn continued_begin_markers_keep_preamble_text_excluded() {
    for command in ["newcommand", "renewcommand"] {
        let directory = tempfile::tempdir().unwrap();
        let main = directory.path().join("main.tex");
        fs::write(
            directory.path().join("declaration.tex"),
            format!("\\{command}"),
        )
        .unwrap();
        let initial = if command == "renewcommand" {
            r"\newcommand{\sample}{Initial}"
        } else {
            ""
        };
        fs::write(&main, format!("\\documentclass{{article}}\n{initial}\n\\input declaration \\sample{{\\begin{{document}}}}\n\\title{{\u{2067}PreambleMarker}}\n\\begin{{document}}\n\u{2067}VisibleTail\u{2069}\n\\end{{document}}\n")).unwrap();
        assert!(findings(&Source::load(&main).unwrap()).is_empty());
        let plain = source_plain(&main).unwrap();
        assert!(plain.contains("VisibleTail"));
        assert!(!plain.contains("PreambleMarker"));
    }
}

#[test]
fn recursive_empty_returns_keep_definition_ownership_and_locations() {
    for command in ["newcommand", "renewcommand"] {
        for newline in ["\n", "\r\n"] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let main = root.join("main.tex");
            fs::write(root.join("declaration.tex"), format!("\\{command}")).unwrap();
            fs::write(root.join("middle.tex"), "\\input declaration \\sample[1]").unwrap();
            fs::write(root.join("upper.tex"), "\\input middle ").unwrap();
            write_document(
                &main,
                command,
                "\u{2067}before \\input upper {\\par #1} after\u{2069}\n\u{2067}outside\\par after\u{2069}",
            );
            let text = fs::read_to_string(&main).unwrap().replace('\n', newline);
            fs::write(&main, text).unwrap();
            let source = Source::load(&main).unwrap();
            let Source::Tex(model) = &source else {
                unreachable!()
            };
            assert_eq!(
                model.closure.sources,
                [
                    main.clone(),
                    root.join("upper.tex"),
                    root.join("middle.tex"),
                    root.join("declaration.tex")
                ]
            );
            assert_eq!(
                findings(&source),
                [(main.clone(), 5), (main, 5)],
                "{command}, newline={newline:?}"
            );
        }
    }
}

#[test]
fn repeated_input_visits_keep_inherited_and_continued_ownership_separate() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    let shared = root.join("shared.tex");
    fs::write(&shared, r"\renewcommand").unwrap();
    write_document(
        &main,
        "renewcommand",
        "\\newcommand{\\opaque}{\\input shared }\n\u{2067}before \\input shared \\sample{\\par} after\u{2069}\n\u{2067}outside\\par after\u{2069}",
    );
    let source = Source::load(&main).unwrap();
    let Source::Tex(model) = &source else {
        unreachable!()
    };
    assert_eq!(model.closure.sources, [main.clone(), shared]);
    assert_eq!(model.closure.text.matches(r"\renewcommand").count(), 2);
    assert_eq!(findings(&source), [(main.clone(), 6), (main, 6)]);
}

#[test]
fn unresolved_or_hooked_inputs_cannot_claim_following_prose() {
    for (child, input, following) in [
        (r"\newcommand*", r"\input declaration ", r"\sample{\par}"),
        (
            r"\newcommand\sample[1][default]",
            r"\input declaration ",
            r"{\par}",
        ),
        (r"\newcommand\sample{", r"\input declaration ", r"\par}"),
        (
            r"\newcommand",
            r"\input declaration ",
            r"ordinary prose\par",
        ),
        (r"\newcommand", r"\input{declaration}", r"\sample{\par}"),
        (r"\newcommand", r"\include{declaration}", r"\sample{\par}"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let main = root.join("main.tex");
        fs::write(root.join("declaration.tex"), child).unwrap();
        write_document(
            &main,
            "newcommand",
            &format!("\u{2067}before {input}{following} after\u{2069}"),
        );
        let mut text = fs::read_to_string(&main).unwrap();
        text.push_str("\\input{missing-after-real-end}\n");
        fs::write(&main, text).unwrap();
        assert_eq!(
            findings(&Source::load(&main).unwrap()),
            [(main.clone(), 4), (main, 4)],
            "child={child:?}, input={input:?}"
        );
    }
}

#[test]
fn continued_control_symbol_names_preserve_following_paragraph_commands() {
    for (child, following, expected) in [
        (r"\renewcommand", r"\\{\par}", 0),
        (r"\renewcommand\\", r"{\par}", 0),
        (r"\renewcommand", r"\\{unused}\par", 2),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let main = root.join("main.tex");
        fs::write(root.join("declaration.tex"), child).unwrap();
        write_document(
            &main,
            "newcommand",
            &format!("\u{2067}before \\input declaration {following} after\u{2069}"),
        );
        assert_eq!(
            findings(&Source::load(&main).unwrap()),
            vec![(main, 4); expected],
            "{child}, {following}"
        );
    }
}

#[test]
fn an_unfinished_resumed_group_cannot_export_a_nested_continuation() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    let middle = root.join("middle.tex");
    let declaration = root.join("declaration.tex");
    fs::write(&declaration, r"\newcommand").unwrap();
    fs::write(&middle, r"\input declaration \sample{\newcommand").unwrap();
    fs::write(
        &main,
        r"\begin{document}\input middle \other{\end{document}}\input{missing}\end{document}",
    )
    .unwrap();

    let source = Source::load(&main).unwrap();
    let Source::Tex(model) = &source else {
        unreachable!()
    };
    assert_eq!(model.closure.sources, [main, middle, declaration]);
    assert_eq!(
        model.body_end,
        model.text().find(r"\end{document}").unwrap()
    );
}

#[test]
fn a_real_document_end_prevents_later_continuation_and_dependency_reads() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    let ending = root.join("ending.tex");
    fs::write(&ending, "\\end{document}\n\\newcommand").unwrap();
    write_document(
        &main,
        "newcommand",
        "\u{2067}Visible\u{2069}\n\\input ending \\sample{\\par}\u{2067}\n\\input{missing-after-real-end}",
    );
    let source = Source::load(&main).unwrap();
    let Source::Tex(model) = &source else {
        unreachable!()
    };
    assert_eq!(model.closure.sources, [main, ending]);
    assert!(findings(&source).is_empty());
}
