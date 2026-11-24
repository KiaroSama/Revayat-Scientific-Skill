use revayat_scientific::lint::{self, Source};
use revayat_scientific::tex::{Segment, Snapshot, SourceClosure};
use revayat_scientific::text_order::source_plain;
use std::fs;
use std::sync::Arc;

#[test]
fn definition_dependency_delimiters_do_not_hide_later_visible_prose() {
    let mut failures = Vec::new();
    for child in ["UnusedData\n", "}\n\\end{document}\n{\n"] {
        for included in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let main = root.join("main.tex");
            let chapter = root.join("chapter.tex");
            fs::write(root.join("definition.tex"), child).unwrap();
            fs::write(&chapter, "\u{2067}before\\par after\u{2069}").unwrap();
            let visible = if included {
                r"\input{chapter}"
            } else {
                "\u{2067}before\\par after\u{2069}"
            };
            fs::write(&main, format!("\\begin{{document}}\n\\newcommand{{\\sample}}{{\\input{{definition}}}}\n{visible}\n\\end{{document}}\n")).unwrap();
            let source = Source::load(&main).unwrap();
            let actual: Vec<_> = lint::check(&source, &[], None, "system-docs")
                .unwrap()
                .into_iter()
                .filter(|finding| finding.check == "bidi-isolate")
                .map(|finding| (finding.path, finding.line))
                .collect();
            let path = if included { chapter } else { main };
            let line = if included { 1 } else { 3 };
            if actual != [(path.clone(), line), (path.clone(), line)] {
                failures.push(format!("child={child:?}, included={included}: expected two at {path:?}:{line}, got {actual:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn definition_dependency_tokens_stay_inert_after_child_braces() {
    let mut failures = Vec::new();
    for (child, prefix, suffix, expected) in [
        ("}\n\\par\n{\n", "\u{2067}before ", " after\u{2069}", 0),
        ("}\n\u{2069}\n{\n", "\u{2067}before ", " after", 1),
        ("}\n\u{2067}\n{\n", "before ", " after", 0),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let main = directory.path().join("main.tex");
        fs::write(directory.path().join("definition.tex"), child).unwrap();
        fs::write(&main, format!("\\begin{{document}}\n{prefix}\\newcommand{{\\sample}}{{\\input{{definition}}}}{suffix}\n\\end{{document}}\n")).unwrap();
        let actual: Vec<_> = lint::check(&Source::load(&main).unwrap(), &[], None, "system-docs")
            .unwrap()
            .into_iter()
            .filter(|finding| finding.check == "bidi-isolate")
            .collect();
        if actual.len() != expected {
            failures.push(format!(
                "child={child:?}: expected {expected}, got {actual:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn production_plain_text_keeps_real_extent_after_dependency_delimiters() {
    let mut failures = Vec::new();
    for child in ["UnusedData\n", "}\n\\end{document}\n{\n"] {
        let directory = tempfile::tempdir().unwrap();
        let main = directory.path().join("main.tex");
        fs::write(directory.path().join("definition.tex"), child).unwrap();
        fs::write(&main, "\\begin{document}\n\\newcommand{\\sample}{\\input{definition}}\nVisibleTail\n\\end{document}\n").unwrap();
        match source_plain(&main) {
            Ok(actual) if actual.contains("VisibleTail") => {}
            actual => failures.push(format!(
                "child={child:?}: visible tail must survive, got {actual:?}"
            )),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    let directory = tempfile::tempdir().unwrap();
    let main = directory.path().join("main.tex");
    fs::write(
        &main,
        "\\begin{document}\\newcommand{\\sample}{RetainedBody} VisibleTail\\end{document}",
    )
    .unwrap();
    assert_eq!(source_plain(&main).unwrap(), "RetainedBody VisibleTail");
}

#[test]
fn nested_and_sibling_definition_inputs_keep_original_locations() {
    for newline in ["\n", "\r\n"] {
        for nested in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let main = root.join("main.tex");
            let left = root.join("left.tex");
            let right = root.join("right.tex");
            let leaf = root.join("leaf.tex");
            let chapter = root.join("chapter.tex");
            let data = format!("}}{newline}\\end{{document}}{newline}{{");
            fs::write(&left, if nested { r"\input{leaf}" } else { &data }).unwrap();
            fs::write(&leaf, &data).unwrap();
            fs::write(
                &right,
                format!("}}{newline}\u{2067}HiddenDefinitionData{newline}{{"),
            )
            .unwrap();
            fs::write(
                &chapter,
                format!("Header{newline}\u{2067}before\\par after\u{2069}"),
            )
            .unwrap();
            fs::write(&main, format!("\\begin{{document}}{newline}\\newcommand{{\\sample}}{{\\input{{left}}\\input{{right}}}}{newline}\\input{{chapter}}{newline}\\end{{document}}{newline}")).unwrap();
            let source = Source::load(&main).unwrap();
            let Source::Tex(model) = &source else {
                unreachable!()
            };
            let mut expected_sources = vec![main.clone(), left];
            if nested {
                expected_sources.push(leaf);
            }
            expected_sources.extend([right, chapter.clone()]);
            assert_eq!(model.closure.sources, expected_sources);
            assert!(model.closure.text.contains(&data));
            assert!(model.live.matches(r"\end{document}").count() >= 2);
            let actual: Vec<_> = lint::check(&source, &[], None, "system-docs")
                .unwrap()
                .into_iter()
                .filter(|finding| finding.check == "bidi-isolate")
                .map(|finding| (finding.path, finding.line))
                .collect();
            assert_eq!(
                actual,
                [(chapter.clone(), 2), (chapter, 2)],
                "nested={nested}, newline={newline:?}"
            );
        }
    }
}

#[test]
fn repeated_file_visits_do_not_share_definition_ownership() {
    for newline in ["\n", "\r\n"] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let main = root.join("main.tex");
        let shared = root.join("shared.tex");
        fs::write(
            &shared,
            format!("Header{newline}\u{2067}before\\par after\u{2069}"),
        )
        .unwrap();
        fs::write(&main, format!("\\begin{{document}}{newline}\\newcommand{{\\sample}}{{\\input{{shared}}}}{newline}\\input{{shared}}{newline}\\end{{document}}{newline}")).unwrap();
        let source = Source::load(&main).unwrap();
        let Source::Tex(model) = &source else {
            unreachable!()
        };
        assert_eq!(model.closure.sources, [main, shared.clone()]);
        assert_eq!(model.closure.text.matches("before").count(), 2);
        let actual: Vec<_> = lint::check(&source, &[], None, "system-docs")
            .unwrap()
            .into_iter()
            .filter(|finding| finding.check == "bidi-isolate")
            .map(|finding| (finding.path, finding.line))
            .collect();
        assert_eq!(actual, [(shared.clone(), 2), (shared, 2)]);
    }
}

#[test]
fn public_snapshot_constructor_retains_definition_classification() {
    for split in [1, 3, 32] {
        let text = "\\begin{document}\\newcommand{\\sample}{\u{2067}متن \\end{document}} VisibleTail\\end{document}";
        let path = std::path::PathBuf::from("main.tex");
        let snapshot = Arc::new(Snapshot::new(path.clone(), Arc::from(text)).unwrap());
        let closure = SourceClosure {
            text: text.to_owned(),
            segments: (0..text.len())
                .step_by(split)
                .map(|start| Segment {
                    start,
                    original_offset: start,
                    snapshot: snapshot.clone(),
                })
                .collect(),
            sources: vec![path],
        };
        assert!(
            closure.plain_text().unwrap().contains("VisibleTail"),
            "split={split}"
        );
    }
}
