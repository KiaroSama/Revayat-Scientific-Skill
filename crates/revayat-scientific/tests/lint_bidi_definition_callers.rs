use revayat_scientific::lint::{self, Finding, Source};
use revayat_scientific::tex::plain_tex;
use std::fs;

fn checked(source: &Source, check: &str) -> Vec<Finding> {
    lint::check(source, &[], None, "system-docs")
        .unwrap()
        .into_iter()
        .filter(|finding| finding.check == check)
        .collect()
}

#[test]
fn definition_end_markers_do_not_hide_prose_or_later_includes() {
    for definition in [
        r"\newcommand{\sample}{unused}",
        r"\newcommand{\sample}{\end{document}}",
    ] {
        for included in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let main = root.join("main.tex");
            let chapter = root.join("chapter.tex");
            let visible = "\u{2067}before\\par after\u{2069}";
            fs::write(&chapter, visible).unwrap();
            let tail = if included {
                r"\input{chapter}"
            } else {
                visible
            };
            fs::write(
                &main,
                format!("\\documentclass{{article}}\n\\begin{{document}}\n{definition}\n{tail}\n\\end{{document}}\n"),
            )
            .unwrap();
            let actual: Vec<_> = checked(&Source::load(&main).unwrap(), "bidi-isolate")
                .into_iter()
                .map(|finding| (finding.path, finding.line))
                .collect();
            let path = if included { chapter } else { main };
            let line = if included { 1 } else { 4 };
            assert_eq!(actual, [(path.clone(), line), (path, line)], "{definition}");
        }
    }
}

#[test]
fn definition_begin_markers_do_not_activate_preamble_prose() {
    for definition in [
        r"\newcommand{\sample}{unused}",
        r"\newcommand{\sample}{\begin{document}}",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let main = directory.path().join("main.tex");
        fs::write(
            &main,
            format!("\\documentclass{{article}}\n{definition}\n\\title{{\u{2067}unused title}}\n\\begin{{document}}\n\u{2067}visible text\u{2069}\n\\end{{document}}\n"),
        )
        .unwrap();
        let actual = checked(&Source::load(&main).unwrap(), "bidi-isolate");
        assert!(actual.is_empty(), "{definition}: {actual:#?}");
    }
}

#[test]
fn plain_text_uses_real_document_markers() {
    for definition in [
        r"\newcommand{\sample}{unused}",
        r"\newcommand{\sample}{\end{document}}",
    ] {
        let text = format!("\\begin{{document}}{definition} VisibleTail\\end{{document}}");
        assert!(
            plain_tex(&text).unwrap().contains("VisibleTail"),
            "{definition}"
        );
    }
    for definition in [
        r"\newcommand{\sample}{unused}",
        r"\newcommand{\sample}{\begin{document}}",
    ] {
        let text = format!(
            "{definition}\\title{{PreambleMarker}}\\begin{{document}}VisibleTail\\end{{document}}"
        );
        let actual = plain_tex(&text).unwrap();
        assert!(actual.contains("VisibleTail"), "{definition}");
        assert!(!actual.contains("PreambleMarker"), "{definition}: {actual}");
    }
}

#[test]
fn admitted_definition_images_retain_their_direction_scope() {
    for scoped in [
        r"\LR{\includegraphics{figure.png}}",
        r"\begin{LTR}\includegraphics{figure.png}\end{LTR}",
        r"\begin{latin}\includegraphics{figure.png}\end{latin}",
    ] {
        for definition in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let main = directory.path().join("main.tex");
            image::RgbImage::from_pixel(4, 4, image::Rgb([160, 170, 180]))
                .save(directory.path().join("figure.png"))
                .unwrap();
            let body = if definition {
                format!("\\newcommand{{\\sample}}{{{scoped}}}\\sample")
            } else {
                scoped.to_owned()
            };
            fs::write(
                &main,
                format!("\\begin{{document}}\n{body}\n\\end{{document}}\n"),
            )
            .unwrap();
            let source = Source::load(&main).unwrap();
            let references = source.image_references();
            assert_eq!(references.len(), 1, "{body}");
            assert_eq!(references[0].1, "figure.png", "{body}");
            let actual = checked(&source, "figure-direction");
            assert!(actual.is_empty(), "{body}: {actual:#?}");
        }
    }
}

#[test]
fn definition_markers_preserve_conservative_dependency_discovery() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    fs::write(
        root.join("preamble.tex"),
        r"\newcommand{\preamblemarker}{unused}",
    )
    .unwrap();
    fs::write(
        root.join("definition.tex"),
        "\\end{document}\n\\input{nested}\n",
    )
    .unwrap();
    fs::write(root.join("nested.tex"), "UnusedDefinitionData\n").unwrap();
    fs::write(
        root.join("chapter.tex"),
        "\u{2067}before\\par after\u{2069}",
    )
    .unwrap();
    fs::write(
        &main,
        "\\documentclass{article}\n\\input{preamble}\n\\begin{document}\n\\newcommand{\\sample}{\\input{definition}}\n\\input{chapter}\n\\end{document}\n\\input{missing-after-real-end}\n",
    )
    .unwrap();
    let source = Source::load(&main).unwrap();
    let Source::Tex(model) = &source else {
        unreachable!()
    };
    assert_eq!(
        model.closure.sources,
        [
            main,
            root.join("preamble.tex"),
            root.join("definition.tex"),
            root.join("nested.tex"),
            root.join("chapter.tex")
        ]
    );
    let actual = checked(&source, "bidi-isolate");
    assert_eq!(actual.len(), 2);
    assert!(
        actual
            .iter()
            .all(|finding| finding.path == root.join("chapter.tex") && finding.line == 1)
    );
}
