use revayat_scientific::lint::{self, Source};
use revayat_scientific::text_order::source_plain;
use std::fs;

#[test]
fn large_incomplete_definition_tails_do_not_hide_visible_prose() {
    for fragment in [
        r"\newcommand{\x}{",
        r"\newcommand\x[",
        r"\newcommand\x[1][{",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.tex");
        let text = format!(
            "\\begin{{document}}\n\u{2067}VisibleTail\\par after\u{2069}\n\\end{{document}}\n{}",
            fragment.repeat(100_000)
        );
        fs::write(&path, &text).unwrap();
        let source = Source::load(&path).unwrap();
        let Source::Tex(model) = &source else {
            unreachable!()
        };
        assert_eq!(model.body_end, text.find(r"\end{document}").unwrap());
        let findings: Vec<_> = lint::check(&source, &[], None, "system-docs")
            .unwrap()
            .into_iter()
            .filter(|finding| finding.check == "bidi-isolate")
            .collect();
        assert_eq!(findings.len(), 2, "{fragment}");
        assert!(findings.iter().all(|finding| finding.line == 2));
        assert!(source_plain(&path).unwrap().contains("VisibleTail"));
    }
}

#[test]
fn live_item_options_remain_protected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.tex");
    fs::write(
        &path,
        "\\begin{document}\n\\begin{itemize}\\item[\u{2067}Label]VisibleTail\\end{itemize}\n\\end{document}",
    )
    .unwrap();
    let source = Source::load(&path).unwrap();
    let actual: Vec<_> = lint::check(&source, &[], None, "system-docs")
        .unwrap()
        .into_iter()
        .filter(|finding| finding.check == "bidi-isolate")
        .collect();
    assert!(actual.is_empty(), "{actual:#?}");
}
