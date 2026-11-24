use revayat_scientific::lint::{self, Source};
use revayat_scientific::text_order::source_plain;
use std::fs;

fn check(body: &str, suffix: &str, hidden_label: bool) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    let text = format!(
        "\\newcommand{{\\sample}}{{initial}}\n\\begin{{document}}\n{body}\n\\end{{document}}\n{suffix}\\input{{missing-after-real-end}}\nAfterRealEnd\n"
    );
    fs::write(&main, &text).unwrap();
    let source = Source::load(&main).unwrap();
    let Source::Tex(model) = &source else {
        unreachable!()
    };
    assert_eq!(model.closure.sources, std::slice::from_ref(&main));
    assert_eq!(
        model.body_end,
        model.text().find(r"\end{document}").unwrap()
    );
    let visible = model.text().find("\u{2067}VisibleBefore").unwrap();
    let line = model.text()[..visible]
        .bytes()
        .filter(|&byte| byte == b'\n')
        .count()
        + 1;
    assert!(!model.is_protected(visible));
    assert!(!model.is_protected(model.text().find("VisibleEnd").unwrap()));
    if hidden_label {
        let hidden = model.text().find("\u{2067}HiddenBefore").unwrap();
        assert!(model.is_protected(hidden));
    }
    let findings: Vec<_> = lint::check(&source, &[], None, "system-docs")
        .unwrap()
        .into_iter()
        .filter(|finding| finding.check == "bidi-isolate")
        .map(|finding| (finding.path, finding.line))
        .collect();
    assert_eq!(findings, [(main.clone(), line), (main.clone(), line)]);
    let plain = source_plain(&main).unwrap();
    assert!(plain.contains("VisibleBefore"));
    assert!(plain.contains("VisibleEnd"));
    assert!(!plain.contains("AfterRealEnd"));
}

#[test]
fn many_owned_closers_do_not_turn_live_openers_into_repeated_suffix_scans() {
    let mut body = "\\relax[\\renewcommand{\\sample}{]}\n".repeat(100_000);
    body.push_str("\u{2067}VisibleBefore\\par after\u{2069} VisibleEnd");
    check(&body, "", false);
}

#[test]
fn label_arguments_cannot_close_an_optional_bracket_after_document_end() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.tex");
    let text = "\\begin{document}\n\\label[\u{2067}ok\u{2069}]{x}\n\\label[\u{2067}Visible\n\\end{document}\n]{x}";
    fs::write(&path, text).unwrap();
    let source = Source::load(&path).unwrap();
    let Source::Tex(model) = &source else {
        unreachable!()
    };
    assert!(model.is_protected(text.find("\u{2067}ok").unwrap()));
    assert!(model.is_protected(text.find("{x}").unwrap() + 1));
    assert!(!model.is_protected(text.find("\u{2067}Visible").unwrap()));
    let findings: Vec<_> = lint::check(&source, &[], None, "system-docs")
        .unwrap()
        .into_iter()
        .filter(|finding| finding.check == "bidi-isolate")
        .collect();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].line, 3);
    assert!(
        findings[0]
            .message
            .starts_with("Close the LRI, RLI, or FSI isolate")
    );
}

#[test]
fn repeated_unfinished_definition_groups_leave_live_prose_unprotected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.tex");
    let repetitions = 20_000;
    let text = format!(
        "\\begin{{document}}\n{}\u{2067}Visible\n\\end{{document}}",
        "\\newcommand{\n".repeat(repetitions)
    );
    fs::write(&path, &text).unwrap();
    let source = Source::load(&path).unwrap();
    let Source::Tex(model) = &source else {
        unreachable!()
    };
    assert_eq!(model.body_end, text.find(r"\end{document}").unwrap());
    assert!(!model.is_protected(text.find("\u{2067}Visible").unwrap()));
    let lines: Vec<_> = lint::check(&source, &[], None, "system-docs")
        .unwrap()
        .into_iter()
        .filter(|finding| finding.check == "bidi-isolate")
        .map(|finding| finding.line)
        .collect();
    assert_eq!(lines, [repetitions + 2]);
}

#[test]
fn optional_bracket_protection_obeys_nested_and_original_document_bounds() {
    for (body, suffix, hidden) in [
        (
            "\\item[Label[\u{2067}HiddenBefore\\par after\u{2069}]Tail]\n\u{2067}VisibleBefore\\par after\u{2069} VisibleEnd",
            "",
            true,
        ),
        (
            "\\item[Label \u{2067}VisibleBefore\\par after\u{2069} VisibleEnd",
            "",
            false,
        ),
        (
            "\\item[Label\\renewcommand{\\sample}{]}\n\u{2067}VisibleBefore\\par after\u{2069} VisibleEnd",
            "",
            false,
        ),
        (
            "\\item[Label \u{2067}VisibleBefore\\par after\u{2069} VisibleEnd",
            "]\n",
            false,
        ),
    ] {
        check(body, suffix, hidden);
    }
}
