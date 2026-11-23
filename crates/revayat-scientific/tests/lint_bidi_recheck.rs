use revayat_scientific::lint::{self, Finding, Source};
use std::fs;

fn bidi_findings(extension: &str, body: &str) -> Vec<Finding> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(format!("source.{extension}"));
    let document = match extension {
        "html" => format!("<!doctype html>\n<html lang=\"fa\"><body>\n{body}\n</body></html>"),
        "tex" => {
            format!("\\documentclass{{article}}\n\\begin{{document}}\n{body}\n\\end{{document}}")
        }
        _ => panic!("unsupported fixture extension"),
    };
    fs::write(&path, document).unwrap();
    lint::check(&Source::load(&path).unwrap(), &[], None, "system-docs")
        .unwrap()
        .into_iter()
        .filter(|finding| finding.check == "bidi-isolate")
        .collect()
}

#[test]
fn balanced_html_isolate_survives_excluded_inline_content() {
    for inline in [
        "<span lang=\"en\">API</span>",
        "<span dir=\"ltr\">API</span>",
        "<code>API</code>",
        "<span hidden>API</span>",
        "<cite>API</cite>",
    ] {
        let source = format!("<p>\u{2067}Rust {inline} برای پژوهش\u{2069}</p>");
        let findings = bidi_findings("html", &source);
        assert!(findings.is_empty(), "{inline}: {findings:#?}");
    }
}

#[test]
fn balanced_html_isolate_can_cross_collapsible_source_newline() {
    let findings = bidi_findings("html", "<p>\u{2067}Rust برای\nپژوهش\u{2069}</p>");
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn tex_isolate_cannot_cross_explicit_paragraph_boundary() {
    let findings = bidi_findings("tex", "\u{2067}Rust برای پژوهش\\par نمونه\u{2069}");
    assert_eq!(findings.len(), 2, "{findings:#?}");
}

#[test]
fn existing_same_line_controls_and_real_html_blocks_remain_distinct() {
    for body in [
        "<p>\u{2067}Rust <em>برای</em> پژوهش\u{2069}</p>",
        "<p>&#x2067;Rust <em>برای</em> پژوهش&#x2069;</p>",
        "<p>\u{2067}Rust <!-- ignored \u{2069} --> پژوهش\u{2069}</p>",
    ] {
        assert!(bidi_findings("html", body).is_empty(), "{body:?}");
    }
    assert_eq!(
        bidi_findings("html", "<p>\u{2067}Rust</p><p>پژوهش\u{2069}</p>").len(),
        2
    );
    assert!(bidi_findings("tex", "\u{2067}Rust \\lr{API} برای پژوهش\u{2069}").is_empty());
}

#[test]
fn waived_findings_do_not_hide_later_unwaived_isolate_errors() {
    let mut body = "<p>\u{2067}Rust</p><!-- fa-lint: allow bidi-isolate -->\n".repeat(64);
    body.push_str("\n\n<p>\u{2067}پژوهش</p>");
    let findings = bidi_findings("html", &body);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].line, 69);
}

#[test]
fn explicit_boundaries_and_source_formatting_are_distinct() {
    for body in [
        "\u{2067}Rust\n\nپژوهش\u{2069}",
        "\u{2067}Rust\r\n \t\r\nپژوهش\u{2069}",
        "\u{2067}Rust\r \t\rپژوهش\u{2069}",
        "\u{2067}Rust\\par{}پژوهش\u{2069}",
        "\\begin{itemize}\\item \u{2067}Rust\\item پژوهش\u{2069}\\end{itemize}",
    ] {
        assert_eq!(bidi_findings("tex", body).len(), 2, "{body:?}");
    }
    for body in [
        "\u{2067}Rust\nپژوهش\u{2069}",
        "\u{2067}Rust\r\nپژوهش\u{2069}",
        "\u{2067}Rust\rپژوهش\u{2069}",
        "\u{2067}Rust\n% comment-only lines do not start a paragraph\nپژوهش\u{2069}",
        "\u{2067}Rust \\lr{\\par} پژوهش\u{2069}",
        "\u{2067}Rust \\verb|\\par| پژوهش\u{2069}",
        "\u{2067}Rust \\\\par پژوهش\u{2069}",
        "\u{2067}Rust \\parbox{test} پژوهش\u{2069}",
    ] {
        assert!(bidi_findings("tex", body).is_empty(), "{body:?}");
    }
    for body in [
        "<p>\u{2067}Rust<br>پژوهش\u{2069}</p>",
        "<p>\u{2067}Rust\u{2029}پژوهش\u{2069}</p>",
        "<p>&#x2067;Rust</p>\n<p>پژوهش&#x2069;</p>",
    ] {
        assert_eq!(bidi_findings("html", body).len(), 2, "{body:?}");
    }
    for extension in ["html", "tex"] {
        assert!(bidi_findings(extension, "\u{2067}Rust\u{2028}پژوهش\u{2069}").is_empty());
    }
}

#[test]
fn bidi_diagnostic_budget_counts_only_emitted_errors_and_is_exact() {
    let mut body = "<p>\u{2067}Rust</p>\n".repeat(63);
    body.push_str("<p>\u{2069}پژوهش\u{2067}</p>");
    assert_eq!(bidi_findings("html", &body).len(), 64);
    assert!(
        bidi_findings(
            "html",
            &"<p>\u{2067}Rust</p><!-- fa-lint: allow bidi-isolate -->\n".repeat(80)
        )
        .is_empty()
    );
}

#[test]
fn waivers_for_one_line_do_not_hide_other_openers_in_the_same_paragraph() {
    for control in ['\u{2067}', '\u{2069}'] {
        let body =
            format!("<p>{control}Rust<!-- fa-lint: allow bidi-isolate -->\n\n{control}پژوهش</p>");
        let findings = bidi_findings("html", &body);
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].line, 5);
    }
    let body = "<p>\u{2067}Rust<!-- fa-lint: allow bidi-isolate -->\n\n\u{2066}API\u{2069} \u{2068}پژوهش</p>";
    let findings = bidi_findings("html", body);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].line, 5);
}

#[test]
fn html_entities_and_inline_markup_keep_original_finding_locations() {
    let body = "<p>&amp;&#x2067;Rust <span lang=\"en\">API</span>\nپژوهش</p>\n<p>&amp;&#x2069;</p>";
    let findings = bidi_findings("html", body);
    assert_eq!(findings.iter().map(|f| f.line).collect::<Vec<_>>(), [3, 5]);
}

#[test]
fn html_preserved_newlines_follow_known_element_and_inline_style_modes() {
    let content = "\u{2067}Rust\nپژوهش\u{2069}";
    for body in [
        format!("<textarea>{content}</textarea>"),
        format!("<p style=\"white-space: pre\">{content}</p>"),
        format!("<p style=\"white-space: pre-wrap\">{content}</p>"),
        format!("<p style=\"white-space: pre-line\">{content}</p>"),
        format!("<p style=\"WHITE-SPACE: PRE !important; white-space: normal\">{content}</p>"),
        format!("<p style=\"white-space-collapse: preserve-breaks\">{content}</p>"),
        format!("<p style=\"white-space: break-spaces\"><em>{content}</em></p>"),
        format!("<div style=\"white-space: pre-wrap\"><p>{content}</p></div>"),
        "<p>\u{2067}Rust <span lang=\"en\" style=\"white-space: pre\">API\nvalue</span>پژوهش\u{2069}</p>".into(),
        "<p>\u{2067}Rust <code>API&#x2029;value</code>پژوهش\u{2069}</p>".into(),
    ] {
        assert_eq!(bidi_findings("html", &body).len(), 2, "{body:?}");
    }
    for body in [
        format!("<textarea style=\"white-space: normal\">{content}</textarea>"),
        format!("<p style=\"white-space: nowrap\">{content}</p>"),
        format!("<p style=\"white-space-collapse: pre\">{content}</p>"),
        "<p>\u{2067}Rust <span hidden style=\"white-space: pre\">API\nvalue</span>پژوهش\u{2069}</p>".into(),
        format!(
            "<div style=\"white-space: pre-wrap\"><p style=\"white-space: normal\">{content}</p></div>"
        ),
    ] {
        assert!(bidi_findings("html", &body).is_empty(), "{body:?}");
    }
}

#[test]
fn tex_paragraph_findings_keep_their_original_included_file_locations() {
    let directory = tempfile::tempdir().unwrap();
    let main = directory.path().join("main.tex");
    let chapter = directory.path().join("chapter.tex");
    fs::write(&main, "\\documentclass{article}\n\\begin{document}\n\u{2067}Rust \\input{chapter}\n\\end{document}").unwrap();
    fs::write(&chapter, "\\par\nپژوهش\u{2069}\n").unwrap();
    let findings: Vec<_> = lint::check(&Source::load(&main).unwrap(), &[], None, "system-docs")
        .unwrap()
        .into_iter()
        .filter(|finding| finding.check == "bidi-isolate")
        .map(|finding| (finding.path, finding.line))
        .collect();
    assert_eq!(findings, [(main, 3), (chapter, 2)]);
}
