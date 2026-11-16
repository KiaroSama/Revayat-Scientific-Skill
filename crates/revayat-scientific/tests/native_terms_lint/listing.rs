// Live TeX listing boundaries and direction/bookmark context.
fn tex_source(d: &tempfile::TempDir, body: &str) -> Source {
    let path = d.path().join("source.tex");
    fs::write(
        &path,
        format!("\\begin{{document}}\n{body}\n\\end{{document}}"),
    )
    .unwrap();
    Source::load(&path).unwrap()
}
#[test]
fn test_real_listing_openers_remain_available_to_direction_checks() {
    let d = tempfile::tempdir().unwrap();
    for env in ["verbatim", "verbatim*", "Verbatim", "lstlisting", "minted"] {
        let s = tex_source(&d, &format!("\\begin{{{env}}}\nCodeMarker\n\\end{{{env}}}"));
        let opener = s.text().find(&format!("\\begin{{{env}}}")).unwrap();
        assert!(!s.inert(opener));
        assert!(s.is_protected(opener));
        let marker = s.text().find("CodeMarker").unwrap();
        assert!(s.inert(marker));
        assert!(s.is_protected(marker));
    }
}
#[test]
fn test_fake_listing_openers_remain_inert() {
    let d = tempfile::tempdir().unwrap();
    for body in [
        r"\verb|\begin{verbatim}|",
        "% \\begin{verbatim}",
        "\\begin{verbatim}\n\\begin{lstlisting}\n\\end{verbatim}",
    ] {
        let s = tex_source(&d, body);
        let marker = if body.contains("lstlisting") {
            r"\begin{lstlisting}"
        } else {
            r"\begin{verbatim}"
        };
        assert!(s.inert(s.text().find(marker).unwrap()));
    }
}
#[test]
fn test_ignored_direction_and_bookmark_context_cannot_hide_live_findings() {
    let d = tempfile::tempdir().unwrap();
    let listing = "\\begin{verbatim}\nCodeMarker\n\\end{verbatim}";
    let image = r"\includegraphics{missing.png}";
    let heading = r"\section{\en{Title}}";
    for fake in [
        r"\verb|\begin{latin}\pdfstringdefDisableCommands|",
        "% \\begin{latin}\\pdfstringdefDisableCommands",
        r"\\begin{latin}\\pdfstringdefDisableCommands",
    ] {
        let s = tex_source(&d, &format!("{fake}\n{listing}\n{image}\n{heading}"));
        let found = lint::check(&s, &[], None, "system-docs").unwrap();
        for id in ["code-direction", "figure-direction", "bookmark-guard"] {
            assert!(found.iter().any(|f| f.check == id), "{fake}: {found:?}");
        }
    }
    let s = tex_source(
        &d,
        &format!(
            "\\pdfstringdefDisableCommands{{}}\n\\begin{{latin}}\n{listing}\n{image}\n\\end{{latin}}\n{heading}"
        ),
    );
    assert!(
        !lint::check(&s, &[], None, "system-docs")
            .unwrap()
            .iter()
            .any(|f| ["code-direction", "figure-direction", "bookmark-guard"]
                .contains(&f.check.as_str()))
    );
}
#[test]
fn test_listing_and_figure_require_live_containing_direction_scopes() {
    let d = tempfile::tempdir().unwrap();
    let listing = "\\begin{verbatim}\nCodeMarker\n\\end{verbatim}";
    let image = r"\includegraphics{missing.png}";
    let cases = [
        (
            format!(
                "\\begin{{latin}}\n{}{listing}\n\\end{{latin}}",
                "متن\n".repeat(200)
            ),
            vec![],
        ),
        (
            format!("\\begin{{latin}}\n\\end{{latin}}\n{listing}"),
            vec!["code-direction"],
        ),
        (
            format!("\\LR{{earlier}}\n{image}"),
            vec!["figure-direction"],
        ),
        (
            format!("\\begin{{LTR}}\n\\begin{{latin}}\n\\end{{latin}}\n{image}\n\\end{{LTR}}"),
            vec![],
        ),
        (format!("\\LR{{{image}}}"), vec![]),
        (
            format!("\\begin{{latin}}\n{listing}\n\\end{{latin}}\n{image}"),
            vec!["figure-direction"],
        ),
    ];
    for (body, expected) in cases {
        let s = tex_source(&d, &body);
        let found = lint::check(&s, &[], None, "system-docs").unwrap();
        let checks: Vec<_> = found
            .iter()
            .filter(|f| ["code-direction", "figure-direction"].contains(&f.check.as_str()))
            .map(|f| f.check.as_str())
            .collect();
        assert_eq!(checks, expected, "{body}");
    }
}
#[test]
fn test_real_listing_inside_preamble_remains_inert() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("source.tex");
    fs::write(&p,"\\begin{verbatim}\nPreambleLiteral\n\\end{verbatim}\n\\begin{document}\nBodyMarker\n\\end{document}").unwrap();
    let s = Source::load(&p).unwrap();
    assert!(s.inert(0));
    assert!(!s.is_protected(s.text().find("BodyMarker").unwrap()));
}
