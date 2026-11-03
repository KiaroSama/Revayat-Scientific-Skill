use revayat_scientific::source::TexSource;
use revayat_scientific::tex::{masked_tex, plain_tex};
use std::fs;

fn source(body: &str) -> (tempfile::TempDir, TexSource) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("main.tex");
    fs::write(
        &path,
        format!("\\begin{{document}}\n{body}\n\\end{{document}}"),
    )
    .unwrap();
    let model = TexSource::load(&path).unwrap();
    (temp, model)
}
fn protected(model: &TexSource, text: &str) -> bool {
    model.is_protected(model.text().find(text).unwrap())
}

#[test]
fn test_inline_literal_is_protected() {
    for opening in [r"\verb|", r"\verb*|"] {
        let (_temp, model) = source(&format!("{opening}كي 123| متن"));
        assert!(protected(&model, "كي"));
        assert!(!protected(&model, "متن"));
    }
}
#[test]
fn test_numeric_punctuation_and_starred_letter_delimiters() {
    for literal in [
        r"\verb1\includegraphics{missing.png}1",
        r"\verb*Z\includegraphics{missing.png}Z",
        r"\verb@\includegraphics{missing.png}@",
    ] {
        let (_temp, model) = source(&format!("{literal} متن"));
        assert!(model.image_references().is_empty());
        assert!(protected(&model, "missing.png"));
        assert!(!protected(&model, "متن"));
    }
}
#[test]
fn test_malformed_literals_fail_without_masking_following_lines() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bad.tex");
    for literal in [
        r"\verb|unclosed",
        "\\verb|first\nsecond|",
        r"\begin{verbatim}no ending",
        r"\begin{minted}no ending",
    ] {
        fs::write(&path, format!("{literal}\nمتن")).unwrap();
        assert!(TexSource::load(&path).is_err(), "{literal}");
    }
}
#[test]
fn test_macro_with_verb_prefix_is_not_literal() {
    let (_temp, model) = source(r"\verbfoo{Label} متن");
    assert!(!protected(&model, "متن"));
    assert!(model.literals.is_empty());
}
#[test]
fn test_starred_and_unstarred_literal_environments_are_protected() {
    for env in ["verbatim", "verbatim*", "Verbatim", "lstlisting", "minted"] {
        let (_temp, model) = source(&format!("\\begin{{{env}}}كي 123\\end{{{env}}} متن"));
        assert!(protected(&model, "كي"));
        assert!(!protected(&model, "متن"));
    }
}
#[test]
fn test_percent_inside_literal_does_not_hide_following_prose() {
    for literal in [
        r"\verb|%|",
        r"\verb*|%|",
        "\\begin{verbatim}\n%\n\\end{verbatim}",
    ] {
        let (_temp, model) = source(&format!("{literal} كي 123"));
        let pos = model.text().find("كي").unwrap();
        assert!(!model.is_protected(pos));
        assert!(!model.inert(pos));
    }
}
#[test]
fn test_literal_waiver_cannot_suppress_same_or_following_line() {
    for separator in [" ", "\n"] {
        let (_temp, model) = source(&format!(r"\verb|% fa-lint: allow all|{separator}كي"));
        assert!(!model.suppressed(model.text().find("كي").unwrap(), "arabic-letters"));
    }
}
#[test]
fn test_comments_after_paired_backslashes_remain_comments() {
    for count in [0, 2, 4, 6] {
        let (_temp, model) = source(&format!("Text{}% كي 123", "\\".repeat(count)));
        let pos = model.text().find("كي").unwrap();
        assert!(model.is_protected(pos));
        assert!(model.inert(pos));
    }
}
#[test]
fn test_escaped_percent_is_not_a_comment() {
    for count in [1, 3, 5] {
        let (_temp, model) = source(&format!("Text{}% كي", "\\".repeat(count)));
        assert!(!protected(&model, "كي"));
    }
}
#[test]
fn test_real_waiver_after_linebreak_is_recognized() {
    let (_temp, model) = source("Text\\\\% fa-lint: allow arabic-letters\nكي");
    let pos = model.text().find("كي").unwrap();
    assert!(model.suppressed(pos, "arabic-letters"));
    assert!(!model.suppressed(pos, "unisolated-number"));
}

#[test]
fn protected_comments_cannot_waive_neighboring_live_prose() {
    for body in [
        "\\begin{latin}% fa-lint: allow all\n\\end{latin} كي",
        "\\en{Original% fa-lint: allow all\n} كي",
        "$x% fa-lint: allow all\n$ كي",
        "\\begin{equation}% fa-lint: allow all\nx\\end{equation} كي",
    ] {
        let (_temp, model) = source(body);
        let pos = model.text().find("كي").unwrap();
        assert!(!model.is_protected(pos));
        assert!(!model.suppressed(pos, "arabic-letters"), "{body}");
    }
    let (_temp, model) = source("% fa-lint: allow arabic-letters\nكي");
    assert!(model.suppressed(model.text().find("كي").unwrap(), "arabic-letters"));
}
#[test]
fn test_literal_images_are_not_asset_dependencies() {
    for body in [
        r"\verb|\includegraphics{missing.png}|",
        r"\verb*|\includegraphics{missing.png}|",
        "\\begin{verbatim}\n\\includegraphics{missing.png}\n\\end{verbatim}",
        r"\begin{verbatim*}\includegraphics{missing.png}\end{verbatim*}",
        "Text\\\\% \\includegraphics{missing.png}",
    ] {
        let (_temp, model) = source(body);
        assert!(model.image_references().is_empty(), "{body}");
    }
}
#[test]
fn test_live_graphics_after_linebreak_are_not_lost() {
    for count in [1, 3, 5] {
        let (_temp, model) = source(&format!(
            "Text{}includegraphics* [width=2cm]{{real.png}}",
            "\\".repeat(count)
        ));
        let refs = model.image_references();
        assert_eq!(
            refs.iter().map(|(_, s)| s.as_str()).collect::<Vec<_>>(),
            ["real.png"]
        );
        assert!(model.text()[refs[0].0..].starts_with(r"\includegraphics* [width=2cm]"));
    }
}
#[test]
fn test_escaped_graphics_commands_are_not_dependencies() {
    for count in [2, 4, 6] {
        let (_temp, model) = source(&format!(
            "Text{}includegraphics{{missing.png}}",
            "\\".repeat(count)
        ));
        assert!(model.image_references().is_empty());
    }
}
#[test]
fn test_fake_isolates_and_math_inside_literal_do_not_affect_prose() {
    let (_temp, model) = source(r"\verb|\en{Fake} $| كي \en{Real} $x$ متن");
    assert_eq!(
        model
            .isolates
            .iter()
            .map(|x| x.body.as_str())
            .collect::<Vec<_>>(),
        ["Real"]
    );
    assert!(!protected(&model, "كي"));
    assert!(!protected(&model, "متن"));
    assert!(protected(&model, "x$"));
}
#[test]
fn test_fake_document_begin_does_not_end_preamble() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("main.tex");
    let text =
        "% \\begin{document}\n\\newcommand{\\sample}{كي}\n\\begin{document}\nمتن\n\\end{document}";
    fs::write(&path, text).unwrap();
    let model = TexSource::load(&path).unwrap();
    assert_eq!(
        model.preamble_end,
        text.rfind(r"\begin{document}").unwrap() + r"\begin{document}".len()
    );
    assert!(model.text().find("كي").unwrap() < model.preamble_end);
    assert!(!protected(&model, "متن"));
}
#[test]
fn test_comment_brace_does_not_close_live_argument() {
    let (_temp, model) = source("\\en{Alpha% } fake brace\nBeta} متن");
    assert_eq!(model.isolates.len(), 1);
    assert!(!model.isolates[0].body.contains("fake brace"));
    assert!(model.text()[..model.isolates[0].end].ends_with("Beta}"));
    assert!(protected(&model, "Beta"));
    assert!(!protected(&model, "متن"));
}
#[test]
fn test_nested_include_locations_and_comment_eof_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::write(
        root.join("child.tex"),
        b"% child-only comment without newline",
    )
    .unwrap();
    fs::write(
        root.join("main.tex"),
        "\\begin{document}\n\\input{child} كي\n\\end{document}",
    )
    .unwrap();
    let model = TexSource::load(&root.join("main.tex")).unwrap();
    let pos = model.text().find("كي").unwrap();
    assert!(!model.is_protected(pos));
    assert!(!model.inert(pos));
    assert_eq!(model.location(pos), (root.join("main.tex"), 2));
    assert_eq!(
        model.closure.sources,
        [root.join("main.tex"), root.join("child.tex")]
    );
    assert_eq!(
        fs::read(root.join("child.tex")).unwrap(),
        b"% child-only comment without newline"
    );
}
#[test]
fn test_region_offsets_and_newline_styles() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("main.tex");
    for newline in ["\n", "\r\n"] {
        let text = format!("\\begin{{document}}{newline}\\verb|%| متن{newline}\\end{{document}}");
        fs::write(&path, &text).unwrap();
        let model = TexSource::load(&path).unwrap();
        assert!(!protected(&model, "متن"));
        assert_eq!(model.location(model.text().find("متن").unwrap()).1, 2);
        let masked = masked_tex(&text).unwrap();
        assert_eq!(masked.len(), text.len());
        assert_eq!(
            masked
                .match_indices('\n')
                .map(|(i, _)| i)
                .collect::<Vec<_>>(),
            text.match_indices('\n').map(|(i, _)| i).collect::<Vec<_>>()
        );
    }
}
#[test]
fn test_plain_prose_respects_backslash_command_parity() {
    for count in [2, 4, 6] {
        assert!(
            plain_tex(&format!(
                "Text{}en{{ParentVisibleMarker}} Tail",
                "\\".repeat(count)
            ))
            .unwrap()
            .contains("ParentVisibleMarker")
        );
    }
    for count in [1, 3, 5] {
        assert!(
            !plain_tex(&format!(
                "Text{}en{{ParentVisibleMarker}} Tail",
                "\\".repeat(count)
            ))
            .unwrap()
            .contains("ParentVisibleMarker")
        );
    }
    assert!(
        plain_tex(r"\verb|%| VisibleMarker")
            .unwrap()
            .contains("VisibleMarker")
    );
    assert!(
        !plain_tex(r"\verb|HiddenMarker|")
            .unwrap()
            .contains("HiddenMarker")
    );
}
#[test]
fn test_complete_document_tail_is_not_prose_or_live_assets() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("main.tex");
    let text = "\\begin{document}\nمتن اصلی\n\\verb|\\end{document}|\n% \\end{document}\nمتن پایانی\n\\end{document}\nكي 123 \\includegraphics{missing.png}";
    fs::write(&path, text).unwrap();
    let model = TexSource::load(&path).unwrap();
    let plain = plain_tex(model.text()).unwrap();
    assert!(plain.contains("متن اصلی"));
    assert!(plain.contains("متن پایانی"));
    assert!(!plain.contains("كي"));
    assert!(protected(&model, "كي"));
    assert!(model.inert(model.text().find("كي").unwrap()));
    assert!(model.image_references().is_empty());
    assert!(
        plain_tex(r"Fragment \end{document} FragmentTail")
            .unwrap()
            .contains("FragmentTail")
    );
}
#[test]
fn test_post_document_missing_include_is_not_a_dependency() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("main.tex");
    let text = r"\begin{document}متن\end{document}\input{missing}";
    fs::write(&path, text).unwrap();
    let model = TexSource::load(&path).unwrap();
    assert_eq!(model.closure.sources.len(), 1);
    assert_eq!(plain_tex(model.text()).unwrap(), "متن");
    assert_eq!(fs::read_to_string(path).unwrap(), text);
}

#[test]
fn test_post_document_isolates_cannot_add_lint_findings() {
    use revayat_scientific::lint::{Source, check};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("main.tex");
    fs::write(
        &path,
        r"\begin{document}متن \en{service}\end{document}\en{services} \en{other}",
    )
    .unwrap();
    let model = TexSource::load(&path).unwrap();
    assert_eq!(
        model
            .isolates
            .iter()
            .map(|i| i.body.as_str())
            .collect::<Vec<_>>(),
        ["service"]
    );
    let findings = check(&Source::load(&path).unwrap(), &[], None, "system-docs").unwrap();
    assert!(
        !findings.iter().any(
            |f| ["en-plural", "split-isolate", "terminology-drift"].contains(&f.check.as_str())
        )
    );
}

#[test]
#[ignore = "requires XeLaTeX and Poppler; required scientific CI executes this test"]
fn test_real_tex_ignores_post_document_tail() -> anyhow::Result<()> {
    use revayat_scientific::runtime::{CommandSpec, run};
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let path = root.join("main.tex");
    let text = "\\documentclass{article}\\begin{document}VisibleBodyMarker\n\\verb|\\end{document}|\n\\end{document}UnrenderedTailMarker";
    fs::write(&path, text)?;
    let before = fs::read(&path)?;
    let mut command = CommandSpec::new("xelatex").args([
        "-no-shell-escape",
        "-halt-on-error",
        "-interaction=nonstopmode",
        "main.tex",
    ]);
    command.cwd = Some(root.into());
    command.timeout = std::time::Duration::from_secs(45);
    assert!(run(&command)?.success());
    let extracted =
        run(&CommandSpec::new("pdftotext")
            .args([root.join("main.pdf").into_os_string(), "-".into()]))?;
    assert!(extracted.success());
    assert!(extracted.stdout_text().contains("VisibleBodyMarker"));
    assert!(!extracted.stdout_text().contains("UnrenderedTailMarker"));
    let plain = plain_tex(text)?;
    assert!(plain.contains("VisibleBodyMarker"));
    assert!(!plain.contains("UnrenderedTailMarker"));
    assert_eq!(fs::read(path)?, before);
    Ok(())
}

#[test]
#[ignore = "requires XeLaTeX and Poppler; required scientific CI executes this test"]
fn test_real_tex_accepts_literal_graphics_and_keeps_parent_after_eof_comment() -> anyhow::Result<()>
{
    use revayat_scientific::runtime::{CommandSpec, run};
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let path = root.join("main.tex");
    fs::write(root.join("child.tex"), b"% EOF comment")?;
    fs::write(
        &path,
        "\\documentclass{article}\\begin{document}\n\\verb|\\includegraphics{missing.png}|\n\\input{child} ParentVisibleMarker\\end{document}",
    )?;
    let mut command = CommandSpec::new("xelatex").args([
        "-no-shell-escape",
        "-halt-on-error",
        "-interaction=nonstopmode",
        "main.tex",
    ]);
    command.cwd = Some(root.into());
    command.timeout = std::time::Duration::from_secs(45);
    assert!(run(&command)?.success());
    let extracted =
        run(&CommandSpec::new("pdftotext")
            .args([root.join("main.pdf").into_os_string(), "-".into()]))?;
    assert!(extracted.success());
    assert!(extracted.stdout_text().contains("ParentVisibleMarker"));
    let model = TexSource::load(&path)?;
    assert!(model.image_references().is_empty());
    assert!(!model.is_protected(model.text().find("ParentVisibleMarker").unwrap()));
    Ok(())
}
