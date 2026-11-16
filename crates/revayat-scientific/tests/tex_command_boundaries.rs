//! Direct native ports of the original TeX closure regression cases.
use revayat_scientific::tex::{SourceClosure, source_closure};
use std::fs;
use std::path::Path;

fn closure(root: &Path, text: &str) -> anyhow::Result<SourceClosure> {
    fs::write(root.join("doc.tex"), text)?;
    source_closure(&root.join("doc.tex"), None)
}

#[test]
fn test_odd_backslash_runs_expand_and_preserve_linebreaks() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::write(root.join("chapter.tex"), "CHAPTER CONTENT\n").unwrap();
    for count in [1, 3, 5, 7, 9] {
        for command in ["input", "include"] {
            let prefix = format!("Intro\n{}", "\\".repeat(count - 1));
            let result = closure(&root, &format!("{prefix}\\{command}{{chapter}}\nTail")).unwrap();
            assert_eq!(result.text, format!("{prefix}CHAPTER CONTENT\n\nTail"));
            assert_eq!(
                result.sources,
                vec![root.join("doc.tex"), root.join("chapter.tex")]
            );
            assert_eq!(
                result.location(result.text.find("CHAPTER").unwrap() as isize),
                (root.join("chapter.tex"), 1)
            );
            assert_eq!(
                result.location(result.text.find("Tail").unwrap() as isize),
                (root.join("doc.tex"), 3)
            );
        }
    }
}

#[test]
fn test_even_backslash_runs_are_not_includes() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    for count in [2, 4, 6, 8] {
        let text = format!("Intro\n{}input{{missing}}\nTail", "\\".repeat(count));
        let result = closure(&root, &text).unwrap();
        assert_eq!(result.text, text);
        assert_eq!(result.sources, vec![root.join("doc.tex")]);
    }
}

#[test]
fn test_comments_and_verbatim_do_not_expand() {
    let temp = tempfile::tempdir().unwrap();
    let text = "% \\\\\\input{missing}\n\\verb|\\\\\\input{missing}|\n\\begin{verbatim}\\\\\\input{missing}\\end{verbatim}\n\\begin{Verbatim}\\\\\\input{missing}\\end{Verbatim}\n";
    let result = closure(temp.path(), text).unwrap();
    assert_eq!(result.text, text);
    assert_eq!(result.sources.len(), 1);
}

#[test]
fn test_missing_cyclic_dynamic_and_includeonly_still_fail() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("chapter.tex"), r"\input{doc}").unwrap();
    for command in [
        "input{missing}",
        "include{missing}",
        r"input{\macro}",
        "includeonly{chapter}",
        "input{chapter}",
    ] {
        assert!(
            closure(temp.path(), &format!("Intro{}{command}", "\\".repeat(3))).is_err(),
            "{command}"
        );
    }
}

#[test]
fn test_nested_and_unbraced_include_location_mapping() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::write(root.join("nested.tex"), "NESTED\n").unwrap();
    fs::write(
        root.join("chapter.tex"),
        format!("Chapter\n{}input nested\nEnd", "\\".repeat(3)),
    )
    .unwrap();
    let result = closure(
        &root,
        &format!("Start\n{}input{{chapter}}\nFinish", "\\".repeat(3)),
    )
    .unwrap();
    assert_eq!(
        result.sources,
        vec![
            root.join("doc.tex"),
            root.join("chapter.tex"),
            root.join("nested.tex")
        ]
    );
    assert!(result.text.contains("\\\\NESTED"));
    for (token, path, line) in [
        ("NESTED", "nested.tex", 1),
        ("End", "chapter.tex", 3),
        ("Finish", "doc.tex", 3),
    ] {
        assert_eq!(
            result.location(result.text.find(token).unwrap() as isize),
            (root.join(path), line)
        );
    }
}

#[test]
fn test_crlf_and_mixed_newlines_are_preserved_with_locations() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    for child in ["\n", "\r\n"] {
        for parent in ["\n", "\r\n"] {
            fs::write(root.join("chapter.tex"), format!("CHAPTER{child}")).unwrap();
            let result = closure(
                &root,
                &format!(
                    "Intro{parent}{}input{{chapter}}{parent}Tail",
                    "\\".repeat(3)
                ),
            )
            .unwrap();
            assert_eq!(
                result.text,
                format!("Intro{parent}\\\\CHAPTER{child}{parent}Tail")
            );
            assert_eq!(
                result.location(result.text.find("CHAPTER").unwrap() as isize),
                (root.join("chapter.tex"), 1)
            );
            assert_eq!(
                result.location(result.text.find("Tail").unwrap() as isize),
                (root.join("doc.tex"), 3)
            );
        }
    }
}

#[test]
#[ignore = "requires XeLaTeX and Poppler; required scientific CI executes this test"]
fn test_real_tex_linebreak_then_input_agrees_with_closure() -> anyhow::Result<()> {
    use revayat_scientific::runtime::{CommandSpec, run};
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    fs::write(root.join("chapter.tex"), b"IncludedUniqueMarker")?;
    let text = format!(
        "\\documentclass{{article}}\\begin{{document}}First{}input{{chapter}}\\end{{document}}",
        "\\".repeat(3)
    );
    let result = closure(root, &text)?;
    let mut command = CommandSpec::new("xelatex").args([
        "-no-shell-escape",
        "-interaction=nonstopmode",
        "-halt-on-error",
        "doc.tex",
    ]);
    command.cwd = Some(root.into());
    command.timeout = std::time::Duration::from_secs(45);
    assert!(run(&command)?.success());
    let extracted =
        run(&CommandSpec::new("pdftotext")
            .args([root.join("doc.pdf").into_os_string(), "-".into()]))?;
    assert!(extracted.success());
    assert!(extracted.stdout_text().contains("IncludedUniqueMarker"));
    assert!(result.text.contains("IncludedUniqueMarker"));
    Ok(())
}
