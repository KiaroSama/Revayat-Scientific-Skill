use anyhow::Result;
use revayat_scientific::{
    runtime::{CommandSpec, run},
    tex::source_closure,
};
use std::{fs, path::Path};
fn fixture(root: &Path, command: &str, child: &str) -> revayat_scientific::tex::SourceClosure {
    fs::write(root.join(child), "IncludedMarker\n").unwrap();
    fs::write(root.join("main.tex"), format!("Before\n{command}\nAfter")).unwrap();
    source_closure(&root.join("main.tex"), None).unwrap()
}
#[test]
fn test_unseparated_digit_and_punctuation_filenames_are_included() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    for (command, child) in [
        (r"\input2", "2.tex"),
        (r"\input2.tex", "2.tex"),
        (r"\input_figure", "_figure.tex"),
        (r"\input-part", "-part.tex"),
        (r"\input./2.tex", "2.tex"),
    ] {
        let closure = fixture(&root, command, child);
        assert!(closure.text.contains("IncludedMarker"));
        assert_eq!(
            closure.location(closure.text.find("IncludedMarker").unwrap() as isize),
            (root.join(child), 1)
        );
        assert_eq!(
            closure.location(closure.text.find("After").unwrap() as isize),
            (root.join("main.tex"), 3)
        );
    }
}
#[test]
fn test_custom_control_words_do_not_become_includes() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    for name in [
        "inputenc",
        "inputExtra",
        "includegraphics",
        "includeonlyExtra",
    ] {
        let closure = fixture(&root, &format!("\\{name}{{missing}}"), "2.tex");
        assert_eq!(closure.sources, [root.join("main.tex")]);
    }
}
#[test]
fn test_unseparated_missing_cycle_and_root_escape_are_blocking() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("job");
    fs::create_dir(&root).unwrap();
    let path = root.join("main.tex");
    fs::write(temp.path().join("outside.tex"), "outside sentinel").unwrap();
    for command in [
        r"\input3",
        r"\input_undefined",
        r"\input../outside.tex",
        r"\includeonly2",
    ] {
        fs::write(&path, command).unwrap();
        assert!(source_closure(&path, None).is_err(), "{command}");
    }
    fs::write(root.join("2.tex"), r"\input{main}").unwrap();
    fs::write(&path, r"\input2").unwrap();
    assert!(
        source_closure(&path, None)
            .unwrap_err()
            .to_string()
            .contains("cycle")
    );
}
#[test]
fn test_literal_comments_and_even_backslashes_stay_inert() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    for command in [
        r"\verb|\input2|",
        "% \\input2",
        r"\\input2",
        r"\begin{verbatim}\input2\end{verbatim}",
    ] {
        let closure = fixture(&root, command, "2.tex");
        assert_eq!(closure.sources, [root.join("main.tex")]);
        assert!(!closure.text.contains("IncludedMarker"));
    }
    let closure = fixture(&root, r"\\\input2", "2.tex");
    assert!(closure.text.contains("\\\\IncludedMarker"));
}
#[test]
#[ignore = "requires native XeLaTeX and Poppler; required scientific CI executes this test"]
fn test_real_compiler_and_source_closure_agree_on_numeric_input() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    fixture(root, r"\input2", "2.tex");
    fs::write(
        root.join("main.tex"),
        r"\documentclass{article}\begin{document}\input2 \end{document}",
    )?;
    let mut command = CommandSpec::new("xelatex").args([
        "-no-shell-escape",
        "-halt-on-error",
        "-interaction=nonstopmode",
        "main.tex",
    ]);
    command.cwd = Some(root.into());
    command.timeout = std::time::Duration::from_secs(45);
    let output = run(&command)?;
    assert!(output.success(), "{}", output.stdout_text());
    let extracted =
        run(&CommandSpec::new("pdftotext")
            .args([root.join("main.pdf").into_os_string(), "-".into()]))?;
    assert!(extracted.success());
    assert!(extracted.stdout_text().contains("IncludedMarker"));
    assert!(
        source_closure(&root.join("main.tex"), None)?
            .text
            .contains("IncludedMarker")
    );
    assert_eq!(fs::read_to_string(root.join("2.tex"))?, "IncludedMarker\n");
    Ok(())
}
