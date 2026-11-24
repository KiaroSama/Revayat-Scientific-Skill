use revayat_scientific::lint::{self, Source};
use revayat_scientific::tex::source_closure;
use revayat_scientific::text_order::source_plain;
use std::fs;

const LITERALS: [&str; 7] = [
    r"\verb|\input{absent}|",
    r"\verb*§\input{absent}§",
    r"\begin{verbatim}\input{absent}\end{verbatim}",
    r"\begin{verbatim*}\input{absent}\end{verbatim*}",
    r"\begin{Verbatim}\input{absent}\end{Verbatim}",
    r"\begin{lstlisting}\input{absent}\end{lstlisting}",
    r"\begin{minted}\input{absent}\end{minted}",
];

fn declaration(command: &str, suffix: &str) -> String {
    let prefix = if command == "renewcommand" {
        "\\newcommand{\\bad}{unused}\n"
    } else {
        ""
    };
    format!("{prefix}\\{command}{{\\bad}}{{\n{suffix}")
}

fn check_load(source: &str, child: bool) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    fs::write(&main, source).unwrap();
    if child {
        fs::write(root.join("child.tex"), "IncludedMarker").unwrap();
    }
    let mut expected = vec![main.clone()];
    if child {
        expected.push(root.join("child.tex"));
    }
    let closure = source_closure(&main, None)
        .unwrap_or_else(|error| panic!("source={source:?}: closure failed: {error:#}"));
    assert_eq!(closure.sources, expected, "source={source:?}");
    assert_eq!(closure.text.contains("IncludedMarker"), child);
    let loaded = Source::load(&main)
        .unwrap_or_else(|error| panic!("source={source:?}: model failed: {error:#}"));
    let Source::Tex(model) = loaded else {
        unreachable!()
    };
    assert_eq!(model.closure.sources, expected);
}

#[test]
fn unfinished_body_keeps_complete_literal_payload_opaque() {
    for command in ["newcommand", "renewcommand"] {
        for literal in LITERALS {
            check_load(&declaration(command, literal), false);
        }
    }
}

#[test]
fn unfinished_body_still_discovers_genuine_input() {
    for command in ["newcommand", "renewcommand"] {
        check_load(&declaration(command, r"\input{child}"), true);
    }
}

#[test]
fn complete_definition_body_keeps_literal_payload_opaque() {
    for command in ["newcommand", "renewcommand"] {
        for literal in LITERALS {
            check_load(&declaration(command, &format!("{literal}}}")), false);
        }
    }
}

#[test]
fn incomplete_recovery_literals_do_not_introduce_a_whole_tail_error() {
    for command in ["newcommand", "renewcommand"] {
        for literal in [
            r"\verb|unclosed \input{child}",
            r"\begin{verbatim}unclosed \input{child}",
        ] {
            check_load(&declaration(command, literal), true);
        }
    }
}

#[test]
fn ordinary_unclosed_literals_keep_the_existing_validation_error() {
    for literal in [r"\verb|unclosed", r"\begin{verbatim}unclosed"] {
        let directory = tempfile::tempdir().unwrap();
        let main = directory.path().join("main.tex");
        fs::write(&main, literal).unwrap();
        let error = source_closure(&main, None).unwrap_err();
        assert!(
            error.to_string().contains("unterminated"),
            "{literal:?}: {error:#}"
        );
        assert!(Source::load(&main).is_err());
    }
}

#[test]
fn recovery_resumes_reference_parity_at_the_complete_literal_endpoint() {
    for command in ["newcommand", "renewcommand"] {
        for literal in [r"\verb|literal|", r"\verb\literal\"] {
            for slashes in 1..=2 {
                let child = slashes == 1;
                let filename = if child { "child" } else { "absent" };
                let suffix = format!("{literal}{}input{{{filename}}}", "\\".repeat(slashes));
                check_load(&declaration(command, &suffix), child);
            }
        }
    }
}

#[test]
fn unfinished_body_cannot_export_nested_pending_after_complete_literal() {
    for command in ["newcommand", "renewcommand"] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let main = root.join("main.tex");
        let child = root.join("declaration.tex");
        fs::write(
            &child,
            format!("\\{command}{{\\outer}}{{\n\\verb|literal|\n\\newcommand"),
        )
        .unwrap();
        fs::write(
            &main,
            "\\newcommand{\\outer}{unused}\n\\newcommand{\\sample}[1]{#1}\n\\begin{document}\n\u{2067}VisibleBefore\\par after\u{2069}\n\\input declaration \\sample{\\end{document}}\n\\input{missing-after-real-end}\nUnexpectedTail\n",
        )
        .unwrap();
        let source = Source::load(&main).unwrap();
        let Source::Tex(model) = &source else {
            unreachable!()
        };
        assert_eq!(model.closure.sources, [main.clone(), child]);
        let findings: Vec<_> = lint::check(&source, &[], None, "system-docs")
            .unwrap()
            .into_iter()
            .filter(|finding| finding.check == "bidi-isolate")
            .map(|finding| (finding.path, finding.line))
            .collect();
        assert_eq!(findings, [(main.clone(), 4), (main.clone(), 4)]);
        match source_plain(&main) {
            Ok(plain) => assert!(!plain.contains("UnexpectedTail")),
            Err(error) => assert_eq!(error.to_string(), "unbalanced TeX prose argument"),
        }
    }
}
