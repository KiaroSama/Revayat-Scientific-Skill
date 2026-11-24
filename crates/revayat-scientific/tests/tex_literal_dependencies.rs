//! The derived literal view and dependency admission share original data bounds.
use revayat_scientific::lint::{self, Source};
use revayat_scientific::tex::source_closure;
use revayat_scientific::text_order::source_plain;
use std::fs;

const CHILD: &str = "\u{2067}IncludedBody\\par IncludedTail\u{2069}\n";

fn observe(
    label: &str,
    candidate: &str,
    files: &[(&str, &str)],
    dependencies: &[&str],
    visible_child: bool,
    failures: &mut Vec<String>,
) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    for (name, text) in files {
        fs::write(root.join(name), text).unwrap();
    }
    fs::write(
        &main,
        format!("\\begin{{document}}\n\u{2067}VisibleBefore\\par after\u{2069}\n{candidate}\nVisibleTail\n\\end{{document}}\n\\input{{missing-after-real-end}}\nAfterRealEnd\n"),
    )
    .unwrap();
    let mut expected_sources = vec![main.clone()];
    expected_sources.extend(dependencies.iter().map(|name| root.join(name)));
    let expect_child = dependencies.contains(&"child.tex");
    match source_closure(&main, None) {
        Ok(closure)
            if closure.sources == expected_sources
                && closure.text.contains("IncludedBody") == expect_child
                && !closure.text.contains("TrapFileMarker") => {}
        actual => failures.push(format!(
            "{label}: closure expected {expected_sources:?}, got {actual:?}"
        )),
    }
    match Source::load(&main) {
        Ok(source) => {
            let Source::Tex(model) = &source else {
                unreachable!()
            };
            if model.closure.sources != expected_sources {
                failures.push(format!(
                    "{label}: TexSource dependencies {:?}",
                    model.closure.sources
                ));
            }
            let mut actual: Vec<_> = lint::check(&source, &[], None, "system-docs")
                .unwrap()
                .into_iter()
                .filter(|finding| finding.check == "bidi-isolate")
                .map(|finding| (finding.path, finding.line))
                .collect();
            let mut expected = vec![(main.clone(), 2), (main.clone(), 2)];
            if visible_child {
                expected.extend([(root.join("child.tex"), 1), (root.join("child.tex"), 1)]);
            }
            actual.sort();
            expected.sort();
            if actual != expected {
                failures.push(format!(
                    "{label}: original findings expected {expected:?}, got {actual:?}"
                ));
            }
        }
        Err(error) => failures.push(format!("{label}: TexSource failed: {error:#}")),
    }
    match source_plain(&main) {
        Ok(plain)
            if plain.contains("VisibleBefore")
                && plain.contains("VisibleTail")
                && !plain.contains("AfterRealEnd")
                && !plain.contains("TrapFileMarker")
                && plain.contains("IncludedBody") == expect_child => {}
        actual => failures.push(format!("{label}: production extraction: {actual:?}")),
    }
}

#[test]
fn complete_literals_hide_payload_references_and_retain_following_inputs() {
    let mut failures = Vec::new();
    for literal in [
        r"\verb|\input{absent}|",
        r"\verb*|\include{absent}|",
        r"\verb§\includeonly{absent}§",
        r"\begin{verbatim}\input{absent}\end{verbatim}",
        r"\begin{verbatim*}\input{absent}\end{verbatim*}",
        r"\begin{Verbatim}\include{absent}\end{Verbatim}",
        r"\begin{lstlisting}\input{absent}\end{lstlisting}",
        r"\begin{minted}\input{absent}\end{minted}",
    ] {
        observe(
            literal,
            &format!("\\newcommand{{\\sample}}{{{literal} \\input{{child}}}}"),
            &[("child.tex", CHILD)],
            &["child.tex"],
            false,
            &mut failures,
        );
    }
    observe(
        "existing literal filename is still inert",
        r"\newcommand{\sample}{\verb|\input{trap}|}",
        &[("trap.tex", "TrapFileMarker")],
        &[],
        false,
        &mut failures,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn input_parity_restarts_at_the_exact_literal_endpoint() {
    let mut failures = Vec::new();
    for literal in [r"\verb|Literal|", r"\verb\Literal\"] {
        for slashes in 1..=3 {
            for owned in [false, true] {
                let body = format!("{literal}{}input{{child}}", "\\".repeat(slashes));
                let candidate = if owned {
                    format!("\\newcommand{{\\sample}}{{{body}}}")
                } else {
                    body
                };
                let active = slashes % 2 == 1;
                observe(
                    &format!("{literal}/{slashes}/{owned}"),
                    &candidate,
                    &[("child.tex", CHILD)],
                    if active { &["child.tex"] } else { &[] },
                    active && !owned,
                    &mut failures,
                );
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn names_counts_and_single_token_bodies_do_not_open_literal_data() {
    let mut failures = Vec::new();
    for (label, candidate, visible) in [
        (
            "declared literal name",
            r"\newcommand{\verb}{\input{child}}",
            false,
        ),
        (
            "nested include name",
            r"\newcommand{\outer}{\renewcommand{\input}[1]{##1}\input{child}}",
            false,
        ),
        (
            "collected single literal token",
            r"\newcommand{\sample}\verb |\input{child}|",
            true,
        ),
        (
            "collected single include token",
            r"\newcommand{\sample}\input Visible\input{child}",
            true,
        ),
        (
            // This malformed count is a conservative recovery control.
            "count header is not a data argument",
            r"\newcommand{\sample}[\verb|\input{absent}|]{\input{child}}",
            false,
        ),
    ] {
        observe(
            label,
            candidate,
            &[("child.tex", CHILD), ("Visible.tex", "TrapFileMarker")],
            &["child.tex"],
            visible,
            &mut failures,
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn nested_spellings_and_argument_limits_do_not_poison_reference_roles() {
    let mut failures = Vec::new();
    for candidate in [
        r"\newcommand{\outer}{\verb|\newcommand{\inner}| \input{child}}",
        r"\newcommand{\outer}{\verb|\newcommand{\inner}{\input{absent}}| \input{child}}",
        r"\newcommand{\outer}{\verb\First\\newcommand{\input}[1]{##1}\input{child}}",
        r"\newcommand{\sample}[1][\verb|\input{absent}| \input{child}]{#1}",
        r"\newcommand{\sample}{\verb| Unclosed \input{child}}",
        r"\newcommand{\sample}[1][\verb|Start]{\input{child}|}",
    ] {
        observe(
            candidate,
            candidate,
            &[("child.tex", CHILD)],
            &["child.tex"],
            false,
            &mut failures,
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn inherited_and_returned_data_keep_original_bounds_and_literal_endpoints() {
    let mut failures = Vec::new();
    for (carrier, child) in [
        (
            r"} \verb|\input{absent}| \input{child} \end{document} {",
            true,
        ),
        (r"} \verb\First\\input{child} {", true),
        (r"} \verb\First\\\input{absent} {", false),
    ] {
        observe(
            carrier,
            r"\newcommand{\outer}{\input{carrier}}",
            &[("carrier.tex", carrier), ("child.tex", CHILD)],
            if child {
                &["carrier.tex", "child.tex"]
            } else {
                &["carrier.tex"]
            },
            false,
            &mut failures,
        );
    }
    for (declaration, candidate) in [
        (
            r"\newcommand",
            r"\input declaration \sample{\verb|\input{absent}| \input{child}}",
        ),
        (
            r"\newcommand{\sample}",
            r"\input declaration {\verb\First\\input{child}}",
        ),
        (
            r"\renewcommand{\sample}[1]",
            r"\newcommand{\sample}[1]{#1}\input declaration [\verb|\input{absent}| \input{child}]{#1}",
        ),
    ] {
        observe(
            declaration,
            candidate,
            &[("declaration.tex", declaration), ("child.tex", CHILD)],
            &["declaration.tex", "child.tex"],
            false,
            &mut failures,
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn raw_comments_remain_authoritative_after_a_completed_literal() {
    let mut failures = Vec::new();
    for (placement, newline) in [
        ("local", "\n"),
        ("local", "\r\n"),
        ("local", "\r"),
        ("inherited", "\n"),
        ("continued", "\r\n"),
    ] {
        for percent in [false, true] {
            let marker = if percent { '%' } else { 'x' };
            let filename = if percent { "absent" } else { "child" };
            let body = format!("\\verb|100{marker}| \\input{{{filename}}}{newline}RetainedBody");
            let candidate = match placement {
                "local" => format!("\\newcommand{{\\sample}}{{{body}}}"),
                "inherited" => r"\newcommand{\sample}{\input{carrier}}".to_owned(),
                _ => format!("\\input declaration {{{body}}}"),
            };
            let mut dependencies = match placement {
                "local" => vec![],
                "inherited" => vec!["carrier.tex"],
                _ => vec!["declaration.tex"],
            };
            if !percent {
                dependencies.push("child.tex");
            }
            observe(
                &format!("{placement}/{newline:?}/{percent}"),
                &candidate,
                &[
                    ("carrier.tex", &body),
                    ("declaration.tex", r"\newcommand{\sample}"),
                    ("child.tex", CHILD),
                ],
                &dependencies,
                false,
                &mut failures,
            );
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
