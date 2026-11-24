use revayat_scientific::lint::{self, Source};
use revayat_scientific::tex::source_closure;
use revayat_scientific::text_order::source_plain;
use std::fs;

fn observe(
    label: &str,
    candidate: &str,
    files: &[(&str, &str)],
    dependencies: &[&str],
    visible_children: &[&str],
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
    match source_closure(&main, None) {
        Ok(closure) if closure.sources == expected_sources => {}
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
            for name in visible_children {
                expected.extend([(root.join(name), 1), (root.join(name), 1)]);
            }
            actual.sort();
            expected.sort();
            if actual != expected {
                failures.push(format!(
                    "{label}: original-location findings expected {expected:?}, got {actual:?}"
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
                && !plain.contains("TrapFileMarker") => {}
        actual => failures.push(format!("{label}: production extraction: {actual:?}")),
    }
}

#[test]
fn default_catcode_input_boundary_and_negative_controls() {
    let mut failures = Vec::new();
    let child = "\u{2067}ChildBefore\\par after\u{2069}\n";
    for candidate in [r"\input@chapter", r"\input @chapter", r"\input{@chapter}"] {
        observe(
            candidate,
            candidate,
            &[("@chapter.tex", child)],
            &["@chapter.tex"],
            &["@chapter.tex"],
            &mut failures,
        );
    }
    for candidate in [
        r"\newcommand{\inputSuffix}{Ignored}\inputSuffix@chapter",
        r"\\input@chapter",
        "% \\input@chapter\nOrdinary",
        r"\verb|\input@chapter|",
    ] {
        observe(candidate, candidate, &[], &[], &[], &mut failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn declaration_names_are_collected_without_include_dispatch() {
    let mut failures = Vec::new();
    for command in ["input", "include", "includeonly"] {
        for braced in [false, true] {
            let name = if braced {
                format!("{{\\{command}}}")
            } else {
                format!("\\{command}")
            };
            let candidate = format!("\\renewcommand{name}[1]{{#1}}");
            observe(
                &format!("local name {command}/{braced}"),
                &candidate,
                &[],
                &[],
                &[],
                &mut failures,
            );
        }
        let candidate = format!("\\input declaration \\{command}[1]{{#1}}");
        observe(
            &format!("continued name {command}"),
            &candidate,
            &[("declaration.tex", r"\renewcommand")],
            &["declaration.tex"],
            &[],
            &mut failures,
        );
    }
    observe(
        "at-name compatibility",
        r"\makeatletter\newcommand{\sample@name}{unused}\makeatother",
        &[],
        &[],
        &[],
        &mut failures,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn single_token_replacement_cannot_take_a_filename_from_following_prose() {
    let mut failures = Vec::new();
    for command in ["input", "include", "includeonly"] {
        let candidate = format!("\\newcommand{{\\load}}\\{command}\nVisible");
        observe(
            &format!("local body {command}"),
            &candidate,
            &[],
            &[],
            &[],
            &mut failures,
        );
        let candidate =
            format!("\\newcommand{{\\load}}{{unused}}\n\\input declaration \\{command}\nVisible");
        observe(
            &format!("continued body {command}"),
            &candidate,
            &[("declaration.tex", r"\renewcommand{\load}")],
            &["declaration.tex"],
            &[],
            &mut failures,
        );
    }
    observe(
        "existing filename must not be read",
        "\\newcommand{\\load}\\input\nVisible",
        &[("Visible.tex", "TrapFileMarker")],
        &[],
        &[],
        &mut failures,
    );
    observe(
        "later real include remains live",
        "\\newcommand{\\load}\\input\nVisible\n\\input{child}",
        &[("child.tex", "ChildMarker")],
        &["child.tex"],
        &[],
        &mut failures,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn complete_default_and_replacement_references_remain_conservative() {
    let mut failures = Vec::new();
    for candidate in [
        r"\newcommand{\load}{\input{child}}",
        r"\newcommand{\load}{\include{child}}",
        r"\newcommand{\load}[1][\input{child}]{#1}",
        r"\newcommand{\load}[1][\include{child}]{#1}",
    ] {
        observe(
            candidate,
            candidate,
            &[("child.tex", "ChildMarker")],
            &["child.tex"],
            &[],
            &mut failures,
        );
    }
    observe(
        "continued replacement reference",
        r"\input declaration {\input{child}}",
        &[
            ("declaration.tex", r"\newcommand{\load}"),
            ("child.tex", "ChildMarker"),
        ],
        &["declaration.tex", "child.tex"],
        &[],
        &mut failures,
    );
    observe(
        "continued default reference",
        r"\input declaration [\input{child}]{#1}",
        &[
            ("declaration.tex", r"\newcommand{\load}[1]"),
            ("child.tex", "ChildMarker"),
        ],
        &["declaration.tex", "child.tex"],
        &[],
        &mut failures,
    );
    observe(
        "inherited definition dependency",
        r"\newcommand{\load}{\input{carrier}}",
        &[
            ("carrier.tex", r"\input{child}"),
            ("child.tex", "ChildMarker"),
        ],
        &["carrier.tex", "child.tex"],
        &[],
        &mut failures,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn nested_declaration_names_are_not_literal_references() {
    let mut failures = Vec::new();
    for command in ["input", "include", "includeonly"] {
        for braced in [false, true] {
            let name = if braced {
                format!("{{\\{command}}}")
            } else {
                format!("\\{command}")
            };
            let nested = format!("\\renewcommand{name}[1]{{##1}}");
            for default in [false, true] {
                let candidate = if default {
                    format!("\\newcommand{{\\outer}}[1][{nested}]{{#1}}")
                } else {
                    format!("\\newcommand{{\\outer}}{{{nested}}}")
                };
                observe(
                    &format!("nested name {command}/{braced}/{default}"),
                    &candidate,
                    &[],
                    &[],
                    &[],
                    &mut failures,
                );
            }
        }
    }
    for candidate in [
        r"\newcommand{\outer}{\newcommand{\load}{\input{child}}}",
        r"\newcommand{\outer}[1][\newcommand{\load}{\input{child}}]{#1}",
    ] {
        observe(
            "nested complete reference",
            candidate,
            &[("child.tex", "ChildMarker")],
            &["child.tex"],
            &[],
            &mut failures,
        );
    }
    observe(
        "inherited nested name and following reference",
        r"\newcommand{\outer}{\input{carrier}}",
        &[
            ("carrier.tex", r"\renewcommand{\input}[1]{#1}\input{child}"),
            ("child.tex", "ChildMarker"),
        ],
        &["carrier.tex", "child.tex"],
        &[],
        &mut failures,
    );
    observe(
        "continued nested name and following reference",
        r"\input declaration {\renewcommand\input[1]{##1}\input{child}}",
        &[
            ("declaration.tex", r"\newcommand{\outer}"),
            ("child.tex", "ChildMarker"),
        ],
        &["declaration.tex", "child.tex"],
        &[],
        &mut failures,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn reference_arguments_stop_at_their_own_data_boundary() {
    let mut failures = Vec::new();
    for command in ["input", "include", "includeonly"] {
        for default in [false, true] {
            let candidate = if default {
                format!("\\newcommand{{\\load}}[1][\\{command}]{{#1}}")
            } else {
                format!("\\newcommand{{\\load}}{{\\{command}}}{{Visible}}")
            };
            observe(
                &format!("argumentless data token {command}/{default}"),
                &candidate,
                &[],
                &[],
                &[],
                &mut failures,
            );
        }
    }
    observe(
        "single-token body with adjacent at text",
        r"\newcommand{\load}\input@chapter",
        &[("@chapter.tex", "TrapFileMarker")],
        &[],
        &[],
        &mut failures,
    );
    for candidate in [
        r"\newcommand{\load}{\input child}",
        r"\newcommand{\load}[1][\input child]{#1}",
    ] {
        observe(
            "bounded unbraced reference",
            candidate,
            &[("child.tex", "ChildMarker")],
            &["child.tex"],
            &[],
            &mut failures,
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
