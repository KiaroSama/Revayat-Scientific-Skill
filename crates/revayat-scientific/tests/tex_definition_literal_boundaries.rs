use revayat_scientific::tex::{plain_tex, source_closure};
use revayat_scientific::text_order::source_plain;
use std::fs;

fn routes(source: &str) -> [(&'static str, Result<String, String>); 3] {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    fs::write(&main, source).unwrap();
    let closure = source_closure(&main, None).and_then(|closure| closure.plain_text());
    [
        ("closure", closure.map_err(|error| error.to_string())),
        (
            "production",
            source_plain(&main).map_err(|error| error.to_string()),
        ),
        (
            "standalone",
            plain_tex(source).map_err(|error| error.to_string()),
        ),
    ]
}

fn compare(
    label: &str,
    literal: &str,
    following: &str,
    marker: &str,
    expected: Option<bool>,
    failures: &mut Vec<String>,
) {
    let source = format!("\\newcommand{{\\sample}}{{{literal}{following} RetainedBody}}");
    let neutral = " ".repeat(literal.len());
    let control = format!("\\newcommand{{\\sample}}{{{neutral}{following} RetainedBody}}");
    for ((route, actual), (_, reference)) in routes(&source).into_iter().zip(routes(&control)) {
        match (actual, reference) {
            (Ok(actual), Ok(reference)) => {
                let actual_marker = actual.contains(marker);
                let reference_marker = reference.contains(marker);
                if actual_marker != reference_marker
                    || expected.is_some_and(|expected| {
                        expected != actual_marker || expected != reference_marker
                    })
                    || !actual.contains("RetainedBody")
                    || !reference.contains("RetainedBody")
                    || (marker == "LiteralPayload"
                        && (actual.contains("MathOnly") || reference.contains("MathOnly")))
                {
                    failures.push(format!(
                        "{label}/{route}: actual={actual:?}; neutral={reference:?}"
                    ));
                }
            }
            (actual, reference) => failures.push(format!(
                "{label}/{route}: actual={actual:?}; neutral={reference:?}"
            )),
        }
    }
}

#[test]
fn math_after_literals_matches_neutral_prefix_for_all_boundary_runs() {
    let mut failures = Vec::new();
    for literal in [
        r"\verb|LiteralPayload|",
        r"\verb§LiteralPayload§",
        r"\verb\LiteralPayload\",
    ] {
        for run in 0..=6 {
            let prefix = "\\".repeat(run);
            for (open, close) in [("$", "$"), ("$$", "$$"), (r"\(", r"\)"), (r"\[", r"\]")] {
                let following = format!("{prefix}{open}MathOnly{close}");
                compare(
                    &format!("math/{literal}/run={run}/{open}"),
                    literal,
                    &following,
                    "MathOnly",
                    (run == 0).then_some(false),
                    &mut failures,
                );
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn adjacent_inline_literals_restart_discovery_after_each_complete_endpoint() {
    let mut failures = Vec::new();
    for literal in [r"\verb|First|", r"\verb§First§", r"\verb\First\"] {
        for run in 0..=6 {
            let prefix = "\\".repeat(run);
            for next in [r"\verb|$LiteralPayload$|", r"\verb*|$LiteralPayload$|"] {
                let following = format!("{prefix}{next} $MathOnly$");
                compare(
                    &format!("inline/{literal}/run={run}/{next}"),
                    literal,
                    &following,
                    "LiteralPayload",
                    Some(run % 2 == 0),
                    &mut failures,
                );
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn adjacent_literal_environments_obey_active_and_escaped_boundaries() {
    let mut failures = Vec::new();
    for environment in ["verbatim", "verbatim*", "Verbatim", "lstlisting", "minted"] {
        for run in 0..=1 {
            let prefix = "\\".repeat(run);
            let following = format!(
                "{prefix}\\begin{{{environment}}}$LiteralPayload$\\end{{{environment}}} $MathOnly$"
            );
            compare(
                &format!("environment/{environment}/run={run}"),
                r"\verb\First\",
                &following,
                "LiteralPayload",
                Some(run == 0),
                &mut failures,
            );
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn escaped_openers_and_incomplete_argument_literals_keep_existing_raw_contracts() {
    let mut cases = Vec::new();
    for escaped in [
        r"\$MathOnly\$",
        r"\$\$MathOnly\$\$",
        r"\\(MathOnly\\)",
        r"\\[MathOnly\\]",
    ] {
        cases.push((
            format!("\\newcommand{{\\sample}}{{\\verb\\First\\{escaped} RetainedBody}}"),
            true,
        ));
    }
    cases.extend([
        (
            r"\newcommand{\sample}[1][\verb|$MathOnly$]{RetainedBody |}".to_owned(),
            false,
        ),
        (
            r"\newcommand{\sample}{\verb|$MathOnly$ RetainedBody}\newcommand{\other}{|}".to_owned(),
            false,
        ),
    ]);
    let mut failures = Vec::new();
    for (index, (source, contains_math)) in cases.iter().enumerate() {
        for (route, actual) in routes(source) {
            match actual {
                Ok(plain)
                    if plain.contains("RetainedBody")
                        && plain.contains("MathOnly") == *contains_math => {}
                actual => failures.push(format!("control={index}/{route}: {actual:?}")),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn original_child_bounds_preserve_literal_boundary_state_despite_inserted_braces() {
    let cases = [
        (
            r"\verb\First\\verb|$LiteralPayload$| $MathOnly$ RetainedBody",
            Some(true),
            false,
        ),
        (
            r"\verb\First\\\verb|$LiteralPayload$| $MathOnly$ RetainedBody",
            Some(false),
            false,
        ),
        (r"\verb\First\\(MathOnly\) RetainedBody", None, false),
        (r"\verb\First\\\(MathOnly\\) RetainedBody", None, true),
    ];
    let mut failures = Vec::new();
    for stray_braces in [false, true] {
        for (index, &(body, payload, math)) in cases.iter().enumerate() {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let main = root.join("main.tex");
            let child = if stray_braces {
                format!("}} {body} {{")
            } else {
                body.to_owned()
            };
            fs::write(root.join("data.tex"), child).unwrap();
            fs::write(&main, r"\newcommand{\sample}{\input{data}} OutsideVisible").unwrap();
            let closure = source_closure(&main, None).unwrap();
            assert_eq!(closure.sources.len(), 2);
            for (route, actual) in [
                ("closure", closure.plain_text()),
                ("production", source_plain(&main)),
            ] {
                match actual {
                    Ok(plain)
                        if plain.contains("RetainedBody")
                            && plain.contains("OutsideVisible")
                            && plain.contains("MathOnly") == math
                            && payload.is_none_or(|expected| {
                                plain.contains("LiteralPayload") == expected
                            }) => {}
                    actual => failures.push(format!(
                        "inherited={index}/stray={stray_braces}/{route}: {actual:?}"
                    )),
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
