use revayat_scientific::lint::{self, Finding, Source};
use std::{fs, path::Path};

fn findings_at(path: &Path) -> Vec<Finding> {
    lint::check(&Source::load(path).unwrap(), &[], None, "system-docs")
        .unwrap()
        .into_iter()
        .filter(|finding| finding.check == "bidi-isolate")
        .collect()
}

fn findings(body: &str) -> Vec<Finding> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.tex");
    fs::write(
        &path,
        format!(
            "\\documentclass{{article}}\\newcommand{{\\existing}}{{old}}\\newcommand{{\\newcommandExtra}}[2]{{#2}}\\newcommand{{\\renewcommandExtra}}[2]{{#2}}\\newcommand{{\\itemlabel}}[1]{{#1}}\n\\begin{{document}}\n{body}\n\\end{{document}}"
        ),
    )
    .unwrap();
    findings_at(&path)
}

#[test]
fn braced_and_unbraced_definitions_do_not_split_visible_prose() {
    for (command, target) in [("newcommand", "sample"), ("renewcommand", "existing")] {
        for star in ["", "*"] {
            for name in [format!("{{\\{target}}}"), format!("\\{target}")] {
                for (options, payload) in [
                    ("", r"\par"),
                    ("[1]", r"\item #1"),
                    ("[1][x]", r"\par #1"),
                    ("[1][{x]y}]", r"\item #1"),
                ] {
                    let definition = format!("\\{command}{star}{name}{options}{{{payload}}}");
                    let actual = findings(&format!("\u{2067}before {definition} after\u{2069}"));
                    assert!(actual.is_empty(), "{definition}: {actual:#?}");
                }
            }
        }
    }
}

#[test]
fn unused_definition_controls_do_not_balance_visible_isolates() {
    for (command, target) in [("newcommand", "sample"), ("renewcommand", "existing")] {
        for name in [format!("{{\\{target}}}"), format!("\\{target}")] {
            let definition = format!("\\{command}{name}{{\u{2069}}}");
            let actual = findings(&format!("\u{2067}before {definition} after"));
            assert_eq!(actual.len(), 1, "{definition}: {actual:#?}");
            assert_eq!(actual[0].line, 3);
            assert!(actual[0].message.starts_with("Close the"));

            let definition = format!("\\{command}{name}{{\u{2067}}}");
            let actual = findings(&format!("before {definition} after"));
            assert!(actual.is_empty(), "{definition}: {actual:#?}");
        }
    }
}

#[test]
fn real_paragraph_after_a_definition_keeps_included_source_locations() {
    for definition in [
        r"\newcommand{\sample}{\par}",
        r"\newcommand\sample{\par}",
        r"\newcommand*{\sample}[1][{x]y}]{\item #1}",
        r"\newcommand*\sample[1][{x]y}]{\item #1}",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let main = root.join("main.tex");
        let chapter = root.join("chapter.tex");
        fs::write(
            &main,
            "\\documentclass{article}\n\\begin{document}\n\u{2067}before \\input{chapter}\n\\end{document}\n",
        )
        .unwrap();
        fs::write(&chapter, format!("{definition}\n\\par\nafter\u{2069}\n")).unwrap();
        let locations: Vec<_> = findings_at(&main)
            .into_iter()
            .map(|finding| (finding.path, finding.line))
            .collect();
        assert_eq!(locations, [(main, 3), (chapter, 3)], "{definition}");
    }
}

#[test]
fn definition_and_paragraph_commands_require_an_active_exact_token() {
    for command in ["newcommand", "renewcommand"] {
        for count in 1..=4 {
            let slashes = "\\".repeat(count);
            let name = if count % 2 == 1 && command == "newcommand" {
                "sample"
            } else {
                "existing"
            };
            let definition = format!("{slashes}{command}{{\\{name}}}{{\\par}}");
            let actual = findings(&format!("\u{2067}before {definition} after\u{2069}"));
            assert_eq!(
                actual.len(),
                if count % 2 == 1 { 0 } else { 2 },
                "{definition}"
            );
        }
    }
    for command in ["par", "item"] {
        for count in 1..=4 {
            let slashes = "\\".repeat(count);
            let body = format!(
                "\\begin{{itemize}}\\item \u{2067}before {slashes}{command} after\u{2069}\\end{{itemize}}"
            );
            assert_eq!(
                findings(&body).len(),
                if count % 2 == 1 { 2 } else { 0 },
                "{body:?}"
            );
        }
    }
    for (body, expected) in [
        (
            "\u{2067}before \\newcommandExtra{\\existing}{\\par} after\u{2069}",
            2,
        ),
        (
            "\u{2067}before \\renewcommandExtra{\\existing}{\\par} after\u{2069}",
            2,
        ),
        (
            "\u{2067}before \\parbox{2cm}{ordinary text} after\u{2069}",
            0,
        ),
        ("\u{2067}before \\itemlabel{ordinary text} after\u{2069}", 0),
    ] {
        assert_eq!(findings(body).len(), expected, "{body:?}");
    }
}

#[test]
fn whitespace_and_comments_separate_definition_tokens() {
    for (command, target) in [("newcommand", "sample"), ("renewcommand", "existing")] {
        for name in [format!("{{\\{target}}}"), format!("\\{target}")] {
            for (star, options) in [
                (" ", ""),
                (" * ", "[1][{x]y}]"),
                ("% note\n*% note\n", "% note\n[1]% note\n[{x]y}]% note\n"),
            ] {
                let definition = format!("\\{command}{star}{name} {options}{{\\par}}");
                let actual = findings(&format!("\u{2067}before {definition} after\u{2069}"));
                assert!(actual.is_empty(), "{definition}: {actual:#?}");
            }
        }
    }
}

#[test]
fn control_symbol_names_do_not_consume_following_live_prose() {
    for (command, symbol) in [("newcommand", "?"), ("renewcommand", "!")] {
        for star in ["", "*"] {
            for name in [format!("{{\\{symbol}}}"), format!("\\{symbol}")] {
                let definition = format!("\\{command}{star}{name}[1][{{x]y}}]{{\\par #1}}");
                let actual = findings(&format!("\u{2067}before {definition} after\u{2069}"));
                assert!(actual.is_empty(), "{definition}: {actual:#?}");
            }
        }
    }
    for definition in [
        r"\renewcommand\\{unused}",
        r"\renewcommand*\\[1][x]{unused #1}",
        r"\renewcommand{\\}{unused}",
        r"\renewcommand*{\\}[1][x]{unused #1}",
    ] {
        let body = format!("\u{2067}before {definition}{{\\par}} after\u{2069}");
        assert_eq!(findings(&body).len(), 2, "{definition}");
    }
}

#[test]
fn unused_definition_tokens_cannot_open_regions_in_following_prose() {
    for (definition, tail) in [
        (r"\newcommand{\sample}{$}", r" $x$"),
        (r"\newcommand{\sample}{\textbf[}", " ]"),
    ] {
        let actual = findings(&format!(
            "{definition}\n\u{2067}before\\par after\u{2069}{tail}"
        ));
        assert_eq!(actual.len(), 2, "{definition}: {actual:#?}");
        assert!(actual.iter().all(|finding| finding.line == 4));
    }
}
