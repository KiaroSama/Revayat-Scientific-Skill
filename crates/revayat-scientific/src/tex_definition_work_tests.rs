use super::*;

fn assert_linear(fragment: &str) {
    assert_work(fragment, true);
}

fn assert_work(fragment: &str, incomplete: bool) {
    for copies in [16, 128, 1024, 100_000] {
        let text = format!(
            "\\begin{{document}}Visible\\end{{document}}{}",
            fragment.repeat(copies)
        );
        let mut visits = 0;
        let actual = ranges_observed(&text, || visits += 1);
        if incomplete {
            assert!(actual.is_empty(), "an incomplete declaration was admitted");
        } else {
            // A later ] can close the default, and the following [ is then
            // the legal one-token replacement. The work bound still applies.
            assert!(!actual.is_empty(), "the complete one-token body was lost");
        }
        let maximum = text.len() * 32 + 16;
        assert!(
            visits <= maximum,
            "{fragment:?}, copies={copies}: actual traversal visits={visits}, linear limit={maximum}"
        );
    }
}

#[test]
fn incomplete_names_have_linear_traversal_work() {
    assert_linear(r"\newcommand{");
}

#[test]
fn incomplete_first_options_have_linear_traversal_work() {
    assert_linear(r"\newcommand{\x}[");
    assert_linear(r"\newcommand{\x}[{");
    assert_linear(r"\newcommand\x[");
}

#[test]
fn incomplete_second_options_have_linear_traversal_work() {
    assert_linear(r"\newcommand{\x}[1][{");
    assert_work(r"\newcommand{\x}[1][", false);
    assert_linear(r"\newcommand\x[1][{");
}

#[test]
fn incomplete_bodies_have_linear_traversal_work() {
    assert_linear(r"\newcommand{\x}{");
}

#[test]
fn incomplete_outer_declarations_preserve_complete_later_definitions() {
    let valid = r"\newcommand\good{\{escaped\}\\\par}";
    for prefix in [
        r"\newcommand{",
        r"\newcommand{\bad}[",
        r"\newcommand{\bad}[1][",
        r"\newcommand{\bad}{",
    ] {
        let text = format!("{prefix}{valid}");
        assert_eq!(ranges(&text), [(prefix.len(), text.len())], "{prefix}");
    }
}

#[test]
fn complete_definitions_preserve_escaped_braces_and_control_symbol_names() {
    for declaration in [
        r"\newcommand\?{\{escaped\}\\}",
        r"\newcommand\☃{\{escaped\}\\}",
        r"\renewcommand*\\[1][{x]y}]{\{#1\}\\}",
        r"\renewcommand*{\\}[1][{x]y}]{\{#1\}\\}",
        r"\newcommand{\outer}{\newcommand\inner{\par}}",
    ] {
        let prefix = "پیش ";
        let text = format!("{prefix}{declaration} after\\par");
        assert_eq!(
            ranges(&text),
            [(prefix.len(), prefix.len() + declaration.len())],
            "{declaration}"
        );
    }
}

#[test]
fn ignored_regions_do_not_supply_definition_tokens_or_delimiters() {
    let prefix = concat!(
        "% \\newcommand{unclosed\n",
        "\\verb|\\newcommand{unclosed|\n",
        "\\begin{verbatim}\\newcommand{unclosed\\end{verbatim}\n"
    );
    let declaration = "\\newcommand% comment\n*\\?% comment\n[1][{x]y}]{\\{#1\\}}";
    let text = format!("{prefix}{declaration} after\\par");
    let masked = crate::tex::masked_tex(&text).unwrap();
    assert_eq!(
        ranges(&masked),
        [(prefix.len(), prefix.len() + declaration.len())]
    );
}
