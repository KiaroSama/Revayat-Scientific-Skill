//! Bounded recognition of complete newcommand/renewcommand definitions.
pub(crate) fn ranges(masked: &str) -> Vec<(usize, usize)> {
    ranges_observed(masked, || {})
}

fn ranges_observed(masked: &str, mut visit: impl FnMut()) -> Vec<(usize, usize)> {
    let mut tokens = tokenize(masked, &mut visit);
    index_options(&mut tokens, &mut visit);
    let mut ranges = Vec::new();
    let mut pos = 0;
    while let Some(token) = token_at(&tokens, pos, &mut visit) {
        if token.kind == Kind::Definition
            && let Some(end) = definition_end(&tokens, pos + 1, &mut visit)
        {
            let closing = token_at(&tokens, end - 1, &mut visit).unwrap();
            ranges.push((token.offset, closing.offset + 1));
            pos = end;
        } else {
            pos += 1;
        }
    }
    ranges
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Definition,
    Control,
    OpenBrace,
    CloseBrace,
    OpenOption,
    CloseOption,
    Star,
    Text,
}

#[derive(Clone, Copy)]
struct Token {
    offset: usize,
    // Exclusive delimiter endpoint; zero denotes an incomplete group. Source
    // admission is bounded to 16 MiB, so token indexes fit comfortably in u32.
    next: u32,
    kind: Kind,
}

fn token_at(tokens: &[Token], pos: usize, visit: &mut impl FnMut()) -> Option<Token> {
    visit();
    tokens.get(pos).copied()
}

fn character(text: &str, pos: usize, visit: &mut impl FnMut()) -> Option<char> {
    visit();
    text[pos..].chars().next()
}

fn word(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '@'
}

fn punctuation(character: char) -> bool {
    matches!(character, '\\' | '{' | '}' | '[' | ']' | '*')
}

fn tokenize(text: &str, visit: &mut impl FnMut()) -> Vec<Token> {
    let mut tokens: Vec<Token> = Vec::new();
    let mut braces = Vec::new();
    let mut pos = 0;
    while let Some(first) = character(text, pos, visit) {
        let start = pos;
        pos += first.len_utf8();
        if first.is_whitespace() {
            continue;
        }
        let kind = match first {
            '\\' => {
                if let Some(first) = character(text, pos, visit) {
                    let name = pos;
                    pos += first.len_utf8();
                    if word(first) {
                        while let Some(next) = character(text, pos, visit) {
                            if !word(next) {
                                break;
                            }
                            pos += next.len_utf8();
                        }
                        if matches!(&text[name..pos], "newcommand" | "renewcommand") {
                            Kind::Definition
                        } else {
                            Kind::Control
                        }
                    } else {
                        Kind::Control
                    }
                } else {
                    Kind::Control
                }
            }
            '{' => Kind::OpenBrace,
            '}' => Kind::CloseBrace,
            '[' => Kind::OpenOption,
            ']' => Kind::CloseOption,
            '*' => Kind::Star,
            _ => {
                while let Some(next) = character(text, pos, visit) {
                    if next.is_whitespace() || punctuation(next) {
                        break;
                    }
                    pos += next.len_utf8();
                }
                Kind::Text
            }
        };
        let index = u32::try_from(tokens.len()).expect("bounded TeX token index");
        tokens.push(Token {
            offset: start,
            next: 0,
            kind,
        });
        if kind == Kind::OpenBrace {
            visit();
            braces.push(index);
        } else if kind == Kind::CloseBrace
            && let Some(open) = braces.pop()
        {
            visit();
            tokens[open as usize].next = index + 1;
        }
    }
    tokens
}

fn index_options(tokens: &mut [Token], visit: &mut impl FnMut()) {
    let mut next_close = 0;
    for pos in (0..tokens.len()).rev() {
        let token = token_at(tokens, pos, visit).unwrap();
        match token.kind {
            // Reuse a closing brace's otherwise-unused endpoint to remember
            // the next optional closer after that entire balanced group.
            Kind::CloseBrace => tokens[pos].next = next_close,
            Kind::OpenBrace => {
                next_close = if token.next == 0 {
                    0
                } else {
                    token_at(tokens, token.next as usize - 1, visit)
                        .unwrap()
                        .next
                };
            }
            Kind::CloseOption => {
                next_close = u32::try_from(pos + 1).expect("bounded TeX token index");
            }
            Kind::OpenOption => tokens[pos].next = next_close,
            _ => (),
        }
    }
}

fn definition_end(tokens: &[Token], mut pos: usize, visit: &mut impl FnMut()) -> Option<usize> {
    if token_at(tokens, pos, visit)?.kind == Kind::Star {
        pos += 1;
    }
    let name = token_at(tokens, pos, visit)?;
    match name.kind {
        Kind::OpenBrace if name.next != 0 => pos = name.next as usize,
        Kind::Control | Kind::Definition => pos += 1,
        _ => return None,
    }
    for _ in 0..2 {
        let option = token_at(tokens, pos, visit)?;
        if option.kind != Kind::OpenOption {
            break;
        }
        if option.next == 0 {
            return None;
        }
        pos = option.next as usize;
    }
    let body = token_at(tokens, pos, visit)?;
    (body.kind == Kind::OpenBrace && body.next != 0).then_some(body.next as usize)
}

pub(crate) fn mask(text: &str, ranges: &[(usize, usize)]) -> String {
    let mut bytes = text.as_bytes().to_vec();
    for &(start, end) in ranges {
        for byte in &mut bytes[start..end] {
            if !matches!(byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(bytes).expect("ASCII definition replacement")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_linear(fragment: &str) {
        for copies in [16, 128, 1024, 100_000] {
            let text = format!(
                "\\begin{{document}}Visible\\end{{document}}{}",
                fragment.repeat(copies)
            );
            let mut visits = 0;
            let actual = ranges_observed(&text, || visits += 1);
            assert!(actual.is_empty(), "an incomplete declaration was admitted");
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
        assert_linear(r"\newcommand{\x}[1][");
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
}
