//! Original TeX tokens and bounded raw argument delimiter indexes.
use super::super::{Region, RegionKind};
use anyhow::{Context, Result, ensure};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Definition,
    Control,
    OpenBrace,
    CloseBrace,
    OpenOption,
    CloseOption,
    Star,
    Text,
    Whitespace,
    Comment,
    LineBreak,
    Paragraph,
}

#[derive(Clone, Copy)]
pub(super) struct Token {
    pub start: u32,
    pub end: u32,
    pub endpoint: u32,
    pub next: u32,
    pub kind: Kind,
}

pub(super) struct Tokens {
    pub values: Vec<Token>,
    pub active: Vec<u32>,
}

fn character(text: &str, pos: usize, visit: &mut impl FnMut()) -> Option<char> {
    visit();
    text[pos..].chars().next()
}

fn word(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '@'
}

pub(super) fn tokenize(text: &str, visit: &mut impl FnMut()) -> Tokens {
    let mut values = Vec::new();
    let mut pos = 0;
    let mut line_has_token = false;
    while let Some(first) = character(text, pos, visit) {
        let start = pos;
        pos += first.len_utf8();
        let mut end = pos;
        let mut step = 1;
        let kind = match first {
            ' ' | '\t' => Kind::Whitespace,
            '\r' | '\n' => {
                if first == '\r' && text.as_bytes().get(pos) == Some(&b'\n') {
                    visit();
                    pos += 1;
                    end = pos;
                }
                let kind = if line_has_token {
                    Kind::LineBreak
                } else {
                    Kind::Paragraph
                };
                line_has_token = false;
                kind
            }
            '\\' => {
                line_has_token = true;
                if let Some(next) = character(text, end, visit) {
                    let name = end;
                    end += next.len_utf8();
                    step += 1;
                    if word(next) {
                        while let Some(next) = character(text, end, visit) {
                            if !word(next) {
                                break;
                            }
                            end += next.len_utf8();
                            step += 1;
                        }
                        if matches!(&text[name..end], "newcommand" | "renewcommand") {
                            Kind::Definition
                        } else {
                            Kind::Control
                        }
                    } else {
                        if next == '\r' && text.as_bytes().get(end) == Some(&b'\n') {
                            visit();
                            end += 1;
                        }
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
            '%' => Kind::Comment,
            _ => Kind::Text,
        };
        if !matches!(kind, Kind::Whitespace | Kind::LineBreak | Kind::Paragraph) {
            line_has_token = true;
        }
        // Retain a possible entry at every scalar, including the character
        // after a control-symbol escape. A literal can consume that escape,
        // leaving its following percent, brace or backslash active again.
        let next = u32::try_from(values.len() + step).expect("bounded TeX token index");
        values.push(Token {
            start: u32::try_from(start).expect("bounded TeX byte offset"),
            end: u32::try_from(end).expect("bounded TeX byte offset"),
            endpoint: 0,
            next,
            kind,
        });
    }
    if !text.is_empty() && !text.ends_with(['\r', '\n']) && !line_has_token {
        // TeX supplies an endline for the final physical line. A line with
        // only whitespace therefore contributes a paragraph token at EOF.
        values.push(Token {
            start: text.len() as u32,
            end: text.len() as u32,
            endpoint: 0,
            next: values.len() as u32 + 1,
            kind: Kind::Paragraph,
        });
    }
    let length = values.len();
    let mut active = vec![length as u32; length + 1];
    let mut after_line = length as u32;
    let mut line_end = text.len() as u32;
    for pos in (0..length).rev() {
        visit();
        let token = values[pos];
        match token.kind {
            Kind::LineBreak | Kind::Paragraph => {
                after_line = pos as u32 + 1;
                line_end = token.start;
            }
            Kind::Comment => {
                values[pos].next = after_line;
                // Comments use the endpoint field for their original byte end.
                values[pos].endpoint = line_end;
            }
            _ => (),
        }
        active[pos] = if matches!(
            token.kind,
            Kind::Comment | Kind::Whitespace | Kind::LineBreak
        ) {
            visit();
            active[values[pos].next as usize]
        } else {
            pos as u32
        };
    }
    // Every raw position remains indexed, including positions inside a comment
    // or apparent literal. Entry after a real literal may resume on that line.
    let mut tail = vec![0; length + 1];
    for pos in (0..length).rev() {
        visit();
        let token = values[pos];
        let following = active[token.next as usize] as usize;
        visit();
        tail[pos] = match token.kind {
            Kind::CloseBrace => pos as u32 + 1,
            Kind::OpenBrace => {
                let close = tail[following];
                visit();
                values[pos].endpoint = close;
                if close == 0 {
                    0
                } else {
                    visit();
                    tail[active[close as usize] as usize]
                }
            }
            _ => tail[following],
        };
    }
    // A second reverse dynamic-programming pass indexes optional closers,
    // skipping complete raw brace groups and active comments in constant work.
    tail.fill(0);
    for pos in (0..length).rev() {
        visit();
        let token = values[pos];
        let following = active[token.next as usize] as usize;
        visit();
        tail[pos] = match token.kind {
            Kind::CloseOption => pos as u32 + 1,
            Kind::OpenBrace => {
                if token.endpoint == 0 {
                    0
                } else {
                    visit();
                    tail[active[token.endpoint as usize] as usize]
                }
            }
            _ => tail[following],
        };
        if token.kind == Kind::OpenOption {
            values[pos].endpoint = tail[pos];
        }
    }
    Tokens { values, active }
}

pub(super) fn literal(
    text: &str,
    start: usize,
    visit: &mut impl FnMut(),
) -> Result<Option<Region>> {
    let tail = &text[start..];
    for env in ["verbatim", "verbatim*", "Verbatim", "lstlisting", "minted"] {
        visit();
        let opening = format!("\\begin{{{env}}}");
        if tail.starts_with(&opening) {
            let closing = format!("\\end{{{env}}}");
            let mut pos = start + opening.len();
            while pos < text.len() {
                visit();
                if text[pos..].starts_with(&closing) {
                    return Ok(Some(Region {
                        start,
                        end: pos + closing.len(),
                        kind: RegionKind::Literal,
                    }));
                }
                pos += text[pos..].chars().next().unwrap().len_utf8();
            }
            anyhow::bail!("unterminated or invalid literal TeX region");
        }
    }
    visit();
    if tail.starts_with("\\verb") && !tail[5..].starts_with(|c: char| c.is_ascii_alphabetic()) {
        let mut pos = start + 5;
        if text[pos..].starts_with('*') {
            pos += 1;
        }
        let delimiter = character(text, pos, visit).context("missing TeX verb delimiter")?;
        ensure!(!delimiter.is_whitespace(), "invalid TeX verb delimiter");
        pos += delimiter.len_utf8();
        while let Some(c) = character(text, pos, visit) {
            ensure!(!matches!(c, '\r' | '\n'), "multiline TeX verb");
            pos += c.len_utf8();
            if c == delimiter {
                return Ok(Some(Region {
                    start,
                    end: pos,
                    kind: RegionKind::Literal,
                }));
            }
        }
        anyhow::bail!("unterminated TeX verb");
    }
    Ok(None)
}
