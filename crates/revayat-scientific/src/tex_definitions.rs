//! Bounded recognition of complete newcommand/renewcommand definitions.
use super::balanced_argument;

pub(crate) fn ranges(masked: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut pos = 0;
    while pos < masked.len() {
        let tail = &masked[pos..];
        if !tail.starts_with('\\') {
            pos += tail.chars().next().unwrap().len_utf8();
            continue;
        }
        let length = tail[1..]
            .bytes()
            .take_while(|c| c.is_ascii_alphabetic() || *c == b'@')
            .count();
        if length == 0 {
            pos += 1;
            pos += masked[pos..].chars().next().map_or(0, char::len_utf8);
            continue;
        }
        let command_end = pos + 1 + length;
        if matches!(&masked[pos + 1..command_end], "newcommand" | "renewcommand")
            && let Some(end) = definition_end(masked, command_end)
        {
            ranges.push((pos, end));
            pos = end;
        } else {
            pos = command_end;
        }
    }
    ranges
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

fn definition_end(text: &str, command_end: usize) -> Option<usize> {
    let mut rest = text[command_end..].trim_start();
    if let Some(after_star) = rest.strip_prefix('*') {
        rest = after_star.trim_start();
    }
    let start = text.len() - rest.len();
    let name_end = if rest.starts_with('{') {
        balanced_argument(text, start).ok()?
    } else {
        let name = rest.strip_prefix('\\')?;
        let first = name.chars().next()?;
        let length = if first.is_ascii_alphabetic() || first == '@' {
            name.find(|c: char| !c.is_ascii_alphabetic() && c != '@')
                .unwrap_or(name.len())
        } else {
            first.len_utf8()
        };
        start + 1 + length
    };
    body_end(text, name_end)
}

fn body_end(text: &str, name_end: usize) -> Option<usize> {
    let mut rest = text[name_end..].trim_start();
    for _ in 0..2 {
        let Some(option) = rest.strip_prefix('[') else {
            break;
        };
        rest = option;
        loop {
            rest = &rest[rest.find(['\\', '{', ']'])?..];
            let end = match rest.as_bytes()[0] {
                b']' => {
                    rest = rest[1..].trim_start();
                    break;
                }
                b'{' => balanced_argument(rest, 0).ok()?,
                _ => 1 + rest[1..].chars().next()?.len_utf8(),
            };
            rest = &rest[end..];
        }
    }
    balanced_argument(text, text.len() - rest.len()).ok()
}
