//! Extract retained source text without matching across declaration owners.
use super::{MAX_DEPTH, Region, balanced_argument, definitions, document_extent, mask_regions};
use anyhow::{Result, ensure};
use regex::Regex;
use std::collections::BTreeMap;

pub fn plain_tex(text: &str) -> Result<String> {
    let analysis = definitions::Index::new(text).analyze()?;
    plain_tex_with_ranges(
        text,
        &analysis.ranges,
        &analysis.regions,
        &analysis.literal_candidates,
    )
}

pub(super) fn plain_tex_with_ranges(
    text: &str,
    owners: &[(usize, usize)],
    regions: &[Region],
    literal_candidates: &[(usize, usize)],
) -> Result<String> {
    let live = mask_regions(text, regions).replace("\\\\", "  ");
    let structural = definitions::mask(&live, owners);
    let (start, end) = document_extent(&structural);
    let mut body = live.as_bytes()[start..end].to_vec();
    let mut owned_matching = live.as_bytes().to_vec();
    for (literal_start, literal_end) in owned_literals(text, owners, literal_candidates) {
        owned_matching[literal_start..literal_end].fill(b' ');
    }
    let owned_matching =
        String::from_utf8(owned_matching).expect("whole-span masks preserve UTF-8");

    // Live pairs may span an unused definition, but its data cannot provide
    // their delimiters. Exclusions retain source offsets until matching ends.
    exclude_domain(&structural[start..end], &mut body, 0);
    for &(owner_start, owner_end) in owners {
        let owner_start = owner_start.max(start);
        let owner_end = owner_end.min(end);
        if owner_start < owner_end {
            // Literal data hides delimiters only in this matching view. Retained
            // output still follows raw argument collection, including literal
            // payload, while genuine paired math retains its legacy exclusion.
            exclude_domain(
                &owned_matching[owner_start..owner_end],
                &mut body,
                owner_start - start,
            );
        }
    }
    let body = String::from_utf8(body).expect("whole-span masks preserve UTF-8");
    let command = Regex::new(r"^\\([A-Za-z@]+)\*?(?:\[[^\]]*\])?\s*")?;
    Ok(unwrap(&body, 0, &command)?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" "))
}

fn owned_literals(
    text: &str,
    owners: &[(usize, usize)],
    candidates: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    // Candidate eligibility and data limits come from original file visits, not
    // a reparse of flattened child braces. Cap every match at its actual owner.
    let mut eligible = Vec::new();
    let mut owner = 0;
    for &(start, limit) in candidates {
        while owner < owners.len() && owners[owner].1 <= start {
            owner += 1;
        }
        if owner < owners.len() && owners[owner].0 <= start {
            eligible.push((start, limit.min(owners[owner].1)));
        }
    }
    let mut ends = vec![None; eligible.len()];
    let mut inline = Vec::new();
    let mut nearest = BTreeMap::new();
    for (index, &(start, limit)) in eligible.iter().enumerate() {
        let tail = &text[start..];
        if tail.starts_with("\\verb") && !tail[5..].starts_with(|c: char| c.is_ascii_alphabetic()) {
            let offset = start + 5 + usize::from(tail[5..].starts_with('*'));
            if let Some(delimiter) = text[offset..].chars().next()
                && !delimiter.is_whitespace()
                && offset + delimiter.len_utf8() < limit
            {
                inline.push((offset, delimiter, index));
                nearest.insert(delimiter, usize::MAX);
            }
        }
    }
    // Resolve all inline closers together. An incomplete literal never causes
    // a suffix search, a broad mask, or a new error in unexpanded source data.
    inline.sort_unstable_by_key(|entry| entry.0);
    let mut query = inline.len();
    let mut line_end = text.len();
    if query != 0 {
        for (position, scalar) in text.char_indices().rev() {
            while query != 0 && inline[query - 1].0 == position {
                let (_, delimiter, index) = inline[query - 1];
                let close = nearest[&delimiter];
                if close < line_end {
                    let end = close + delimiter.len_utf8();
                    if end <= eligible[index].1 {
                        ends[index] = Some(end);
                    }
                }
                query -= 1;
            }
            if matches!(scalar, '\r' | '\n') {
                line_end = position;
            }
            if let Some(next) = nearest.get_mut(&scalar) {
                *next = position;
            }
        }
    }
    for (opening, closing) in [
        ("\\begin{verbatim}", "\\end{verbatim}"),
        ("\\begin{verbatim*}", "\\end{verbatim*}"),
        ("\\begin{Verbatim}", "\\end{Verbatim}"),
        ("\\begin{lstlisting}", "\\end{lstlisting}"),
        ("\\begin{minted}", "\\end{minted}"),
    ] {
        // Five fixed closer censuses bound malformed-environment work too.
        let closers: Vec<_> = text.match_indices(closing).map(|entry| entry.0).collect();
        for (index, &(start, limit)) in eligible.iter().enumerate() {
            if text[start..].starts_with(opening) {
                let next = closers.partition_point(|&position| position < start + opening.len());
                if let Some(&close) = closers.get(next)
                    && close + closing.len() <= limit
                {
                    ends[index] = Some(close + closing.len());
                }
            }
        }
    }
    let mut result = Vec::new();
    let mut occupied_until = 0;
    for ((start, _), end) in eligible.into_iter().zip(ends) {
        if let Some(end) = end
            && start >= occupied_until
        {
            result.push((start, end));
            occupied_until = end;
        }
    }
    result
}

fn exclude_domain(text: &str, output: &mut [u8], offset: usize) {
    let mut matching = text.as_bytes().to_vec();
    for (open, close) in [
        ("\\begin{latin}", "\\end{latin}"),
        ("\\begin{equation}", "\\end{equation}"),
        ("\\begin{equation*}", "\\end{equation*}"),
        ("\\begin{align}", "\\end{align}"),
        ("\\begin{align*}", "\\end{align*}"),
        ("\\begin{displaymath}", "\\end{displaymath}"),
        ("\\begin{math}", "\\end{math}"),
    ] {
        exclude_pairs(&mut matching, output, offset, open, close, false);
    }
    for (open, close) in [("$$", "$$"), ("$", "$"), ("\\[", "\\]"), ("\\(", "\\)")] {
        exclude_pairs(&mut matching, output, offset, open, close, true);
    }
}

fn exclude_pairs(
    matching: &mut [u8],
    output: &mut [u8],
    offset: usize,
    open: &str,
    close: &str,
    escaped_delimiters: bool,
) {
    let text = std::str::from_utf8(matching).expect("whole-span masks preserve UTF-8");
    let mut ranges = Vec::new();
    let mut pos = 0;
    while let Some(relative) = text[pos..].find(open) {
        let start = pos + relative;
        if escaped_delimiters && start > 0 && matching[start - 1] == b'\\' {
            // Preserve an overlapping display opener after an escaped dollar.
            pos = start + 1;
            continue;
        }
        let mut closing = start + open.len();
        let end = loop {
            let Some(relative_end) = text[closing..].find(close) else {
                break None;
            };
            let candidate = closing + relative_end;
            if !escaped_delimiters || candidate == 0 || matching[candidate - 1] != b'\\' {
                break Some(candidate + close.len());
            }
            // Supported delimiters start with ASCII. Advance monotonically by
            // one byte so overlapping display-delimiter candidates stay visible.
            closing = candidate + 1;
        };
        let Some(end) = end else {
            break;
        };
        ranges.push((start, end));
        pos = end;
    }
    // Masking both views unions exclusions without concatenating unmatched
    // delimiters or changing any later owner's original byte coordinates.
    for (start, end) in ranges {
        matching[start..end].fill(b' ');
        output[offset + start..offset + end].fill(b' ');
    }
}

fn unwrap(text: &str, depth: usize, command: &Regex) -> Result<String> {
    ensure!(depth < MAX_DEPTH, "TeX formatting depth exceeds 32");
    let discard = [
        "en",
        "lr",
        "textenglish",
        "texttt",
        "url",
        "label",
        "ref",
        "eqref",
        "cite",
        "includegraphics",
        "begin",
        "end",
    ];
    let mut result = String::new();
    let mut pos = 0;
    while pos < text.len() {
        if let Some(capture) = command.captures(&text[pos..]) {
            pos += capture.get(0).unwrap().end();
            if text[pos..].starts_with('{') {
                let end = balanced_argument(text, pos)?;
                if discard.contains(&&capture[1]) {
                    result.push(' ');
                } else {
                    result.push_str(&unwrap(&text[pos + 1..end - 1], depth + 1, command)?);
                }
                pos = end;
            } else {
                result.push(' ');
            }
        } else {
            let next = text[pos..].chars().next().unwrap();
            result.push(if matches!(next, '{' | '}' | '\\') {
                ' '
            } else {
                next
            });
            pos += next.len_utf8();
        }
    }
    Ok(result)
}
