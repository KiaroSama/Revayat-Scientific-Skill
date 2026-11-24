//! Extract retained source text without matching across declaration owners.
use super::{MAX_DEPTH, Region, balanced_argument, definitions, document_extent, mask_regions};
use anyhow::{Result, ensure};
use regex::Regex;

pub fn plain_tex(text: &str) -> Result<String> {
    let analysis = definitions::Index::new(text).analyze()?;
    plain_tex_with_ranges(
        text,
        &analysis.ranges,
        &analysis.regions,
        &analysis.literal_spans,
        &analysis.data_comments,
    )
}

pub(super) fn plain_tex_with_ranges(
    text: &str,
    owners: &[(usize, usize)],
    regions: &[Region],
    literal_spans: &[(usize, usize)],
    data_comments: &[(usize, usize)],
) -> Result<String> {
    let region_masked = mask_regions(text, regions);
    let live = region_masked.replace("\\\\", "  ");
    let structural = definitions::mask(&live, owners);
    let (start, end) = document_extent(&structural);
    let mut body = live.as_bytes()[start..end].to_vec();
    let mut owned_matching = region_masked.into_bytes();
    for &(range_start, range_end) in literal_spans.iter().chain(data_comments) {
        owned_matching[range_start..range_end].fill(b' ');
    }
    // A literal's closing backslash belongs to that literal. Only normalize
    // remaining pairs after masking, so the next active control token survives.
    let owned_matching = String::from_utf8(owned_matching)
        .expect("whole-span masks preserve UTF-8")
        .replace("\\\\", "  ");

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
