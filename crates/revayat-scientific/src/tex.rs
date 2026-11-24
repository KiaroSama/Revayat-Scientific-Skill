//! Escape-aware TeX analysis. Never execute input to discover dependencies.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "tex_definitions.rs"]
pub(crate) mod definitions;
#[path = "tex_expansion.rs"]
mod expansion;
#[path = "tex_plain.rs"]
mod plain;
#[path = "tex_provenance.rs"]
mod provenance;
pub use expansion::source_closure;
pub use plain::plain_tex;
use plain::plain_tex_with_ranges;

pub const MAX_FILES: usize = 128;
pub const MAX_DEPTH: usize = 32;
pub const MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum RegionKind {
    Comment,
    Literal,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Region {
    pub start: usize,
    pub end: usize,
    pub kind: RegionKind,
}

/// One lexical pass handles paired backslashes, comments, inline literals and
/// verbatim environments. A malformed literal is an error, never a broad mask.
pub fn ignored_regions(text: &str) -> Result<Vec<Region>> {
    let mut regions = Vec::new();
    let mut pos = 0;
    while pos < text.len() {
        let tail = &text[pos..];
        if tail.starts_with('%') {
            let length = tail.find(['\r', '\n']).unwrap_or(tail.len());
            regions.push(Region {
                start: pos,
                end: pos + length,
                kind: RegionKind::Comment,
            });
            pos += length;
        } else if tail.starts_with('\\') {
            let mut literal_end = None;
            for env in ["verbatim", "verbatim*", "Verbatim", "lstlisting", "minted"] {
                let opening = format!("\\begin{{{env}}}");
                if tail.starts_with(&opening) {
                    let closing = format!("\\end{{{env}}}");
                    let end = tail[opening.len()..]
                        .find(&closing)
                        .context("unterminated or invalid literal TeX region")?;
                    literal_end = Some(pos + opening.len() + end + closing.len());
                    break;
                }
            }
            if literal_end.is_none()
                && tail.starts_with("\\verb")
                && !tail[5..].starts_with(|c: char| c.is_ascii_alphabetic())
            {
                let content = tail[5..].strip_prefix('*').unwrap_or(&tail[5..]);
                let delimiter = content
                    .chars()
                    .next()
                    .context("missing TeX verb delimiter")?;
                ensure!(!delimiter.is_whitespace(), "invalid TeX verb delimiter");
                let body = &content[delimiter.len_utf8()..];
                let end = body.find(delimiter).context("unterminated TeX verb")?;
                ensure!(!body[..end].contains(['\r', '\n']), "multiline TeX verb");
                literal_end = Some(pos + (tail.len() - body.len()) + end + delimiter.len_utf8());
            }
            if let Some(end) = literal_end {
                regions.push(Region {
                    start: pos,
                    end,
                    kind: RegionKind::Literal,
                });
                pos = end;
            } else {
                // Control symbols consume their next full Unicode scalar. This
                // also consumes \\ as a pair, leaving odd runs' final command live.
                pos += 1;
                if let Some(next) = text[pos..].chars().next() {
                    pos += next.len_utf8();
                }
            }
        } else {
            pos += tail.chars().next().expect("nonempty tail").len_utf8();
        }
    }
    Ok(regions)
}

pub fn masked_tex(text: &str) -> Result<String> {
    Ok(mask_regions(text, &ignored_regions(text)?))
}

pub(crate) fn mask_regions(text: &str, regions: &[Region]) -> String {
    let mut bytes = text.as_bytes().to_vec();
    for region in regions {
        for byte in &mut bytes[region.start..region.end] {
            if !matches!(byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(bytes).expect("mask preserves UTF-8")
}

pub fn live_tex(text: &str) -> Result<String> {
    Ok(masked_tex(text)?.replace("\\\\", "  "))
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub path: PathBuf,
    pub text: Arc<str>,
    #[serde(skip)]
    newlines: Vec<u32>,
    #[serde(skip)]
    blank_line_breaks: Vec<u32>,
    #[serde(skip)]
    definition_ranges: Option<Vec<(usize, usize)>>,
    #[serde(skip)]
    definition_starts: Option<Vec<usize>>,
    #[serde(skip)]
    literal_spans: Option<Vec<(usize, usize)>>,
    #[serde(skip)]
    data_comments: Option<Vec<(usize, usize)>>,
    #[serde(skip)]
    definition_context: bool,
    #[serde(skip)]
    definition_eof: bool,
    #[serde(skip)]
    lexical_regions: Option<Vec<Region>>,
}

impl Snapshot {
    pub fn new(path: PathBuf, text: Arc<str>) -> Result<Self> {
        ensure!(
            text.len() <= u32::MAX as usize,
            "source snapshot exceeds indexed size"
        );
        let mut newlines = Vec::new();
        let mut blank_line_breaks = Vec::new();
        let mut blank = true;
        let mut previous_cr = false;
        let mut line_start = 0;
        for (pos, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                newlines.push(pos as u32);
            }
            match byte {
                b'\r' | b'\n' => {
                    if blank && !(byte == b'\n' && previous_cr) {
                        blank_line_breaks.push(pos as u32);
                    }
                    blank = true;
                    previous_cr = byte == b'\r';
                    line_start = pos + 1;
                }
                _ => {
                    blank &= matches!(byte, b' ' | b'\t');
                    previous_cr = false;
                }
            }
        }
        // TeX supplies an endline for a nonempty final physical line. The
        // closure's generated separator represents that EOF boundary.
        if blank && line_start < text.len() {
            blank_line_breaks.push(text.len() as u32);
        }
        Ok(Self {
            path,
            text,
            newlines,
            blank_line_breaks,
            definition_ranges: None,
            definition_starts: None,
            literal_spans: None,
            data_comments: None,
            definition_context: false,
            definition_eof: false,
            lexical_regions: None,
        })
    }

    fn line(&self, position: i128) -> usize {
        let length = self.text.len() as i128;
        let clamped = if position < 0 {
            (length + position).max(0)
        } else {
            position.min(length)
        };
        if clamped == 0 {
            return 1;
        }
        crate::source::query::partition_index(&self.newlines, |n| *n as usize, clamped as usize - 1)
            + 1
    }

    /// Bytes used by the public newline index; paragraph metadata is separate.
    pub fn index_bytes(&self) -> usize {
        self.newlines.len() * size_of::<u32>()
    }
    pub fn newline_index(&self) -> &[u32] {
        &self.newlines
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Segment {
    pub start: usize,
    pub original_offset: usize,
    pub snapshot: Arc<Snapshot>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceClosure {
    pub text: String,
    pub segments: Vec<Segment>,
    pub sources: Vec<PathBuf>,
}

impl SourceClosure {
    pub fn location(&self, offset: isize) -> (PathBuf, usize) {
        if self.segments.is_empty() {
            return (self.sources.first().cloned().unwrap_or_default(), 1);
        }
        let index = if offset < 0 {
            0
        } else {
            crate::source::query::partition_index(
                &self.segments,
                |segment| segment.start,
                offset as usize,
            )
            .saturating_sub(1)
        };
        let segment = &self.segments[index];
        let position = segment.original_offset as i128 + offset as i128 - segment.start as i128;
        (
            segment.snapshot.path.clone(),
            segment.snapshot.line(position),
        )
    }
}

pub fn document_extent(live: &str) -> (usize, usize) {
    let Some(begin) = live.find("\\begin{document}") else {
        return (0, live.len());
    };
    let start = begin + "\\begin{document}".len();
    (
        start,
        live[start..]
            .find("\\end{document}")
            .map_or(live.len(), |end| start + end),
    )
}

pub fn balanced_argument(text: &str, open: usize) -> Result<usize> {
    ensure!(
        text.as_bytes().get(open) == Some(&b'{'),
        "missing TeX argument"
    );
    let mut depth = 1;
    let mut pos = open + 1;
    while pos < text.len() {
        match text.as_bytes()[pos] {
            b'\\' => {
                pos += 1;
                if let Some(next) = text[pos..].chars().next() {
                    pos += next.len_utf8();
                }
                continue;
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(pos + 1);
                }
            }
            _ => (),
        }
        pos += text[pos..].chars().next().unwrap().len_utf8();
    }
    bail!("unbalanced TeX prose argument")
}
