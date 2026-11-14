//! Escape-aware TeX analysis. Never execute input to discover dependencies.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    let mut bytes = text.as_bytes().to_vec();
    for region in ignored_regions(text)? {
        for byte in &mut bytes[region.start..region.end] {
            if !matches!(byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
    }
    Ok(String::from_utf8(bytes).expect("mask preserves UTF-8"))
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
}

impl Snapshot {
    pub fn new(path: PathBuf, text: Arc<str>) -> Result<Self> {
        ensure!(
            text.len() <= u32::MAX as usize,
            "source snapshot exceeds indexed size"
        );
        let newlines = text
            .bytes()
            .enumerate()
            .filter(|(_, c)| *c == b'\n')
            .map(|(pos, _)| pos as u32)
            .collect();
        Ok(Self {
            path,
            text,
            newlines,
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

struct Expansion {
    root: PathBuf,
    closure: SourceClosure,
    visits: usize,
    used_bytes: usize,
    started: bool,
    ended: bool,
}

impl Expansion {
    fn append(&mut self, text: &str, snapshot: &Arc<Snapshot>, original_offset: usize) {
        if text.is_empty() {
            return;
        }
        self.closure.segments.push(Segment {
            start: self.closure.text.len(),
            snapshot: snapshot.clone(),
            original_offset,
        });
        self.closure.text.push_str(text);
    }

    fn expand(&mut self, path: &Path, stack: &mut Vec<PathBuf>) -> Result<()> {
        let path = fs::canonicalize(path)
            .with_context(|| format!("missing literal TeX include: {}", path.display()))?;
        ensure!(
            path.starts_with(&self.root),
            "TeX include leaves the approved job root"
        );
        ensure!(!stack.contains(&path), "TeX include cycle detected");
        ensure!(stack.len() < MAX_DEPTH, "TeX include depth exceeds 32");
        self.visits += 1;
        ensure!(
            self.visits <= MAX_FILES,
            "TeX closure exceeds 128 file visits"
        );
        ensure!(path.is_file(), "missing literal TeX include");
        let size = fs::metadata(&path)?.len();
        ensure!(
            size <= (MAX_BYTES - self.used_bytes) as u64,
            "TeX closure exceeds 16 MiB"
        );
        // Limit the read too: a file may grow between metadata and read.
        use std::io::Read;
        let mut raw = Vec::new();
        fs::File::open(&path)?
            .take((MAX_BYTES - self.used_bytes + 1) as u64)
            .read_to_end(&mut raw)?;
        self.used_bytes += raw.len();
        ensure!(self.used_bytes <= MAX_BYTES, "TeX closure exceeds 16 MiB");
        let text = String::from_utf8(raw).context("TeX source is not UTF-8")?;
        let snapshot = Arc::new(Snapshot::new(path.clone(), Arc::from(text.as_str()))?);
        if !self.closure.sources.contains(&path) {
            self.closure.sources.push(path.clone());
        }
        let live = masked_tex(&text)?;
        stack.push(path);
        let mut cursor = 0;
        let mut pos = 0;
        while pos < live.len() && !self.ended {
            let tail = &live[pos..];
            if !tail.starts_with('\\') {
                pos += tail.chars().next().unwrap().len_utf8();
                continue;
            }
            if tail.starts_with("\\\\") {
                pos += 2;
                continue;
            }
            if tail.starts_with("\\begin{document}") {
                self.started = true;
                pos += "\\begin{document}".len();
                continue;
            }
            if tail.starts_with("\\end{document}") {
                if self.started {
                    self.ended = true;
                }
                pos += "\\end{document}".len();
                continue;
            }
            let command_length = tail[1..]
                .bytes()
                .take_while(u8::is_ascii_alphabetic)
                .count();
            let name = &tail[1..1 + command_length];
            if !matches!(name, "input" | "include" | "includeonly") {
                pos += 1 + command_length;
                if command_length == 0 {
                    pos += live[pos..].chars().next().map_or(0, char::len_utf8);
                }
                continue;
            }
            ensure!(
                name != "includeonly",
                "includeonly requires an explicit reviewed source closure"
            );
            let mut argument_start = pos + 1 + command_length;
            argument_start +=
                live[argument_start..].len() - live[argument_start..].trim_start().len();
            let (name_start, name_end, argument_end) = if live[argument_start..].starts_with('{') {
                let close = live[argument_start + 1..]
                    .find('}')
                    .context("unsupported dynamic or missing TeX include")?;
                let end = argument_start + 1 + close;
                ensure!(
                    !live[argument_start + 1..end].contains('{'),
                    "unsupported dynamic TeX include"
                );
                (argument_start + 1, end, end + 1)
            } else {
                let length = live[argument_start..]
                    .find(|c: char| c.is_whitespace() || matches!(c, '{' | '}'))
                    .unwrap_or(live.len() - argument_start);
                (
                    argument_start,
                    argument_start + length,
                    argument_start + length,
                )
            };
            let reference = live[name_start..name_end].trim();
            ensure!(
                !reference.is_empty() && !reference.contains(['\\', '#', '$', '%', '~', '^', '&']),
                "unsupported dynamic TeX include"
            );
            let mut child = PathBuf::from(reference);
            if child.extension().is_none() {
                child.set_extension("tex");
            }
            let extension = child
                .extension()
                .and_then(|x| x.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            ensure!(
                matches!(extension.as_str(), "tex" | "ltx"),
                "unsupported TeX include type"
            );
            self.append(&text[cursor..pos], &snapshot, cursor);
            self.expand(&self.root.join(child), stack)?;
            cursor = argument_end;
            pos = argument_end;
        }
        self.append(&text[cursor..], &snapshot, cursor);
        if stack.len() > 1 && !text.is_empty() && !text.ends_with(['\n', '\r']) {
            self.append("\n", &snapshot, text.len());
        }
        stack.pop();
        Ok(())
    }
}

pub fn source_closure(source: &Path, root: Option<&Path>) -> Result<SourceClosure> {
    let source = fs::canonicalize(source)?;
    let root = fs::canonicalize(
        root.unwrap_or_else(|| source.parent().expect("absolute source has parent")),
    )?;
    let mut expansion = Expansion {
        root,
        closure: SourceClosure {
            text: String::new(),
            segments: Vec::new(),
            sources: Vec::new(),
        },
        visits: 0,
        used_bytes: 0,
        started: false,
        ended: false,
    };
    expansion.expand(&source, &mut Vec::new())?;
    Ok(expansion.closure)
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

pub fn plain_tex(text: &str) -> Result<String> {
    use regex::Regex;
    let live = live_tex(text)?;
    let (start, end) = document_extent(&live);
    let mut body = live[start..end].to_owned();
    for env in [
        "latin",
        "equation",
        "equation*",
        "align",
        "align*",
        "displaymath",
        "math",
    ] {
        let pattern = format!(
            "(?s){}.*?{}",
            regex::escape(&format!("\\begin{{{env}}}")),
            regex::escape(&format!("\\end{{{env}}}"))
        );
        body = Regex::new(&pattern)?.replace_all(&body, " ").into_owned();
    }
    for (open, close) in [("$$", "$$"), ("$", "$"), ("\\[", "\\]"), ("\\(", "\\)")] {
        let mut pos = 0;
        let mut result = String::new();
        while let Some(index) = body[pos..].find(open) {
            let index = pos + index;
            if index > 0 && body.as_bytes()[index - 1] == b'\\' {
                result.push_str(&body[pos..index + open.len()]);
                pos = index + open.len();
                continue;
            }
            let Some(end) = body[index + open.len()..].find(close) else {
                break;
            };
            result.push_str(&body[pos..index]);
            result.push(' ');
            pos = index + open.len() + end + close.len();
        }
        result.push_str(&body[pos..]);
        body = result;
    }
    fn unwrap(text: &str, depth: usize) -> Result<String> {
        ensure!(depth < MAX_DEPTH, "TeX formatting depth exceeds 32");
        let command = Regex::new(r"^\\([A-Za-z@]+)\*?(?:\[[^\]]*\])?\s*")?;
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
                        result.push_str(&unwrap(&text[pos + 1..end - 1], depth + 1)?);
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
    Ok(unwrap(&body, 0)?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" "))
}
