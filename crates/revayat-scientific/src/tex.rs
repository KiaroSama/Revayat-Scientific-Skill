//! Escape-aware TeX analysis. Never execute input to discover dependencies.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[path = "tex_definitions.rs"]
pub(crate) mod definitions;
#[path = "tex_plain.rs"]
mod plain;
#[path = "tex_provenance.rs"]
mod provenance;
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
    literal_candidates: Option<Vec<(usize, usize)>>,
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
            literal_candidates: None,
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

struct PendingVisit {
    snapshot: Snapshot,
    continued_ranges: Vec<(usize, usize)>,
}

struct PendingSegment {
    start: usize,
    original_offset: usize,
    visit: usize,
}

struct PendingDefinition {
    state: definitions::Continuation,
    owners: Vec<(usize, usize, usize)>,
}

struct IncludeArgument {
    reference: String,
    end: usize,
    braced: bool,
}

fn include_argument(text: &str, mut pos: usize) -> Result<IncludeArgument> {
    loop {
        pos += text[pos..].len() - text[pos..].trim_start().len();
        if !text[pos..].starts_with('%') {
            break;
        }
        pos += text[pos..].find(['\r', '\n']).unwrap_or(text.len() - pos);
    }
    let braced = text[pos..].starts_with('{');
    if !braced {
        let length = text[pos..]
            .find(|c: char| c.is_whitespace() || matches!(c, '{' | '}' | '%'))
            .unwrap_or(text.len() - pos);
        return Ok(IncludeArgument {
            reference: text[pos..pos + length].to_owned(),
            end: pos + length,
            braced,
        });
    }
    pos += 1;
    let mut reference = String::new();
    while let Some(character) = text[pos..].chars().next() {
        match character {
            '}' => {
                return Ok(IncludeArgument {
                    reference,
                    end: pos + 1,
                    braced,
                });
            }
            '{' => bail!("unsupported dynamic TeX include"),
            '%' => {
                let length = text[pos..].find(['\r', '\n']).unwrap_or(text.len() - pos);
                reference.extend(std::iter::repeat_n(' ', length));
                pos += length;
            }
            _ => {
                reference.push(character);
                pos += character.len_utf8();
            }
        }
    }
    bail!("unsupported dynamic or missing TeX include")
}

struct Expansion {
    root: PathBuf,
    closure: SourceClosure,
    snapshots: Vec<PendingVisit>,
    segments: Vec<PendingSegment>,
    visits: usize,
    used_bytes: usize,
    started: bool,
    ended: bool,
}

impl Expansion {
    fn append(&mut self, text: &str, visit: usize, original_offset: usize) {
        if text.is_empty() {
            return;
        }
        self.segments.push(PendingSegment {
            start: self.closure.text.len(),
            original_offset,
            visit,
        });
        self.closure.text.push_str(text);
    }

    fn complete_definition(&mut self, pending: PendingDefinition) {
        if let Some(&(visit, start, _)) = pending.owners.first() {
            self.snapshots[visit]
                .snapshot
                .definition_starts
                .as_mut()
                .unwrap()
                .push(start);
        }
        for (visit, start, end) in pending.owners {
            self.snapshots[visit].continued_ranges.push((start, end));
            // An included file without a final newline receives a synthetic
            // separator. It belongs to a declaration continuing after EOF too.
            self.snapshots[visit].snapshot.definition_eof = true;
        }
    }

    fn finish(mut self) -> SourceClosure {
        let snapshots: Vec<_> = self
            .snapshots
            .into_iter()
            .map(|mut visit| {
                if !visit.continued_ranges.is_empty() {
                    let original = visit.snapshot.definition_ranges.take().unwrap();
                    visit.snapshot.definition_ranges =
                        Some(merge_definition_ranges(original, visit.continued_ranges));
                }
                Arc::new(visit.snapshot)
            })
            .collect();
        self.closure.segments = self
            .segments
            .into_iter()
            .map(|segment| Segment {
                start: segment.start,
                original_offset: segment.original_offset,
                snapshot: snapshots[segment.visit].clone(),
            })
            .collect();
        self.closure
    }

    fn expand(
        &mut self,
        path: &Path,
        stack: &mut Vec<PathBuf>,
        definition_context: bool,
    ) -> Result<Option<PendingDefinition>> {
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
        if !self.closure.sources.contains(&path) {
            self.closure.sources.push(path.clone());
        }
        let definitions = definitions::Index::new(&text);
        let mut snapshot = Snapshot::new(path.clone(), Arc::from(text.as_str()))?;
        snapshot.definition_ranges = Some(Vec::new());
        snapshot.definition_starts = Some(Vec::new());
        snapshot.literal_candidates = Some(Vec::new());
        snapshot.lexical_regions = Some(Vec::new());
        snapshot.definition_context = definition_context;
        let visit = self.snapshots.len();
        self.snapshots.push(PendingVisit {
            snapshot,
            continued_ranges: Vec::new(),
        });
        stack.push(path);
        let mut append_start = 0;
        let mut cursor = definitions.cursor(0);
        let mut owned_end = 0;
        let mut collected_end = 0;
        let mut reference_scopes = definitions::ReferenceScopes::default();
        let mut local_pending = None;
        let mut continued = None;
        while let Some(item) = definitions.next(
            &mut cursor,
            if definition_context {
                text.len()
            } else {
                collected_end
            },
        )? {
            let (pos, token_end, nested_references) = match item {
                definitions::Item::Definition {
                    start,
                    end,
                    references,
                } => {
                    self.snapshots[visit].snapshot.definition_eof |= definitions.owns_eof(end);
                    self.snapshots[visit]
                        .snapshot
                        .definition_ranges
                        .as_mut()
                        .unwrap()
                        .push((start, end));
                    self.snapshots[visit]
                        .snapshot
                        .definition_starts
                        .as_mut()
                        .unwrap()
                        .push(start);
                    owned_end = end;
                    collected_end = end;
                    reference_scopes.select(references);
                    continue;
                }
                definitions::Item::Pending(pending) => {
                    local_pending.get_or_insert(pending);
                    // A pending header has already collected its name/options.
                    // Keep those tokens unexpanded without granting ownership
                    // until an eventual caller establishes the complete body.
                    collected_end = text.len();
                    reference_scopes.pending(text.len());
                    continue;
                }
                definitions::Item::Ignored(region) => {
                    self.snapshots[visit]
                        .snapshot
                        .lexical_regions
                        .as_mut()
                        .unwrap()
                        .push(region);
                    continue;
                }
                definitions::Item::Token {
                    start,
                    end,
                    references,
                } => (start, end, references),
            };
            // Keep lexical validation/projection of the original tail, but do
            // not discover dependencies or resume definitions after the end.
            if self.ended {
                continue;
            }
            let reference_limit =
                reference_scopes.observe(pos, nested_references, Some(text.len()));
            let tail = &text[pos..];
            let inside_definition = definition_context || pos < owned_end;
            if inside_definition
                && let Some(limit) = reference_limit
                && definitions::literal_start(&text, pos)
            {
                self.snapshots[visit]
                    .snapshot
                    .literal_candidates
                    .as_mut()
                    .unwrap()
                    .push((pos, limit));
            }
            if tail.starts_with("\\begin{document}") {
                if !inside_definition {
                    self.started = true;
                }
                continue;
            }
            if tail.starts_with("\\end{document}") {
                if self.started && !inside_definition {
                    self.ended = true;
                }
                continue;
            }
            let Some(command) = text[pos..token_end].strip_prefix('\\') else {
                continue;
            };
            // Dependency dispatch retains the established default-catcode
            // boundary. Definition-name tokenization separately supports @.
            let length = command.bytes().take_while(u8::is_ascii_alphabetic).count();
            let name = &command[..length];
            if !matches!(name, "input" | "include" | "includeonly") {
                continue;
            }
            let Some(limit) = reference_limit else {
                continue;
            };
            let argument_start = pos + 1 + length;
            let inside_data = definition_context || !reference_scopes.is_empty();
            if inside_data && argument_start >= limit {
                continue;
            }
            let argument = include_argument(&text[..limit], argument_start)?;
            let reference = argument.reference.trim();
            if inside_data && reference.is_empty() {
                continue;
            }
            ensure!(
                name != "includeonly",
                "includeonly requires an explicit reviewed source closure"
            );
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
            self.append(&text[append_start..pos], visit, append_start);
            // Includes remain conservative dependencies even in a definition;
            // their document-marker tokens still belong to replacement data.
            let pending = self.expand(&self.root.join(child), stack, inside_definition)?;
            if name == "input"
                && !argument.braced
                && !inside_definition
                && cursor.allows_continuation()
                && let Some(mut pending) = pending
            {
                let (completion, references) =
                    definitions.resume_with_references(argument.end, pending.state);
                match completion {
                    definitions::Completion::Complete(end) => {
                        self.complete_definition(pending);
                        self.snapshots[visit].snapshot.definition_eof |= definitions.owns_eof(end);
                        self.snapshots[visit]
                            .continued_ranges
                            .push((argument.end, end));
                        owned_end = end;
                        collected_end = end;
                        reference_scopes.select(references);
                    }
                    definitions::Completion::Pending(state) => {
                        pending.state = state;
                        pending.owners.push((visit, argument.end, text.len()));
                        collected_end = text.len();
                        let mut references = references;
                        references.end = text.len();
                        reference_scopes.select(references);
                        continued = Some(pending);
                    }
                    definitions::Completion::Invalid => (),
                }
            }
            append_start = argument.end;
            definitions.advance(&mut cursor, argument.end);
        }
        self.append(&text[append_start..], visit, append_start);
        if stack.len() > 1 && !text.is_empty() && !text.ends_with(['\n', '\r']) {
            self.append("\n", visit, text.len());
        }
        stack.pop();
        if definition_context || self.ended {
            return Ok(None);
        }
        Ok(continued.or_else(|| {
            local_pending.map(|pending| PendingDefinition {
                state: pending.state,
                owners: vec![(visit, pending.start, text.len())],
            })
        }))
    }
}

fn merge_definition_ranges(
    original: Vec<(usize, usize)>,
    mut continued: Vec<(usize, usize)>,
) -> Vec<(usize, usize)> {
    // Original scanner ranges are already sorted. Only the small set of EOF
    // continuations can arrive later, so merge without sorting the whole source.
    continued.sort_unstable();
    let mut original = original.into_iter().peekable();
    let mut continued = continued.into_iter().peekable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    while original.peek().is_some() || continued.peek().is_some() {
        let (start, end) = if continued.peek().is_none()
            || original
                .peek()
                .is_some_and(|range| continued.peek().is_some_and(|next| range <= next))
        {
            original.next().unwrap()
        } else {
            continued.next().unwrap()
        };
        if start >= end {
            continue;
        }
        if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
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
        snapshots: Vec::new(),
        segments: Vec::new(),
        visits: 0,
        used_bytes: 0,
        started: false,
        ended: false,
    };
    expansion.expand(&source, &mut Vec::new(), false)?;
    Ok(expansion.finish())
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
