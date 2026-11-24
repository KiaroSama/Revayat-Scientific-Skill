//! Bounded original-file expansion and deferred declaration ownership.
use super::{MAX_BYTES, MAX_DEPTH, MAX_FILES, Segment, Snapshot, SourceClosure, definitions};
use anyhow::{Context, Result, bail, ensure};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[path = "tex_document_boundaries.rs"]
mod boundaries;
use boundaries::{Deferred, Marker, State};

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
    markers: Deferred,
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

fn include_source(
    text: &str,
    argument_start: usize,
    limit: usize,
    name: &str,
    inside_data: bool,
) -> Result<Option<(IncludeArgument, PathBuf)>> {
    if inside_data && argument_start >= limit {
        return Ok(None);
    }
    let argument = include_argument(&text[..limit], argument_start)?;
    let reference = argument.reference.trim();
    if inside_data && reference.is_empty() {
        return Ok(None);
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
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    ensure!(
        matches!(extension.as_str(), "tex" | "ltx"),
        "unsupported TeX include type"
    );
    Ok(Some((argument, child)))
}

struct Expansion {
    root: PathBuf,
    closure: SourceClosure,
    snapshots: Vec<PendingVisit>,
    segments: Vec<PendingSegment>,
    visits: usize,
    used_bytes: usize,
    document: State,
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
        // Committed ownership keeps provisional header markers as data.
        // Only a rejected or unresolved continuation applies their effect.
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

    fn append_data(
        &mut self,
        text: &str,
        view: definitions::DataView,
        visit: usize,
        stack: &mut Vec<PathBuf>,
        append_start: &mut usize,
    ) -> Result<()> {
        self.snapshots[visit]
            .snapshot
            .literal_spans
            .as_mut()
            .unwrap()
            .extend(view.literal_spans);
        self.snapshots[visit]
            .snapshot
            .data_comments
            .as_mut()
            .unwrap()
            .extend(view.comments);
        for input in view.includes {
            if input.start < *append_start {
                continue;
            }
            let Some((argument, child)) =
                include_source(text, input.argument_start, input.limit, input.name, true)?
            else {
                continue;
            };
            self.append(&text[*append_start..input.start], visit, *append_start);
            // The data cursor admits complete references outside literals. Raw
            // comments and argument ownership are recorded by the other walk.
            self.expand(&self.root.join(child), stack, true)?;
            *append_start = argument.end;
        }
        Ok(())
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
        snapshot.literal_spans = Some(Vec::new());
        snapshot.data_comments = Some(Vec::new());
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
        let mut unresolved: Option<PendingDefinition> = None;
        if definition_context && !self.document.ended() {
            let view = definitions.data_view(0, text.len(), None)?;
            self.append_data(&text, view, visit, stack, &mut append_start)?;
        }
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
                    if !self.document.ended() {
                        let view = definitions.data_view(start, end, Some(references))?;
                        self.append_data(&text, view, visit, stack, &mut append_start)?;
                    }
                    continue;
                }
                definitions::Item::Pending(pending) => {
                    unresolved.get_or_insert_with(|| PendingDefinition {
                        state: pending.state,
                        owners: vec![(visit, pending.start, text.len())],
                        markers: Deferred::default(),
                    });
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
            if self.document.ended() {
                continue;
            }
            let reference_limit =
                reference_scopes.observe(pos, nested_references, Some(text.len()));
            let tail = &text[pos..];
            let inside_definition = definition_context || pos < owned_end;
            let marker = if tail.starts_with("\\begin{document}") {
                Some(Marker::Begin)
            } else if tail.starts_with("\\end{document}") {
                Some(Marker::End)
            } else {
                None
            };
            if let Some(marker) = marker {
                if !inside_definition {
                    if let Some(pending) = &mut unresolved {
                        // Header tokens are collected, but ownership is not
                        // established until a caller supplies the whole body.
                        pending.markers.observe(marker);
                    } else {
                        self.document.observe(marker);
                    }
                }
                continue;
            }
            if inside_definition {
                // Owned dependencies were consumed by the independent data
                // view, including control starts exposed by a literal closer.
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
            let Some((argument, child)) =
                include_source(&text, argument_start, limit, name, inside_data)?
            else {
                continue;
            };
            self.append(&text[append_start..pos], visit, append_start);
            // Includes remain conservative dependencies even in a definition;
            // their document-marker tokens still belong to replacement data.
            let pending = self.expand(&self.root.join(child), stack, inside_definition)?;
            append_start = argument.end;
            definitions.advance(&mut cursor, argument.end);
            let Some(mut pending) = pending else {
                continue;
            };
            if name == "input"
                && !argument.braced
                && !inside_definition
                && cursor.allows_continuation()
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
                        let view = definitions.data_view(argument.end, end, Some(references))?;
                        self.append_data(&text, view, visit, stack, &mut append_start)?;
                    }
                    definitions::Completion::Pending(state) => {
                        pending.state = state;
                        pending.owners.push((visit, argument.end, text.len()));
                        collected_end = text.len();
                        let mut references = references;
                        references.end = text.len();
                        reference_scopes.select(references);
                        unresolved = Some(pending);
                    }
                    definitions::Completion::Invalid { unfinished } => {
                        pending.markers.apply(&mut self.document);
                        // A settled end retains strict lexical validation;
                        // it must not create a new recovery context afterward.
                        if unfinished && !self.document.ended() {
                            cursor.block_continuation();
                        }
                    }
                }
            } else {
                pending.markers.apply(&mut self.document);
            }
        }
        self.append(&text[append_start..], visit, append_start);
        if stack.len() > 1 && !text.is_empty() && !text.ends_with(['\n', '\r']) {
            self.append("\n", visit, text.len());
        }
        stack.pop();
        if definition_context || self.document.ended() {
            return Ok(None);
        }
        Ok(unresolved)
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
        document: State::Preamble,
    };
    if let Some(pending) = expansion.expand(&source, &mut Vec::new(), false)? {
        pending.markers.apply(&mut expansion.document);
    }
    Ok(expansion.finish())
}
