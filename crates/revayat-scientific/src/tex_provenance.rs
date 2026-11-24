//! Project immutable per-visit definition ownership onto an expanded closure.
use super::{Region, SourceClosure, definitions, plain_tex_with_ranges};
use anyhow::Result;
use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::Arc;

type CachedDefinitionMetadata = (Vec<(usize, usize)>, bool, Vec<usize>);

#[derive(Clone, Copy)]
enum DataSpanKind {
    Literal,
    Comment,
}

impl SourceClosure {
    pub(crate) fn is_blank_line_break(&self, offset: usize) -> bool {
        if self.segments.is_empty() {
            return false;
        }
        let index =
            crate::source::query::partition_index(&self.segments, |segment| segment.start, offset)
                .saturating_sub(1);
        let segment = &self.segments[index];
        let Some(original) = offset
            .checked_sub(segment.start)
            .and_then(|relative| segment.original_offset.checked_add(relative))
            .and_then(|original| u32::try_from(original).ok())
        else {
            return false;
        };
        segment
            .snapshot
            .blank_line_breaks
            .binary_search(&original)
            .is_ok()
    }

    pub(crate) fn definition_ranges(&self) -> Result<Vec<(usize, usize)>> {
        self.projected_definition_ranges(false)
    }

    fn projected_definition_ranges(&self, separate_owners: bool) -> Result<Vec<(usize, usize)>> {
        if self.segments.is_empty() {
            return Ok(definitions::Index::new(&self.text).analyze()?.ranges);
        }
        let mut result = Vec::new();
        let mut defaults: BTreeMap<_, CachedDefinitionMetadata> = BTreeMap::new();
        for (index, segment) in self.segments.iter().enumerate() {
            let output_end = self
                .segments
                .get(index + 1)
                .map_or(self.text.len(), |next| next.start)
                .min(self.text.len());
            if segment.start >= output_end {
                continue;
            }
            if segment.snapshot.definition_context {
                append_range(&mut result, segment.start, output_end, false);
                continue;
            }
            // Public Snapshot::new remains usable by manually assembled
            // closures. Parse each such immutable snapshot only once here.
            let (ranges, definition_eof, starts): (&[(usize, usize)], bool, &[usize]) =
                match &segment.snapshot.definition_ranges {
                    Some(ranges) => (
                        ranges,
                        segment.snapshot.definition_eof,
                        segment.snapshot.definition_starts.as_deref().unwrap_or(&[]),
                    ),
                    None => {
                        let value = match defaults.entry(Arc::as_ptr(&segment.snapshot)) {
                            Entry::Occupied(entry) => entry.into_mut(),
                            Entry::Vacant(entry) => {
                                let index = definitions::Index::new(&segment.snapshot.text);
                                let analysis = index.analyze()?;
                                let eof = analysis
                                    .ranges
                                    .last()
                                    .is_some_and(|&(_, end)| index.owns_eof(end));
                                let starts = analysis.ranges.iter().map(|range| range.0).collect();
                                entry.insert((analysis.ranges, eof, starts))
                            }
                        };
                        (&value.0, value.1, &value.2)
                    }
                };
            if definition_eof && segment.original_offset >= segment.snapshot.text.len() {
                append_range(&mut result, segment.start, output_end, false);
                continue;
            }
            let original_start = segment.original_offset;
            let original_end = original_start
                .saturating_add(output_end - segment.start)
                .min(segment.snapshot.text.len());
            let first = ranges.partition_point(|&(_, end)| end <= original_start);
            for &(start, end) in &ranges[first..] {
                if start >= original_end {
                    break;
                }
                let clipped_start = start.max(original_start);
                let clipped_end = end.min(original_end);
                let project = |position| segment.start + position - original_start;
                let mut current = clipped_start;
                let mut new_owner = false;
                if separate_owners {
                    let first_start = starts.partition_point(|&position| position < clipped_start);
                    for &boundary in &starts[first_start..] {
                        if boundary >= clipped_end {
                            break;
                        }
                        append_range(&mut result, project(current), project(boundary), new_owner);
                        current = boundary;
                        new_owner = true;
                    }
                }
                append_range(
                    &mut result,
                    project(current),
                    project(clipped_end),
                    new_owner,
                );
            }
        }
        Ok(result)
    }

    /// Extract text using the original definition ownership of each file visit.
    pub fn plain_text(&self) -> Result<String> {
        plain_tex_with_ranges(
            &self.text,
            &self.projected_definition_ranges(true)?,
            &self.lexical_regions()?,
            &self.literal_spans()?,
            &self.data_comments()?,
        )
    }

    pub(crate) fn literal_spans(&self) -> Result<Vec<(usize, usize)>> {
        self.projected_data_spans(DataSpanKind::Literal)
    }

    pub(crate) fn data_comments(&self) -> Result<Vec<(usize, usize)>> {
        self.projected_data_spans(DataSpanKind::Comment)
    }

    fn projected_data_spans(&self, kind: DataSpanKind) -> Result<Vec<(usize, usize)>> {
        if self.segments.is_empty() {
            let analysis = definitions::Index::new(&self.text).analyze()?;
            return Ok(match kind {
                DataSpanKind::Literal => analysis.literal_spans,
                DataSpanKind::Comment => analysis.data_comments,
            });
        }
        #[derive(Clone, Copy)]
        struct Origin {
            snapshot: *const super::Snapshot,
            span: (usize, usize),
            original_end: usize,
        }
        let mut defaults: BTreeMap<_, Vec<(usize, usize)>> = BTreeMap::new();
        let mut result: Vec<(usize, usize)> = Vec::new();
        let mut previous: Option<Origin> = None;
        for (index, segment) in self.segments.iter().enumerate() {
            let output_end = self
                .segments
                .get(index + 1)
                .map_or(self.text.len(), |next| next.start)
                .min(self.text.len());
            let original_start = segment.original_offset;
            if segment.start >= output_end || original_start > segment.snapshot.text.len() {
                continue;
            }
            let original_end = original_start
                .saturating_add(output_end - segment.start)
                .min(segment.snapshot.text.len());
            if original_start >= original_end {
                continue;
            }
            let identity = Arc::as_ptr(&segment.snapshot);
            let stored = match kind {
                DataSpanKind::Literal => &segment.snapshot.literal_spans,
                DataSpanKind::Comment => &segment.snapshot.data_comments,
            };
            let spans = match stored {
                Some(spans) => spans,
                None => match defaults.entry(identity) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        let analysis = definitions::Index::new(&segment.snapshot.text).analyze()?;
                        entry.insert(match kind {
                            DataSpanKind::Literal => analysis.literal_spans,
                            DataSpanKind::Comment => analysis.data_comments,
                        })
                    }
                },
            };
            let first = spans.partition_point(|&(_, end)| end <= original_start);
            for &(start, end) in &spans[first..] {
                if start >= original_end {
                    break;
                }
                let clipped_start = start.max(original_start);
                let clipped_end = end.min(original_end);
                if clipped_start >= clipped_end {
                    continue;
                }
                let projected_start = segment.start + clipped_start - original_start;
                let projected_end = segment.start + clipped_end - original_start;
                // Intersect with each source piece; a foreign visit between
                // pieces must never inherit this span. Contiguous byte-stride
                // pieces of the same original span still form one UTF-8 mask.
                let same_span = previous.is_some_and(|previous| {
                    previous.snapshot == identity
                        && previous.span == (start, end)
                        && previous.original_end == clipped_start
                });
                if same_span
                    && let Some(last) = result.last_mut().filter(|last| last.1 == projected_start)
                {
                    last.1 = projected_end;
                } else {
                    result.push((projected_start, projected_end));
                }
                previous = Some(Origin {
                    snapshot: identity,
                    span: (start, end),
                    original_end: clipped_end,
                });
            }
        }
        Ok(result)
    }

    pub(crate) fn lexical_regions(&self) -> Result<Vec<Region>> {
        if self.segments.is_empty() {
            return Ok(definitions::Index::new(&self.text).analyze()?.regions);
        }
        let mut result: Vec<Region> = Vec::new();
        let mut defaults: BTreeMap<_, Vec<Region>> = BTreeMap::new();
        for (index, segment) in self.segments.iter().enumerate() {
            let output_end = self
                .segments
                .get(index + 1)
                .map_or(self.text.len(), |next| next.start)
                .min(self.text.len());
            if segment.start >= output_end {
                continue;
            }
            let regions = match &segment.snapshot.lexical_regions {
                Some(regions) => regions,
                None => match defaults.entry(Arc::as_ptr(&segment.snapshot)) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => entry.insert(
                        definitions::Index::new(&segment.snapshot.text)
                            .analyze()?
                            .regions,
                    ),
                },
            };
            let original_start = segment.original_offset;
            let original_end = original_start
                .saturating_add(output_end - segment.start)
                .min(segment.snapshot.text.len());
            let first = regions.partition_point(|region| region.end <= original_start);
            for region in &regions[first..] {
                if region.start >= original_end {
                    break;
                }
                let start = segment.start + region.start.max(original_start) - original_start;
                let end = segment.start + region.end.min(original_end) - original_start;
                if start >= end {
                    continue;
                }
                // Literal starts carry structural meaning. Adjacent distinct
                // regions must not lose their individual environment openers.
                result.push(Region {
                    start,
                    end,
                    kind: region.kind,
                });
            }
        }
        Ok(result)
    }
}

fn append_range(ranges: &mut Vec<(usize, usize)>, start: usize, end: usize, new_owner: bool) {
    if start >= end {
        return;
    }
    if let Some(last) = ranges
        .last_mut()
        .filter(|last| !new_owner && start <= last.1)
    {
        last.1 = last.1.max(end);
    } else {
        ranges.push((start, end));
    }
}
