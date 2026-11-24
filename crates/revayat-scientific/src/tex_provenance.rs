//! Project immutable per-visit definition ownership onto an expanded closure.
use super::{Region, SourceClosure, definitions, plain_tex_with_ranges};
use anyhow::Result;
use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::Arc;

type CachedDefinitionMetadata = (Vec<(usize, usize)>, bool, Vec<usize>);

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
        )
    }

    pub(crate) fn literal_spans(&self) -> Result<Vec<(usize, usize)>> {
        if self.segments.is_empty() {
            return Ok(definitions::Index::new(&self.text).analyze()?.literal_spans);
        }
        #[derive(Clone, Copy)]
        struct Piece {
            original_start: usize,
            original_end: usize,
            output_start: usize,
            output_end: usize,
        }
        let mut groups: Vec<Vec<Piece>> = Vec::new();
        let mut active: BTreeMap<_, usize> = BTreeMap::new();
        let mut positions = vec![None; self.segments.len()];
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
            let identity = Arc::as_ptr(&segment.snapshot);
            // Expansion has one immutable snapshot per visit. A manually
            // assembled closure may reuse an Arc for another visit; an offset
            // reset starts another ordered projection group in that case.
            let group = match active.get(&identity).copied() {
                Some(group)
                    if groups[group]
                        .last()
                        .is_some_and(|last| last.original_end <= original_start) =>
                {
                    group
                }
                _ => {
                    let group = groups.len();
                    groups.push(Vec::new());
                    active.insert(identity, group);
                    group
                }
            };
            positions[index] = Some((group, groups[group].len()));
            groups[group].push(Piece {
                original_start,
                original_end,
                output_start: segment.start,
                output_end,
            });
        }
        let mut defaults: BTreeMap<_, Vec<(usize, usize)>> = BTreeMap::new();
        let mut result = Vec::new();
        for (index, segment) in self.segments.iter().enumerate() {
            let Some((group, piece)) = positions[index] else {
                continue;
            };
            let group = &groups[group];
            let piece = group[piece];
            let spans = match &segment.snapshot.literal_spans {
                Some(spans) => spans,
                None => match defaults.entry(Arc::as_ptr(&segment.snapshot)) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => entry.insert(
                        definitions::Index::new(&segment.snapshot.text)
                            .analyze()?
                            .literal_spans,
                    ),
                },
            };
            let first = spans.partition_point(|&(start, _)| start < piece.original_start);
            for &(start, end) in &spans[first..] {
                if start >= piece.original_end {
                    break;
                }
                // Project the accepted endpoint through this original visit.
                // A literal may cross several manually supplied source pieces;
                // its ownership and endpoint must not be reparsed per piece.
                let following = group.partition_point(|part| part.original_end < end);
                let projected_end = group.get(following).map_or_else(
                    || group.last().unwrap().output_end,
                    |part| {
                        part.output_start
                            + end
                                .saturating_sub(part.original_start)
                                .min(part.output_end - part.output_start)
                    },
                );
                let projected_start = piece.output_start + start - piece.original_start;
                if projected_start < projected_end {
                    result.push((projected_start, projected_end));
                }
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
