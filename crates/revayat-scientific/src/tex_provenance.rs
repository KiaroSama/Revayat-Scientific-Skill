//! Project immutable per-visit definition ownership onto an expanded closure.
use super::{Region, SourceClosure, definitions, plain_tex_with_ranges};
use anyhow::Result;
use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::Arc;

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
        if self.segments.is_empty() {
            return Ok(definitions::Index::new(&self.text).analyze()?.ranges);
        }
        let mut result = Vec::new();
        let mut defaults: BTreeMap<_, (Vec<(usize, usize)>, bool)> = BTreeMap::new();
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
                append_range(&mut result, segment.start, output_end);
                continue;
            }
            // Public Snapshot::new remains usable by manually assembled
            // closures. Parse each such immutable snapshot only once here.
            let (ranges, definition_eof): (&[(usize, usize)], bool) =
                match &segment.snapshot.definition_ranges {
                    Some(ranges) => (ranges, segment.snapshot.definition_eof),
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
                                entry.insert((analysis.ranges, eof))
                            }
                        };
                        (&value.0, value.1)
                    }
                };
            if definition_eof && segment.original_offset >= segment.snapshot.text.len() {
                append_range(&mut result, segment.start, output_end);
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
                append_range(
                    &mut result,
                    segment.start + start.max(original_start) - original_start,
                    segment.start + end.min(original_end) - original_start,
                );
            }
        }
        Ok(result)
    }

    /// Extract text using the original definition ownership of each file visit.
    pub fn plain_text(&self) -> Result<String> {
        plain_tex_with_ranges(
            &self.text,
            &self.definition_ranges()?,
            &self.lexical_regions()?,
        )
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

fn append_range(ranges: &mut Vec<(usize, usize)>, start: usize, end: usize) {
    if start >= end {
        return;
    }
    if let Some(last) = ranges.last_mut().filter(|last| start <= last.1) {
        last.1 = last.1.max(end);
    } else {
        ranges.push((start, end));
    }
}
