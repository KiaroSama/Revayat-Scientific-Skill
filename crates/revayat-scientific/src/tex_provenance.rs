//! Project immutable per-visit definition ownership onto an expanded closure.
use super::{SourceClosure, definitions, masked_tex, plain_tex_with_ranges};
use anyhow::Result;
use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::Arc;

impl SourceClosure {
    pub(crate) fn definition_ranges(&self) -> Result<Vec<(usize, usize)>> {
        if self.segments.is_empty() {
            return Ok(definitions::ranges(&masked_tex(&self.text)?));
        }
        let mut result = Vec::new();
        let mut defaults: BTreeMap<_, Vec<(usize, usize)>> = BTreeMap::new();
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
            let ranges: &[(usize, usize)] = match &segment.snapshot.definition_ranges {
                Some(ranges) => ranges,
                None => match defaults.entry(Arc::as_ptr(&segment.snapshot)) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        entry.insert(definitions::ranges(&masked_tex(&segment.snapshot.text)?))
                    }
                },
            };
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
        plain_tex_with_ranges(&self.text, &self.definition_ranges()?)
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
