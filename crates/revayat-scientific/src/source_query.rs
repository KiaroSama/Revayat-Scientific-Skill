//! Build bounded source indexes and query precomputed positions and waivers.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

pub(crate) fn partition_index<T>(
    entries: &[T],
    mut key: impl FnMut(&T) -> usize,
    limit: usize,
) -> usize {
    entries.partition_point(|entry| key(entry) <= limit)
}
pub(crate) fn allowed(
    waivers: &BTreeMap<(PathBuf, usize), BTreeSet<String>>,
    path: &std::path::Path,
    line: usize,
    check: &str,
) -> bool {
    [line, line.saturating_sub(1)].into_iter().any(|line| {
        waivers
            .get(&(path.to_owned(), line))
            .is_some_and(|checks| checks.contains(check) || checks.contains("all"))
    })
}

pub(crate) struct BracketIndex {
    pairs: Vec<(usize, usize)>,
}

impl BracketIndex {
    pub fn new(text: &str, start: usize, end: usize) -> Self {
        let end = end.min(text.len());
        Self::from_reader(start.min(end)..end, |position| text.as_bytes()[position])
    }

    fn from_reader(positions: std::ops::Range<usize>, mut read: impl FnMut(usize) -> u8) -> Self {
        let mut pairs = Vec::new();
        let mut stack = Vec::new();
        for position in positions {
            match read(position) {
                b'[' => {
                    stack.push(pairs.len());
                    pairs.push((position, 0));
                }
                b']' => {
                    if let Some(index) = stack.pop() {
                        pairs[index].1 = position + 1;
                    }
                }
                _ => (),
            }
        }
        Self { pairs }
    }

    pub fn end(&self, start: usize) -> Option<usize> {
        self.end_with_key(start, |position| position)
    }

    fn end_with_key(&self, start: usize, mut key: impl FnMut(usize) -> usize) -> Option<usize> {
        let index = self
            .pairs
            .binary_search_by_key(&start, |&(position, _)| key(position))
            .ok()?;
        let end = self.pairs[index].1;
        (end != 0).then_some(end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_brackets_preserve_nested_offsets_and_unmatched_boundaries() {
        for (text, expected) in [
            ("", vec![]),
            ("[a[b]c]", vec![(0, Some(7)), (2, Some(5))]),
            ("][[x]", vec![(1, None), (2, Some(5))]),
            ("§[a]", vec![(2, Some(5))]),
            ("[incomplete", vec![(0, None)]),
        ] {
            let index = BracketIndex::new(text, 0, text.len());
            for (start, end) in expected {
                assert_eq!(index.end(start), end, "{text:?}/{start}");
            }
            assert_eq!(index.end(text.len()), None);
        }
        let text = "[before] [inside] [after]";
        let start = text.find("[inside]").unwrap();
        let index = BracketIndex::new(text, start, start + "[inside]".len());
        assert_eq!(index.end(start), Some(start + "[inside]".len()));
        assert_eq!(index.end(0), None);
        assert_eq!(index.end(text.find("[after]").unwrap()), None);
        assert_eq!(BracketIndex::new("[x]", 0, 2).end(0), None);
    }

    #[test]
    fn optional_bracket_scan_and_queries_have_bounded_actual_work() {
        for length in [0usize, 1, 128, 4096, 100_000] {
            for complete in [false, true] {
                let text = format!(
                    "{}{}",
                    "[".repeat(length),
                    if complete {
                        "]".repeat(length)
                    } else {
                        String::new()
                    }
                );
                let mut reads = 0;
                let index = BracketIndex::from_reader(0..text.len(), |position| {
                    assert_eq!(position, reads);
                    reads += 1;
                    text.as_bytes()[position]
                });
                assert_eq!(reads, text.len());
                let maximum = (usize::BITS - length.leading_zeros()) as usize + 1;
                for start in 0..length {
                    let mut queries = 0;
                    let actual = index.end_with_key(start, |position| {
                        queries += 1;
                        position
                    });
                    assert_eq!(actual, complete.then_some(2 * length - start));
                    assert!(queries <= maximum, "{length}/{start}: {queries}");
                }
            }
        }
        // The callbacks supply values consumed by the actual implementation.
        assert_eq!(BracketIndex::from_reader(0..3, |_| b' ').end(0), None);
        assert_eq!(
            BracketIndex::new("[]", 0, 2).end_with_key(0, |_| usize::MAX),
            None
        );
    }

    #[test]
    fn index_queries_measure_actual_projection_reads() {
        for length in [0usize, 1, 2, 3, 127, 1024, 10000] {
            let keys: Vec<_> = (0..length).map(|i| i * 3 + 1).collect();
            for limit in [0, 1, 2, 3, length, length.saturating_mul(3), usize::MAX] {
                let mut reads = Vec::new();
                let actual = partition_index(
                    &keys,
                    |key| {
                        reads.push(*key);
                        *key
                    },
                    limit,
                );
                assert_eq!(actual, keys.iter().take_while(|key| **key <= limit).count());
                let maximum = if length == 0 {
                    0
                } else {
                    (usize::BITS - length.leading_zeros()) as usize + 1
                };
                assert!(
                    reads.len() <= maximum,
                    "actual index reads={} maximum={maximum}",
                    reads.len()
                );
                assert!(reads.iter().all(|key| keys.binary_search(key).is_ok()));
                // The observed callback supplies the values used by the real query, not a parallel counter.
                assert_eq!(partition_index(&keys, |_| usize::MAX, 0), 0);
                assert_eq!(partition_index(&keys, |_| 0, 0), length);
            }
        }
        assert_eq!(partition_index(&[1, 1, 1, 3, 5], |key| *key, 1), 3);
    }

    #[test]
    fn waiver_queries_use_only_precomputed_locations() {
        let path = PathBuf::from("chapter.tex");
        let map = BTreeMap::from([
            (
                (path.clone(), 2),
                BTreeSet::from(["arabic-letters".to_owned()]),
            ),
            ((path.clone(), 7), BTreeSet::from(["all".to_owned()])),
        ]);
        for line in 0..=10 {
            assert_eq!(
                allowed(&map, &path, line, "arabic-letters"),
                [2, 3, 7, 8].contains(&line)
            );
            assert_eq!(
                allowed(&map, &path, line, "eastern-digits"),
                [7, 8].contains(&line)
            );
            assert!(!allowed(
                &map,
                &PathBuf::from("other.tex"),
                line,
                "arabic-letters"
            ));
        }
        assert!(!allowed(&BTreeMap::new(), &path, 2, "all"));
    }
}
