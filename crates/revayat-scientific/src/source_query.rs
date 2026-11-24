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

pub(crate) struct DelimiterIndex {
    start: usize,
    ends: Vec<u32>,
}

impl DelimiterIndex {
    pub fn new(text: &str, start: usize) -> Self {
        Self::from_reader(start..text.len(), |position| text.as_bytes()[position])
    }

    fn from_reader(positions: std::ops::Range<usize>, mut read: impl FnMut(usize) -> u8) -> Self {
        let start = positions.start;
        let mut ends = vec![0; positions.len()];
        let (mut brackets, mut braces) = (Vec::new(), Vec::new());
        // Square brackets retain raw pairing; braces honor TeX escapes.
        let mut escaped = false;
        for position in positions {
            let byte = read(position);
            let open = match byte {
                b'[' => {
                    brackets.push(position);
                    None
                }
                b']' => brackets.pop(),
                b'{' if !escaped => {
                    braces.push(position);
                    None
                }
                b'}' if !escaped => braces.pop(),
                _ => None,
            };
            if let Some(open) = open {
                ends[open - start] = u32::try_from(position + 1).expect("bounded TeX byte offset");
            }
            escaped = byte == b'\\' && !escaped;
        }
        Self { start, ends }
    }

    pub fn end(&self, open: usize) -> Option<usize> {
        let end = *self.ends.get(open.checked_sub(self.start)?)?;
        (end != 0).then_some(end as usize)
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
            let index = DelimiterIndex::new(text, 0);
            for (start, end) in expected {
                assert_eq!(index.end(start), end, "{text:?}/{start}");
            }
            assert_eq!(index.end(text.len()), None);
        }
        let text = "[before] [inside] [after]";
        let start = text.find("[inside]").unwrap();
        let end = start + "[inside]".len();
        let index = DelimiterIndex::new(&text[..end], start);
        assert_eq!(index.end(start), Some(end));
        assert_eq!(index.end(0), None);
        assert_eq!(index.end(text.find("[after]").unwrap()), None);
        assert_eq!(DelimiterIndex::new("[x", 0).end(0), None);
    }

    #[test]
    fn brace_pairs_skip_escaped_braces_and_stop_at_the_document_bound() {
        let text = r"{\} {x} \\} {past}";
        let end = text.find("past").unwrap();
        let index = DelimiterIndex::new(&text[..end], 0);
        let nested = text.find("{x}").unwrap();
        assert_eq!(index.end(0), Some(text.find(" {past}").unwrap()));
        assert_eq!(index.end(nested), Some(nested + "{x}".len()));
        assert_eq!(index.end(end - 1), None);
    }

    #[test]
    fn delimiter_index_reads_each_body_byte_once() {
        for (open, close) in [("[", "]"), ("{", "}")] {
            for length in [0, 1, 128, 4096, 100_000] {
                for complete in [false, true] {
                    let mut text = open.repeat(length);
                    if complete {
                        text.push_str(&close.repeat(length));
                    }
                    let mut reads = 0;
                    let index = DelimiterIndex::from_reader(0..text.len(), |position| {
                        assert_eq!(position, reads);
                        reads += 1;
                        text.as_bytes()[position]
                    });
                    assert_eq!(reads, text.len());
                    for start in 0..length {
                        assert_eq!(index.end(start), complete.then_some(2 * length - start));
                    }
                }
            }
        }
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
