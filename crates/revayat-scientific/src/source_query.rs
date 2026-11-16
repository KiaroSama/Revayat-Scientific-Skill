//! Queries borrow precomputed indexes, never source text or comment collections.
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

#[cfg(test)]
mod tests {
    use super::*;

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
