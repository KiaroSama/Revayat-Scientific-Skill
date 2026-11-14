//! Sliding probes materialize only their bounded token window, not the remaining suffix.
use anyhow::{Result, bail};
use std::{collections::HashSet, hash::Hash};

pub(super) fn token_windows<T: Clone + Eq + Hash>(
    words: &[T],
    counts: &[usize],
    min_letters: usize,
    max_steps: usize,
) -> Result<Vec<Vec<T>>> {
    let mut windows = Vec::new();
    let mut seen = HashSet::new();
    let (mut end, mut letters, mut steps) = (0, 0, 0);
    for start in 0..words.len() {
        while letters < min_letters && end < words.len() {
            letters += counts[end];
            end += 1;
            steps += 1;
        }
        if letters < min_letters {
            break;
        }
        steps += end - start;
        if steps > max_steps {
            bail!("text-order probe work limit exceeded; check bounded document parts");
        }
        let acc = words[start..end].to_vec();
        if seen.insert(acc.clone()) {
            windows.push(acc);
        }
        letters -= counts[start];
    }
    Ok(windows)
}

#[cfg(test)]
mod tests {
    use super::token_windows;
    use std::{
        cell::Cell,
        hash::{Hash, Hasher},
        rc::Rc,
    };

    #[derive(Debug)]
    struct Token {
        value: usize,
        clones: Rc<Cell<usize>>,
    }
    impl Clone for Token {
        fn clone(&self) -> Self {
            self.clones.set(self.clones.get() + 1);
            Self {
                value: self.value,
                clones: self.clones.clone(),
            }
        }
    }
    impl PartialEq for Token {
        fn eq(&self, other: &Self) -> bool {
            self.value == other.value
        }
    }
    impl Eq for Token {}
    impl Hash for Token {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.value.hash(state);
        }
    }

    #[test]
    fn bounded_token_materialization_tracks_actual_clones() {
        for length in [0usize, 11, 12, 32, 256, 2048] {
            let clones = Rc::new(Cell::new(0));
            let words: Vec<_> = (0..length)
                .map(|value| Token {
                    value,
                    clones: clones.clone(),
                })
                .collect();
            // Borrowing even an open-ended Rust suffix does not clone its tokens.
            let borrowed = &words[length / 2..];
            assert_eq!(borrowed.len(), length - length / 2);
            assert_eq!(clones.get(), 0);
            let windows = length.saturating_sub(11);
            let work = length + 12 * windows;
            let actual = token_windows(&words, &vec![1; length], 12, work).unwrap();
            assert_eq!(actual.len(), windows);
            for (start, window) in actual.iter().enumerate() {
                assert_eq!(
                    window.iter().map(|token| token.value).collect::<Vec<_>>(),
                    (start..start + 12).collect::<Vec<_>>()
                );
            }
            // Count actual Clone calls from to_vec and dedup's owned key, not a parallel estimate.
            assert_eq!(clones.get(), 2 * 12 * windows);
            if windows > 0 {
                clones.set(0);
                assert!(token_windows(&words, &vec![1; length], 12, 23).is_err());
                assert_eq!(clones.get(), 0, "work refusal must precede materialization");
                assert!(token_windows(&words, &vec![1; length], 12, work - 1).is_err());
            }
        }
        assert_eq!(
            token_windows(&[1, 1, 1, 1], &[1, 1, 1, 1], 2, 20).unwrap(),
            vec![vec![1, 1]]
        );
    }
}
