//! Complete literal endpoints, indexed once before applying data-role bounds.
use std::collections::BTreeMap;

const ENVIRONMENTS: [(&str, &str); 5] = [
    ("\\begin{verbatim}", "\\end{verbatim}"),
    ("\\begin{verbatim*}", "\\end{verbatim*}"),
    ("\\begin{Verbatim}", "\\end{Verbatim}"),
    ("\\begin{lstlisting}", "\\end{lstlisting}"),
    ("\\begin{minted}", "\\end{minted}"),
];

pub(super) struct LiteralIndex {
    ends: BTreeMap<usize, usize>,
}

impl LiteralIndex {
    pub fn new(text: &str, visit: &mut impl FnMut()) -> Self {
        let mut inline = Vec::new();
        let mut nearest = BTreeMap::new();
        let mut openings: [Vec<usize>; 5] = std::array::from_fn(|_| Vec::new());
        let mut closings: [Vec<usize>; 5] = std::array::from_fn(|_| Vec::new());
        for (start, scalar) in text.char_indices() {
            visit();
            if scalar != '\\' {
                continue;
            }
            let tail = &text[start..];
            visit();
            if tail.starts_with("\\verb")
                && !tail[5..].starts_with(|c: char| c.is_ascii_alphabetic())
            {
                let offset = start + 5 + usize::from(tail[5..].starts_with('*'));
                if let Some(delimiter) = text[offset..].chars().next()
                    && !delimiter.is_whitespace()
                {
                    inline.push((start, offset, delimiter));
                    nearest.insert(delimiter, usize::MAX);
                }
            }
            for (index, (opening, closing)) in ENVIRONMENTS.iter().enumerate() {
                visit();
                if tail.starts_with(opening) {
                    openings[index].push(start);
                }
                visit();
                if tail.starts_with(closing) {
                    closings[index].push(start);
                }
            }
        }
        let mut ends = BTreeMap::new();
        let mut query = inline.len();
        let mut line_end = text.len();
        if query != 0 {
            for (position, scalar) in text.char_indices().rev() {
                visit();
                while query != 0 && inline[query - 1].1 == position {
                    visit();
                    let (start, _, delimiter) = inline[query - 1];
                    let close = nearest[&delimiter];
                    if close < line_end {
                        ends.insert(start, close + delimiter.len_utf8());
                    }
                    query -= 1;
                }
                if matches!(scalar, '\r' | '\n') {
                    line_end = position;
                }
                if let Some(next) = nearest.get_mut(&scalar) {
                    *next = position;
                }
            }
        }
        for (index, (opening, closing)) in ENVIRONMENTS.iter().enumerate() {
            for &start in &openings[index] {
                let next = closings[index].partition_point(|&position| {
                    visit();
                    position < start + opening.len()
                });
                if let Some(&close) = closings[index].get(next) {
                    ends.insert(start, close + closing.len());
                }
            }
        }
        Self { ends }
    }

    pub fn end(&self, start: usize, limit: usize) -> Option<usize> {
        self.ends.get(&start).copied().filter(|&end| end <= limit)
    }
}
