//! Literal-reference domains within an unexpanded declaration.

#[derive(Clone, Copy, Default)]
pub(crate) struct References {
    pub end: usize,
    pub(super) default: Option<(usize, usize)>,
    pub(super) body: Option<(usize, usize)>,
}

impl References {
    pub fn limit(&self, offset: usize) -> Option<usize> {
        [self.default, self.body]
            .into_iter()
            .flatten()
            .find_map(|(start, end)| {
                (start <= offset && offset < end && offset < self.end).then_some(end.min(self.end))
            })
    }
}

#[derive(Default)]
pub(crate) struct ReferenceScopes {
    scopes: Vec<References>,
}

impl ReferenceScopes {
    pub fn select(&mut self, references: References) {
        self.scopes.clear();
        self.scopes.push(references);
    }

    pub fn pending(&mut self, end: usize) {
        self.select(References {
            end,
            ..References::default()
        });
    }

    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    pub fn observe(
        &mut self,
        offset: usize,
        nested: Option<References>,
        fallback: Option<usize>,
    ) -> Option<usize> {
        self.observe_observed(offset, nested, fallback, &mut || {})
    }

    pub(super) fn observe_observed(
        &mut self,
        offset: usize,
        nested: Option<References>,
        fallback: Option<usize>,
        visit: &mut impl FnMut(),
    ) -> Option<usize> {
        while self.scopes.last().is_some_and(|scope| {
            visit();
            offset >= scope.end
        }) {
            self.scopes.pop();
        }
        visit();
        let limit = self
            .scopes
            .last()
            .map_or(fallback, |scope| scope.limit(offset));
        if let Some(mut references) = nested
            && let Some(limit) = limit
            && references.end > offset
        {
            references.end = references.end.min(limit);
            self.scopes.push(references);
        }
        limit
    }
}

pub(super) fn literal_start_observed(text: &str, start: usize, visit: &mut impl FnMut()) -> bool {
    let tail = &text[start..];
    visit();
    if tail.starts_with("\\verb") && !tail[5..].starts_with(|c: char| c.is_ascii_alphabetic()) {
        return true;
    }
    for opening in [
        "\\begin{verbatim}",
        "\\begin{verbatim*}",
        "\\begin{Verbatim}",
        "\\begin{lstlisting}",
        "\\begin{minted}",
    ] {
        visit();
        if tail.starts_with(opening) {
            return true;
        }
    }
    false
}
