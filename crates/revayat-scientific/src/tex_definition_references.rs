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
