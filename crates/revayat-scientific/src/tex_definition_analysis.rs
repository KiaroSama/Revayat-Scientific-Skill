//! Analyze one original file with shared declaration data-role tracking.
use super::{Analysis, Cursor, Index, Item, ReferenceScopes, references};
use anyhow::Result;

impl Index<'_> {
    pub fn analyze(&self) -> Result<Analysis> {
        self.analyze_observed(&mut || {})
    }

    pub(super) fn analyze_observed(&self, visit: &mut impl FnMut()) -> Result<Analysis> {
        let mut cursor = Cursor {
            token: 0,
            offset: 0,
            candidate: 0,
            blocked: false,
            pending_header: false,
        };
        let mut result = Analysis {
            ranges: Vec::new(),
            pending: None,
            regions: Vec::new(),
            literal_candidates: Vec::new(),
        };
        let mut collected_until = 0;
        let mut scopes = ReferenceScopes::default();
        while let Some(item) = self.next_observed(&mut cursor, collected_until, visit)? {
            match item {
                Item::Definition {
                    start,
                    end,
                    references,
                } => {
                    result.ranges.push((start, end));
                    collected_until = end;
                    scopes.select(references);
                }
                Item::Pending(pending) => {
                    result.pending = Some(pending);
                    collected_until = self.text.len();
                    scopes.pending(self.text.len());
                }
                Item::Ignored(region) => result.regions.push(region),
                Item::Token {
                    start,
                    references: nested,
                    ..
                } => {
                    if let Some(limit) = scopes.observe_observed(start, nested, None, visit)
                        && references::literal_start_observed(self.text, start, visit)
                    {
                        result.literal_candidates.push((start, limit));
                    }
                }
            }
        }
        Ok(result)
    }
}
