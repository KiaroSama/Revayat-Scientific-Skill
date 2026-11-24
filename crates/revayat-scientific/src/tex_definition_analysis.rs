//! Analyze one original file with shared declaration data-role tracking.
use super::{Analysis, Cursor, Index, Item};
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
            literal_spans: Vec::new(),
            data_comments: Vec::new(),
        };
        let mut collected_until = 0;
        while let Some(item) = self.next_observed(&mut cursor, collected_until, visit)? {
            match item {
                Item::Definition {
                    start,
                    end,
                    references,
                } => {
                    result.ranges.push((start, end));
                    collected_until = end;
                    let data = self.data_view_observed(start, end, Some(references), visit)?;
                    result.literal_spans.extend(data.literal_spans);
                    result.data_comments.extend(data.comments);
                }
                Item::Pending(pending) => {
                    result.pending = Some(pending);
                    collected_until = self.text.len();
                }
                Item::Ignored(region) => result.regions.push(region),
                Item::Token { .. } => (),
            }
        }
        Ok(result)
    }
}
