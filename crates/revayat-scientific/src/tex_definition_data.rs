//! A literal-aware consumer cursor separate from raw declaration collection.
use super::{Cursor, Index, Item, ReferenceScopes, References, RegionKind, literals, references};
use anyhow::Result;

pub(crate) struct DataInput {
    pub start: usize,
    pub argument_start: usize,
    pub limit: usize,
    pub name: &'static str,
}

#[derive(Default)]
pub(crate) struct DataView {
    pub literal_spans: Vec<(usize, usize)>,
    pub includes: Vec<DataInput>,
}

impl Index<'_> {
    pub fn data_view(
        &self,
        start: usize,
        end: usize,
        references: Option<References>,
    ) -> Result<DataView> {
        self.data_view_observed(start, end, references, &mut || {})
    }

    pub(super) fn data_view_observed(
        &self,
        start: usize,
        end: usize,
        references: Option<References>,
        visit: &mut impl FnMut(),
    ) -> Result<DataView> {
        let mut cursor = Cursor {
            token: 0,
            offset: 0,
            candidate: 0,
            blocked: false,
            pending_header: false,
        };
        self.advance_observed(&mut cursor, start, visit);
        // The consumer can jump over a literal containing a raw percent sign.
        // Record raw comments independently so resuming after that literal
        // cannot reactivate commands before the original physical line ends.
        let mut raw = Cursor {
            token: cursor.token,
            offset: cursor.offset,
            candidate: cursor.candidate,
            blocked: false,
            pending_header: false,
        };
        let mut comments = Vec::new();
        while raw.offset < end {
            let Some(item) = self.next_observed(&mut raw, self.text.len(), visit)? else {
                break;
            };
            if let Item::Ignored(region) = item
                && region.kind == RegionKind::Comment
            {
                comments.push((region.start, region.end));
            }
        }
        let mut comment = 0;
        let mut scopes = ReferenceScopes::default();
        let fallback = if let Some(references) = references {
            scopes.select(references);
            None
        } else {
            Some(end)
        };
        let mut result = DataView::default();
        // Raw bounds were established separately. This cursor may restart at
        // any scalar entry after a literal without changing that collection.
        while let Some(item) = self.next_observed(&mut cursor, self.text.len(), visit)? {
            let Item::Token {
                start: position,
                end: token_end,
                references: nested,
            } = item
            else {
                continue;
            };
            if position >= end {
                break;
            }
            while comments.get(comment).is_some_and(|&(_, end)| {
                visit();
                end <= position
            }) {
                comment += 1;
            }
            if let Some(&(start, end)) = comments.get(comment)
                && start <= position
            {
                self.advance_observed(&mut cursor, end, visit);
                continue;
            }
            let Some(limit) = scopes.observe_observed(position, nested, fallback, visit) else {
                continue;
            };
            if references::literal_start_observed(self.text, position, visit) {
                let literals = self
                    .literal_index
                    .get_or_init(|| literals::LiteralIndex::new(self.text, visit));
                visit();
                if let Some(literal_end) = literals.end(position, limit.min(end)) {
                    result.literal_spans.push((position, literal_end));
                    self.advance_observed(&mut cursor, literal_end, visit);
                    continue;
                }
            }
            let Some(command) = self.text[position..token_end].strip_prefix('\\') else {
                continue;
            };
            let length = command.bytes().take_while(u8::is_ascii_alphabetic).count();
            let name = match &command[..length] {
                "input" => "input",
                "include" => "include",
                "includeonly" => "includeonly",
                _ => continue,
            };
            result.includes.push(DataInput {
                start: position,
                argument_start: position + 1 + length,
                limit: limit.min(end),
                name,
            });
        }
        Ok(result)
    }
}
