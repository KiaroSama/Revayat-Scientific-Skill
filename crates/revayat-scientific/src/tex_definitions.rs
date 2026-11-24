//! Bounded declaration collection over original TeX tokens and lexical context.
use super::{Region, RegionKind};
use anyhow::Result;
#[path = "tex_definition_tokens.rs"]
mod lexical;
use lexical::{Kind, Token, Tokens};

#[cfg(test)]
fn ranges(masked: &str) -> Vec<(usize, usize)> {
    ranges_observed(masked, || {})
}

#[cfg(test)]
fn ranges_observed(text: &str, mut visit: impl FnMut()) -> Vec<(usize, usize)> {
    Index::new_observed(text, &mut visit)
        .analyze_observed(&mut visit)
        .expect("valid scanner fixture")
        .ranges
}

pub(crate) struct Index<'a> {
    text: &'a str,
    tokens: Tokens,
    candidates: Vec<Candidate>,
}

pub(crate) struct Analysis {
    pub ranges: Vec<(usize, usize)>,
    pub pending: Option<Pending>,
    pub regions: Vec<Region>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pending {
    pub start: usize,
    pub state: Continuation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Continuation {
    Command,
    AfterName,
    AfterFirstOption,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Completion {
    Complete(usize),
    Pending(Continuation),
    Invalid,
}

pub(crate) enum Item {
    Definition { start: usize, end: usize },
    Pending(Pending),
    Ignored(Region),
    Token { start: usize, end: usize },
}

pub(crate) struct Cursor {
    token: usize,
    offset: usize,
    candidate: usize,
    blocked: bool,
    pending_header: bool,
}

impl Cursor {
    pub fn allows_continuation(&self) -> bool {
        !self.blocked && !self.pending_header
    }
}

#[derive(Clone, Copy)]
enum End {
    Complete(usize),
    Pending(Continuation),
    Invalid { unfinished: bool },
}

#[derive(Clone, Copy)]
struct Candidate {
    token: usize,
    end: End,
}

impl<'a> Index<'a> {
    pub fn new(text: &'a str) -> Self {
        Self::new_observed(text, &mut || {})
    }

    fn new_observed(text: &'a str, visit: &mut impl FnMut()) -> Self {
        let mut index = Self {
            text,
            tokens: lexical::tokenize(text, visit),
            candidates: Vec::new(),
        };
        for pos in 0..index.tokens.values.len() {
            visit();
            if index.tokens.values[pos].kind == Kind::Definition {
                let end = index.definition_end(
                    index.tokens.values[pos].next as usize,
                    0,
                    Continuation::Command,
                    visit,
                );
                index.candidates.push(Candidate { token: pos, end });
            }
        }
        index
    }

    fn token(&self, pos: usize, visit: &mut impl FnMut()) -> Option<Token> {
        visit();
        self.tokens.values.get(pos).copied()
    }

    fn active(&self, pos: usize, visit: &mut impl FnMut()) -> Option<(usize, Token)> {
        visit();
        let pos = *self.tokens.active.get(pos)? as usize;
        self.token(pos, visit).map(|token| (pos, token))
    }

    pub fn cursor(&self, offset: usize) -> Cursor {
        let mut cursor = Cursor {
            token: 0,
            offset: 0,
            candidate: 0,
            blocked: false,
            pending_header: false,
        };
        self.advance_observed(&mut cursor, offset, &mut || {});
        cursor
    }

    pub fn advance(&self, cursor: &mut Cursor, offset: usize) {
        self.advance_observed(cursor, offset, &mut || {});
    }

    pub fn owns_eof(&self, end: usize) -> bool {
        end == self.text.len()
            && self.tokens.values.last().is_some_and(|token| {
                token.kind == Kind::Paragraph
                    && token.start == token.end
                    && token.end as usize == end
            })
    }

    fn advance_observed(&self, cursor: &mut Cursor, offset: usize, visit: &mut impl FnMut()) {
        cursor.offset = offset.min(self.text.len());
        cursor.token = self.tokens.values.partition_point(|token| {
            visit();
            (token.start as usize) < cursor.offset
        });
        cursor.candidate = self.candidates.partition_point(|candidate| {
            visit();
            candidate.token < cursor.token
        });
    }

    pub fn next(&self, cursor: &mut Cursor, collected_until: usize) -> Result<Option<Item>> {
        self.next_observed(cursor, collected_until, &mut || {})
    }

    fn next_observed(
        &self,
        cursor: &mut Cursor,
        collected_until: usize,
        visit: &mut impl FnMut(),
    ) -> Result<Option<Item>> {
        let Some(token) = self.token(cursor.token, visit) else {
            return Ok(None);
        };
        let start = cursor.offset.max(token.start as usize);
        let end = token.end as usize;
        let token_pos = cursor.token;
        cursor.token = token.next as usize;
        cursor.offset = end;
        while let Some(candidate) = self.candidates.get(cursor.candidate) {
            visit();
            if candidate.token >= token_pos {
                break;
            }
            cursor.candidate += 1;
        }
        if token.kind == Kind::Comment {
            cursor.token = token.next as usize;
            cursor.offset = self
                .tokens
                .values
                .get(cursor.token)
                .map_or(self.text.len(), |next| next.start as usize);
            return Ok(Some(Item::Ignored(Region {
                start,
                end: token.endpoint as usize,
                kind: RegionKind::Comment,
            })));
        }
        let collected = start < collected_until;
        if !collected && !cursor.pending_header {
            if token.kind == Kind::Definition
                && let Some(candidate) = self.candidates.get(cursor.candidate)
                && candidate.token == token_pos
            {
                visit();
                match candidate.end {
                    End::Complete(end) => return Ok(Some(Item::Definition { start, end })),
                    End::Pending(state) if !cursor.blocked => {
                        cursor.pending_header = true;
                        return Ok(Some(Item::Pending(Pending { start, state })));
                    }
                    End::Invalid { unfinished: true } => cursor.blocked = true,
                    _ => (),
                }
            }
            if !cursor.blocked
                && matches!(token.kind, Kind::Control | Kind::Definition)
                && let Some(region) = lexical::literal(self.text, start, visit)?
            {
                self.advance_observed(cursor, region.end, visit);
                return Ok(Some(Item::Ignored(region)));
            }
        }
        // A single-character body may end inside an ordinary text run. Keep
        // the remaining characters available to ordinary lexical discovery.
        if collected && collected_until < end {
            cursor.token = token_pos;
            cursor.offset = collected_until;
            return Ok(Some(Item::Token {
                start,
                end: collected_until,
            }));
        }
        Ok(Some(Item::Token { start, end }))
    }

    pub fn analyze(&self) -> Result<Analysis> {
        self.analyze_observed(&mut || {})
    }

    fn analyze_observed(&self, visit: &mut impl FnMut()) -> Result<Analysis> {
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
        };
        let mut collected_until = 0;
        while let Some(item) = self.next_observed(&mut cursor, collected_until, visit)? {
            match item {
                Item::Definition { start, end } => {
                    result.ranges.push((start, end));
                    collected_until = end;
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

    #[cfg(test)]
    fn local(&self) -> Analysis {
        self.analyze().expect("valid scanner fixture")
    }

    #[cfg(test)]
    fn local_observed(&self, visit: &mut impl FnMut()) -> Analysis {
        self.analyze_observed(visit).expect("valid scanner fixture")
    }

    pub fn resume(&self, offset: usize, state: Continuation) -> Completion {
        self.resume_observed(offset, state, &mut || {})
    }

    fn resume_observed(
        &self,
        offset: usize,
        state: Continuation,
        visit: &mut impl FnMut(),
    ) -> Completion {
        visit();
        if offset > self.text.len() {
            return Completion::Invalid;
        }
        let pos = self.tokens.values.partition_point(|token| {
            visit();
            (token.start as usize) < offset
        });
        match self.definition_end(pos, offset, state, visit) {
            End::Complete(end) => Completion::Complete(end),
            End::Pending(state) => Completion::Pending(state),
            End::Invalid { .. } => Completion::Invalid,
        }
    }

    fn definition_end(
        &self,
        mut pos: usize,
        mut offset: usize,
        mut state: Continuation,
        visit: &mut impl FnMut(),
    ) -> End {
        let invalid = End::Invalid { unfinished: false };
        if state == Continuation::Command {
            let Some((first_pos, first)) = self.active(pos, visit) else {
                return End::Pending(Continuation::Command);
            };
            pos = if first.kind == Kind::Star {
                first.next as usize
            } else {
                first_pos
            };
            let Some((_name_pos, name)) = self.active(pos, visit) else {
                return invalid;
            };
            match name.kind {
                Kind::OpenBrace => {
                    if name.endpoint == 0 {
                        return End::Invalid { unfinished: true };
                    }
                    let Some((_inner_pos, inner)) = self.active(name.next as usize, visit) else {
                        return invalid;
                    };
                    let Some((close_pos, _)) = self.active(inner.next as usize, visit) else {
                        return invalid;
                    };
                    if !matches!(inner.kind, Kind::Control | Kind::Definition)
                        || close_pos + 1 != name.endpoint as usize
                    {
                        return invalid;
                    }
                    pos = name.endpoint as usize;
                }
                Kind::Control | Kind::Definition => pos = name.next as usize,
                _ => return invalid,
            }
            offset = 0;
            state = Continuation::AfterName;
        }
        if state == Continuation::AfterName {
            let Some((option_pos, option)) = self.active(pos, visit) else {
                return End::Pending(Continuation::AfterName);
            };
            if option.kind == Kind::OpenOption {
                if option.endpoint == 0 {
                    return End::Invalid { unfinished: true };
                }
                pos = option.endpoint as usize;
                offset = 0;
                state = Continuation::AfterFirstOption;
            } else {
                pos = option_pos;
            }
        }
        if state == Continuation::AfterFirstOption {
            let Some((option_pos, option)) = self.active(pos, visit) else {
                return End::Pending(Continuation::AfterFirstOption);
            };
            if option.kind == Kind::OpenOption {
                if option.endpoint == 0 {
                    return End::Invalid { unfinished: true };
                }
                pos = option.endpoint as usize;
                offset = 0;
            } else {
                pos = option_pos;
            }
        }
        let Some((body_pos, body)) = self.active(pos, visit) else {
            return invalid;
        };
        match body.kind {
            Kind::OpenBrace if body.endpoint == 0 => End::Invalid { unfinished: true },
            Kind::OpenBrace => {
                let close = self.token(body.endpoint as usize - 1, visit).unwrap();
                End::Complete(close.end as usize)
            }
            Kind::CloseBrace => invalid,
            Kind::Text => {
                let start = if body_pos == pos {
                    offset.max(body.start as usize)
                } else {
                    body.start as usize
                };
                visit();
                End::Complete(start + self.text[start..].chars().next().unwrap().len_utf8())
            }
            _ => End::Complete(body.end as usize),
        }
    }
}

pub(crate) fn mask(text: &str, ranges: &[(usize, usize)]) -> String {
    let mut bytes = text.as_bytes().to_vec();
    for &(start, end) in ranges {
        for byte in &mut bytes[start..end] {
            if !matches!(byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(bytes).expect("ASCII definition replacement")
}

#[cfg(test)]
#[path = "tex_definitions_continuation_tests.rs"]
mod continuation_tests;
#[cfg(test)]
#[path = "tex_definition_work_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tex_definition_context_tests.rs"]
mod context_tests;
