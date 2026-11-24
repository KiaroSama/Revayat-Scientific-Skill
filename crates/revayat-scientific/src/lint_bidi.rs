//! Unicode-isolate balance over supported static prose paragraphs.
use super::Source;

const MAX_FINDINGS: usize = 64;
const MISSING_OPEN: &str =
    "Remove PDI (U+2069) or add its opening isolate in the same prose paragraph";
const MISSING_CLOSE: &str =
    "Close the LRI, RLI, or FSI isolate with PDI (U+2069) in the same prose paragraph";

struct Balance<'a> {
    source: &'a Source,
    depth: usize,
    open: Option<(usize, usize)>,
    stray: Option<usize>,
    findings: Vec<(usize, &'static str)>,
}

impl Balance<'_> {
    fn control(&mut self, pos: usize, control: char) {
        match control {
            '\u{2069}' if self.depth == 0 => {
                if self.stray.is_none() && !self.source.suppressed(pos, "bidi-isolate") {
                    self.stray = Some(pos);
                }
            }
            '\u{2069}' => {
                self.depth -= 1;
                if self.open.is_some_and(|(depth, _)| depth > self.depth) {
                    self.open = None;
                }
            }
            '\u{2066}' | '\u{2067}' | '\u{2068}' => {
                self.depth += 1;
                // The earliest unwaived opener is sufficient: if it closes,
                // every opener nested inside it has necessarily closed too.
                if self.open.is_none() && !self.source.suppressed(pos, "bidi-isolate") {
                    self.open = Some((self.depth, pos));
                }
            }
            _ => {}
        }
    }

    fn paragraph_end(&mut self) -> bool {
        for (pos, message) in [
            (self.stray.take(), MISSING_OPEN),
            (self.open.take().map(|(_, pos)| pos), MISSING_CLOSE),
        ] {
            if let Some(pos) = pos
                && self.findings.len() < MAX_FINDINGS
            {
                self.findings.push((pos, message));
            }
        }
        self.depth = 0;
        self.findings.len() == MAX_FINDINGS
    }
}

fn explicit_paragraph_break(c: char) -> bool {
    // U+2028 is a line separator, not a bidi paragraph separator. Source CR/LF
    // handling belongs to the document language's whitespace processing.
    matches!(c, '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2029}')
}

pub(super) fn findings(source: &Source) -> Vec<(usize, &'static str)> {
    let mut balance = Balance {
        source,
        depth: 0,
        open: None,
        stray: None,
        findings: Vec::new(),
    };
    match source {
        Source::Html(source) => {
            'paragraphs: for (start, end, checked, preserve_newlines) in
                source.html.bidi_prose_ranges()
            {
                if start == end {
                    if balance.paragraph_end() {
                        break;
                    }
                    continue;
                }
                for (offset, c) in source.html.text[start..end].char_indices() {
                    if explicit_paragraph_break(c)
                        || (preserve_newlines && matches!(c, '\r' | '\n'))
                    {
                        if balance.paragraph_end() {
                            break 'paragraphs;
                        }
                    } else if checked {
                        balance.control(start + offset, c);
                    }
                }
            }
        }
        Source::Tex(source) => {
            let mut paragraphs = source.bidi_paragraphs.iter().copied().peekable();
            for (pos, c) in source.text().char_indices() {
                if paragraphs.peek() == Some(&pos) {
                    paragraphs.next();
                    if balance.paragraph_end() {
                        break;
                    }
                }
                if matches!(c, '\r' | '\n') {
                    if source.closure.is_blank_line_break(pos)
                        && !source.is_protected(pos)
                        && balance.paragraph_end()
                    {
                        break;
                    }
                    continue;
                }
                if !explicit_paragraph_break(c)
                    && !matches!(c, '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}')
                {
                    continue;
                }
                if source.is_protected(pos) {
                    continue;
                }
                if explicit_paragraph_break(c) {
                    if balance.paragraph_end() {
                        break;
                    }
                } else {
                    balance.control(pos, c);
                }
            }
        }
    }
    balance.paragraph_end();
    balance.findings
}
