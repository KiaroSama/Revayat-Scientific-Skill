//! Bounded static HTML source model. Offsets are UTF-8 byte offsets.
//!
//! The supported tree rules deliberately refuse HTML5 repairs which can change
//! inherited language, identity or hidden state. No content is executed.
use crate::source::Isolate;
use anyhow::{Result, bail};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(crate) fn member(set: &str, value: &str) -> bool {
    set.split_ascii_whitespace().any(|x| x == value)
}
pub(crate) const VOID: &str =
    "area base br col embed hr img input link meta param source track wbr";
const INERT: &str = "script style head title pre code kbd samp math";
const TEXT_EXCLUDED: &str = "head title script style";
const BREAKS: &str = "address article aside blockquote br caption dd div dl dt fieldset figcaption figure footer form h1 h2 h3 h4 h5 h6 header hr li main nav ol option p pre section table tbody td textarea tfoot th thead tr ul xmp";
const RCDATA: &str = "textarea title";
const RAWTEXT: &str = "script style xmp iframe noembed noframes";
const FOREIGN_BREAKOUT: &str = "b big blockquote body br center code dd div dl dt em embed h1 h2 h3 h4 h5 h6 head hr i img li listing menu meta nobr ol p pre ruby s small span strong strike sub sup table tt u ul var";
const MAX_ELEMENTS: usize = 100_000;
const MAX_DEPTH: usize = 512;

#[derive(Clone, Debug)]
pub struct HtmlNode {
    pub tag: String,
    pub namespace: String,
    pub attrs: BTreeMap<String, String>,
    pub start: usize,
    pub content: usize,
    pub content_end: usize,
    pub end: usize,
    pub language: String,
    pub isolate: bool,
    pub identity: bool,
    pub protected: bool,
    pub text_excluded: bool,
}
impl HtmlNode {
    pub fn attr(&self, name: &str) -> &str {
        self.attrs.get(name).map_or("", String::as_str)
    }
}
#[derive(Clone, Debug)]
struct Entity {
    raw_start: usize,
    raw_end: usize,
    decoded_start: usize,
    decoded_end: usize,
    value: String,
}
#[derive(Clone, Debug)]
pub struct ParsedHtml {
    pub raw: String,
    pub text: String,
    pub nodes: Vec<HtmlNode>,
    pub comments: Vec<(usize, usize)>,
    waiver_comments: Vec<(usize, usize)>,
    pub protected: Vec<(usize, usize)>,
    pub identity: Vec<(usize, usize)>,
    pub literals: Vec<(usize, usize)>,
    pub isolates: Vec<Isolate>,
    pub(crate) stack: Vec<usize>,
    entities: Vec<Entity>,
    markup: Vec<(usize, usize)>,
    text_tokens: Vec<(usize, usize)>,
    lint_tokens: Vec<(usize, usize)>,
}
impl ParsedHtml {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > 16 * 1024 * 1024 {
            bail!("source exceeds 16 MiB");
        }
        let mut p = Self {
            raw: text.into(),
            text: String::new(),
            nodes: Vec::new(),
            comments: Vec::new(),
            waiver_comments: Vec::new(),
            protected: Vec::new(),
            identity: Vec::new(),
            literals: Vec::new(),
            isolates: Vec::new(),
            stack: Vec::new(),
            entities: Vec::new(),
            markup: Vec::new(),
            text_tokens: Vec::new(),
            lint_tokens: Vec::new(),
        };
        p.tokenize()?;
        while let Some(index) = p.stack.pop() {
            p.finish(index, text.len(), text.len());
        }
        let mut cursor = 0;
        for entity in &mut p.entities {
            p.text.push_str(&text[cursor..entity.raw_start]);
            entity.decoded_start = p.text.len();
            p.text.push_str(&entity.value);
            entity.decoded_end = p.text.len();
            cursor = entity.raw_end;
        }
        p.text.push_str(&text[cursor..]);
        p.comments = p.normalize_ranges(&p.comments);
        p.waiver_comments = p.normalize_ranges(&p.waiver_comments);
        p.protected = p.normalize_ranges(&p.protected);
        p.identity = p.normalize_ranges(&p.identity);
        p.literals = p.normalize_ranges(&p.literals);
        for i in 0..p.isolates.len() {
            p.isolates[i].start = p.normalized_offset(p.isolates[i].start);
            p.isolates[i].end = p.normalized_offset(p.isolates[i].end);
        }
        for i in 0..p.nodes.len() {
            p.nodes[i].start = p.normalized_offset(p.nodes[i].start);
            p.nodes[i].content = p.normalized_offset(p.nodes[i].content);
            p.nodes[i].end = p.normalized_offset(p.nodes[i].end);
            p.nodes[i].content_end = p.normalized_offset(p.nodes[i].content_end);
        }
        p.protected.sort_unstable();
        Ok(p)
    }
    fn normalize_ranges(&self, ranges: &[(usize, usize)]) -> Vec<(usize, usize)> {
        ranges
            .iter()
            .map(|&(a, b)| (self.normalized_offset(a), self.normalized_offset(b)))
            .collect()
    }
    pub fn normalized_offset(&self, offset: usize) -> usize {
        let i = self.entities.partition_point(|e| e.raw_start <= offset);
        if i == 0 {
            return offset;
        }
        let e = &self.entities[i - 1];
        if offset < e.raw_end {
            e.decoded_start
        } else {
            offset - e.raw_end + e.decoded_end
        }
    }
    pub fn original_offset(&self, offset: usize) -> usize {
        let i = self.entities.partition_point(|e| e.decoded_start <= offset);
        if i == 0 {
            return offset;
        }
        let e = &self.entities[i - 1];
        if offset < e.decoded_end {
            e.raw_start
        } else {
            offset - e.decoded_end + e.raw_end
        }
    }
    pub fn text_content(&self) -> String {
        let mut text = String::new();
        for &(a, b) in &self.text_tokens {
            if a == b {
                text.push(' ');
            } else {
                text.push_str(&self.text[self.normalized_offset(a)..self.normalized_offset(b)]);
            }
        }
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
    pub fn lint_prose(&self) -> (String, Vec<(usize, usize)>) {
        let mut text = String::new();
        let mut segments = Vec::new();
        for &(a, b) in &self.lint_tokens {
            let start = self.normalized_offset(a);
            let end = self.normalized_offset(b);
            let chunk = if a == b { "\0" } else { &self.text[start..end] };
            if !chunk.is_empty() {
                segments.push((text.len(), start));
                text.push_str(chunk);
            }
        }
        (text, segments)
    }
    pub fn image_references(&self) -> Vec<(usize, String)> {
        self.nodes
            .iter()
            .filter(|n| n.tag == "img" && !n.attr("src").is_empty())
            .map(|n| (n.start, n.attr("src").into()))
            .collect()
    }
    pub(crate) fn namespace_for(&self, tag: &str) -> String {
        let parent = self.stack.last().map(|&i| &self.nodes[i]);
        let mut ns = parent.map_or("html", |p| p.namespace.as_str());
        if let Some(p) = parent {
            if ns == "svg" && member("foreignobject desc title", &p.tag) {
                ns = "html";
            }
            if ns == "math"
                && ((member("mi mo mn ms mtext", &p.tag) && !member("mglyph malignmark", tag))
                    || (p.tag == "annotation-xml"
                        && member(
                            "text/html application/xhtml+xml",
                            &p.attr("encoding").to_ascii_lowercase(),
                        )))
            {
                ns = "html";
            }
        }
        if ns == "html" && member("svg math", tag) {
            tag.into()
        } else {
            ns.into()
        }
    }
    pub(crate) fn finish(&mut self, index: usize, content_end: usize, end: usize) {
        let n = self.nodes[index].clone();
        self.nodes[index].end = end;
        self.nodes[index].content_end = content_end;
        if member(BREAKS, &n.tag) || n.protected || n.identity {
            self.lint_tokens.push((end, end));
        }
        if member(BREAKS, &n.tag) && !n.text_excluded {
            self.text_tokens.push((end, end));
        }
        if n.namespace == "html" && member(RCDATA, &n.tag) {
            self.literals.push((n.content, content_end));
        }
        if n.protected {
            self.protected.push((n.content, content_end));
        }
        if n.isolate && !n.identity {
            let mut ignored = self.identity.clone();
            ignored.extend(
                self.markup
                    .iter()
                    .copied()
                    .filter(|&(a, b)| a < content_end && b > n.content),
            );
            ignored.sort_unstable();
            let mut body = String::new();
            let mut cursor = n.content;
            for (a, b) in ignored {
                if b <= cursor || a >= content_end {
                    continue;
                }
                body.push_str(&self.raw[cursor..a.max(cursor)]);
                body.push(' ');
                cursor = b.min(content_end);
            }
            body.push_str(&self.raw[cursor..content_end]);
            self.isolates.push(Isolate {
                start: n.start,
                end,
                body: decode(&body),
            });
        }
        if n.identity || !member("fa fa-ir en en-us en-gb", &n.language) {
            self.identity.push((n.start, end));
        }
    }
    fn markup(&mut self, start: usize, end: usize) {
        self.markup.push((start, end));
        self.protected.push((start, end));
    }
    fn record_text(&mut self, start: usize, end: usize) {
        let node = self.stack.last().map(|&i| &self.nodes[i]);
        if node.is_none_or(|n| !n.text_excluded) {
            self.text_tokens.push((start, end));
        }
        if node.is_none_or(|n| !n.protected && !n.identity) {
            self.lint_tokens.push((start, end));
        } else {
            self.lint_tokens.push((start, start));
        }
    }
    fn data(&mut self, start: usize, end: usize, raw_mode: Option<&str>) -> Result<()> {
        let value = self.raw[start..end].to_owned();
        if raw_mode.is_none() {
            crate::html_scopes::before_text(self, &value, start)?;
        }
        self.record_text(start, end);
        if raw_mode.is_none() || raw_mode.is_some_and(|t| member(RCDATA, t)) {
            let re = charrefs();
            for m in re.find_iter(&value) {
                let token = m.as_str();
                let decoded = decode(token);
                if decoded != token {
                    self.entities.push(Entity {
                        raw_start: start + m.start(),
                        raw_end: start + m.end(),
                        decoded_start: 0,
                        decoded_end: 0,
                        value: decoded,
                    });
                }
            }
        }
        Ok(())
    }
    fn start(
        &mut self,
        tag: String,
        attrs: BTreeMap<String, String>,
        start: usize,
        end: usize,
        slash: bool,
    ) -> Result<()> {
        if self.nodes.len() >= MAX_ELEMENTS || self.stack.len() >= MAX_DEPTH {
            bail!("HTML work budget exceeded: at most 100000 elements and 512 open ancestors");
        }
        if self.namespace_for(&tag) != "html"
            && (member(FOREIGN_BREAKOUT, &tag)
                || (tag == "font"
                    && ["color", "face", "size"]
                        .iter()
                        .any(|n| attrs.contains_key(*n))))
        {
            while !self.stack.is_empty() && self.namespace_for(&tag) != "html" {
                let i = self.stack.pop().expect("nonempty");
                self.finish(i, start, start);
            }
        }
        crate::html_scopes::before_start(self, &tag, start)?;
        let parent = self.stack.last().map(|&i| &self.nodes[i]);
        let language = attrs
            .get("lang")
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| parent.map_or("fa", |p| p.language.as_str()))
            .to_ascii_lowercase();
        let classes: BTreeSet<&str> = attrs
            .get("class")
            .map_or("", String::as_str)
            .split_whitespace()
            .collect();
        let isolate = attrs
            .get("dir")
            .is_some_and(|d| d.eq_ignore_ascii_case("ltr"))
            || ["ltr", "en", "num", "refs"]
                .iter()
                .any(|c| classes.contains(c));
        let identity = member(INERT, &tag)
            || member("cite q blockquote", &tag)
            || classes.contains("refs")
            || attrs
                .get("data-source-identity")
                .is_some_and(|s| s == "true")
            || parent.is_some_and(|p| p.identity);
        let namespace = self.namespace_for(&tag);
        if namespace == "html" && member("template plaintext", &tag) {
            bail!("HTML template/plaintext requires an explicitly reviewed static document");
        }
        let node = HtmlNode {
            namespace,
            tag,
            attrs,
            start,
            content: end,
            content_end: end,
            end,
            language: language.clone(),
            isolate,
            identity,
            text_excluded: false,
            protected: false,
        };
        let mut node = node;
        node.text_excluded = member(TEXT_EXCLUDED, &node.tag)
            || node.attrs.contains_key("hidden")
            || parent.is_some_and(|p| p.text_excluded);
        node.protected = member(INERT, &node.tag)
            || isolate
            || !member("fa fa-ir", &language)
            || node.attrs.contains_key("hidden")
            || parent.is_some_and(|p| p.protected);
        if member(BREAKS, &node.tag) || node.protected || node.identity {
            self.lint_tokens.push((start, start));
        }
        if member(BREAKS, &node.tag) && !node.text_excluded {
            self.text_tokens.push((start, start));
        }
        let foreign = node.namespace != "html";
        let push = foreign || !member(VOID, &node.tag);
        let i = self.nodes.len();
        self.nodes.push(node);
        self.markup(start, end);
        if push {
            self.stack.push(i);
            if foreign && slash {
                self.stack.pop();
                self.finish(i, end, end);
            }
        }
        Ok(())
    }
    fn end(&mut self, tag: &str, start: usize, end: usize) -> Result<()> {
        self.markup(start, end);
        if let Some(index) = crate::html_scopes::end_index(self, tag)? {
            if member(crate::html_scopes::FORMATTING, tag) && index + 1 != self.stack.len() {
                bail!("HTML formatting adoption requires explicitly nested markup");
            }
            crate::html_scopes::close_from(self, Some(index), start, end)?;
        }
        Ok(())
    }
    fn tokenize(&mut self) -> Result<()> {
        let mut cursor = 0;
        let comment_end = Regex::new(r"--!?>")?;
        while cursor < self.raw.len() {
            let raw_tag = self
                .stack
                .last()
                .map(|&i| &self.nodes[i])
                .filter(|n| {
                    n.namespace == "html" && (member(RAWTEXT, &n.tag) || member(RCDATA, &n.tag))
                })
                .map(|n| n.tag.clone());
            if let Some(tag) = raw_tag {
                let re = Regex::new(&format!(r"(?i)</{}[\t\n\r\x0c />]", regex::escape(&tag)))?;
                let found = re.find(&self.raw[cursor..]).map(|m| cursor + m.start());
                let Some(start) = found else {
                    bail!("unterminated HTML raw-text or RCDATA element");
                };
                self.data(cursor, start, Some(&tag))?;
                let end = tag_end(&self.raw, start + 2 + tag.len()).ok_or_else(|| {
                    anyhow::anyhow!("unterminated HTML raw-text or RCDATA element")
                })?;
                self.end(&tag, start, end)?;
                cursor = end;
                continue;
            }
            if self.raw.as_bytes()[cursor] != b'<' {
                let end = self.raw[cursor..]
                    .find('<')
                    .map_or(self.raw.len(), |x| cursor + x);
                self.data(cursor, end, None)?;
                cursor = end;
                continue;
            }
            if self.raw[cursor..].starts_with("<!--") {
                let rest = &self.raw[cursor + 4..];
                let width = if rest.starts_with('>') {
                    Some(1)
                } else if rest.starts_with("->") {
                    Some(2)
                } else {
                    comment_end.find(rest).map(|m| m.end())
                };
                let end = width.map_or(self.raw.len(), |n| cursor + 4 + n);
                self.comments.push((cursor, end));
                if self
                    .stack
                    .last()
                    .is_none_or(|&i| !self.nodes[i].protected && !self.nodes[i].identity)
                {
                    self.waiver_comments.push((cursor, end));
                }
                self.markup(cursor, end);
                cursor = end;
                continue;
            }
            if self.raw[cursor..].starts_with("<!") || self.raw[cursor..].starts_with("<?") {
                let end = self.raw[cursor..]
                    .find('>')
                    .map_or(self.raw.len(), |n| cursor + n + 1);
                self.markup(cursor, end);
                cursor = end;
                continue;
            }
            let ending = self.raw[cursor..].starts_with("</");
            let start = cursor + if ending { 2 } else { 1 };
            if start >= self.raw.len() || !self.raw.as_bytes()[start].is_ascii_alphabetic() {
                let end = cursor + 1;
                self.data(cursor, end, None)?;
                cursor = end;
                continue;
            }
            let stop = self.raw[start..]
                .find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
                .map_or(self.raw.len(), |n| start + n);
            let tag = self.raw[start..stop].to_ascii_lowercase();
            let Some(end) = tag_end(&self.raw, stop) else {
                self.data(cursor, self.raw.len(), None)?;
                break;
            };
            if ending {
                self.end(&tag, cursor, end)?;
            } else {
                let (attrs, slash) = parse_attrs(&self.raw[stop..end - 1]);
                self.start(tag, attrs, cursor, end, slash)?;
            }
            cursor = end;
        }
        Ok(())
    }
}
/// HTML end-tag attributes allow quotes only at the start of a value.
fn tag_end(text: &str, start: usize) -> Option<usize> {
    let mut state = 0u8;
    let mut quote = 0u8;
    for (i, b) in text.as_bytes().iter().copied().enumerate().skip(start) {
        if quote != 0 {
            if b == quote {
                quote = 0;
                state = 4;
            }
            continue;
        }
        if b == b'>' {
            return Some(i + 1);
        }
        if state == 2 {
            if b.is_ascii_whitespace() {
                continue;
            }
            if b == b'\'' || b == b'"' {
                quote = b;
            }
            state = 3;
        } else if state == 3 {
            if b.is_ascii_whitespace() {
                state = 0;
            }
        } else if b == b'=' && (state == 1 || state == 5) {
            state = 2;
        } else if b.is_ascii_whitespace() {
            state = if state == 1 { 5 } else { 0 };
        } else if b == b'/' {
            state = 0;
        } else {
            state = 1;
        }
    }
    None
}
fn parse_attrs(raw: &str) -> (BTreeMap<String, String>, bool) {
    let mut attrs = BTreeMap::new();
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'/' {
            i += 1;
            if i == bytes.len() {
                return (attrs, true);
            }
            continue;
        }
        let start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'/'
        {
            i += 1;
        }
        if start == i {
            break;
        }
        let name = raw[start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'\'' || bytes[i] == b'"') {
                let quote = bytes[i];
                i += 1;
                let v = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                value = decode(&raw[v..i]);
                if i < bytes.len() {
                    i += 1;
                }
            } else {
                let v = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                value = decode(&raw[v..i]);
            }
        }
        attrs.entry(name).or_insert(value);
    }
    (attrs, false)
}
fn charrefs() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"&(?:#[xX][0-9A-Fa-f]+;?|#[0-9]+;?|[A-Za-z][A-Za-z0-9]{0,31};?)")
            .expect("character references")
    })
}
/// Decode exactly one HTML character-reference layer, retaining full two-scalar entities.
pub fn decode(value: &str) -> String {
    charrefs()
        .replace_all(value, |capture: &regex::Captures<'_>| {
            let token = &capture[0];
            let name = &token[1..];
            if let Some(number) = name.strip_prefix('#') {
                let number = number.trim_end_matches(';');
                let n = if let Some(hex) = number
                    .strip_prefix('x')
                    .or_else(|| number.strip_prefix('X'))
                {
                    u32::from_str_radix(hex, 16)
                } else {
                    number.parse()
                }
                .unwrap_or(u32::MAX);
                let n = match n {
                    0 => 0xfffd,
                    0x80 => 0x20ac,
                    0x82 => 0x201a,
                    0x83 => 0x192,
                    0x84 => 0x201e,
                    0x85 => 0x2026,
                    0x86 => 0x2020,
                    0x87 => 0x2021,
                    0x88 => 0x2c6,
                    0x89 => 0x2030,
                    0x8a => 0x160,
                    0x8b => 0x2039,
                    0x8c => 0x152,
                    0x8e => 0x17d,
                    0x91 => 0x2018,
                    0x92 => 0x2019,
                    0x93 => 0x201c,
                    0x94 => 0x201d,
                    0x95 => 0x2022,
                    0x96 => 0x2013,
                    0x97 => 0x2014,
                    0x98 => 0x2dc,
                    0x99 => 0x2122,
                    0x9a => 0x161,
                    0x9b => 0x203a,
                    0x9c => 0x153,
                    0x9e => 0x17e,
                    0x9f => 0x178,
                    n => n,
                };
                if n > 0x10ffff || (0xd800..=0xdfff).contains(&n) {
                    return "\u{fffd}".to_owned();
                }
                if matches!(n,1..=8|11|14..=31|0x7f..=0x9f|0xfdd0..=0xfdef)
                    || n & 0xffff == 0xfffe
                    || n & 0xffff == 0xffff
                {
                    return String::new();
                }
                return char::from_u32(n).unwrap_or('\u{fffd}').to_string();
            }
            for length in (1..=name.len()).rev() {
                if let Some(&(a, b)) = markup5ever::data::NAMED_ENTITIES.get(&name[..length])
                    && a != 0
                {
                    let mut s = char::from_u32(a).expect("HTML entity scalar").to_string();
                    if b != 0 {
                        s.push(char::from_u32(b).expect("HTML entity scalar"));
                    }
                    s.push_str(&name[length..]);
                    return s;
                }
            }
            token.to_owned()
        })
        .into_owned()
}

#[derive(Clone, Debug)]
pub struct HtmlSource {
    pub path: PathBuf,
    pub html: ParsedHtml,
    waivers: BTreeMap<usize, BTreeSet<String>>,
}
impl HtmlSource {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = crate::resource::bounded_read(path, 16 * 1024 * 1024)?;
        Self::from_text(path, std::str::from_utf8(&bytes)?)
    }
    pub fn from_text(path: &Path, text: &str) -> Result<Self> {
        let html = ParsedHtml::parse(text)?;
        let mut waivers: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
        let re = Regex::new(r"fa-lint:\s*allow\s+([\w-]+)")?;
        for &(a, b) in &html.waiver_comments {
            for m in re.captures_iter(&html.text[a..b]) {
                let line = 1 + html.raw
                    [..html.original_offset(a + m.get(0).expect("match").start())]
                    .bytes()
                    .filter(|&c| c == b'\n')
                    .count();
                waivers.entry(line).or_default().insert(m[1].into());
            }
        }
        Ok(Self {
            path: path.to_owned(),
            html,
            waivers,
        })
    }
    pub fn line_of(&self, pos: usize) -> usize {
        1 + self.html.raw[..self.html.original_offset(pos).min(self.html.raw.len())]
            .bytes()
            .filter(|&c| c == b'\n')
            .count()
    }
    pub fn location(&self, pos: usize) -> (PathBuf, usize) {
        (self.path.clone(), self.line_of(pos))
    }
    pub fn is_protected(&self, pos: usize) -> bool {
        self.html
            .protected
            .iter()
            .any(|&(a, b)| a <= pos && pos < b)
    }
    pub fn inert(&self, pos: usize) -> bool {
        self.html
            .comments
            .iter()
            .chain(&self.html.literals)
            .any(|&(a, b)| a <= pos && pos < b)
    }
    pub fn suppressed(&self, pos: usize, check: &str) -> bool {
        let line = self.line_of(pos);
        [line, line.saturating_sub(1)].iter().any(|l| {
            self.waivers
                .get(l)
                .is_some_and(|s| s.contains(check) || s.contains("all"))
        })
    }
}
