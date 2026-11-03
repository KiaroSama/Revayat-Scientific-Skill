//! Located immutable source model shared by lint, inventory and verification.
use crate::tex::{
    RegionKind, SourceClosure, balanced_argument, document_extent, ignored_regions, live_tex,
    source_closure,
};
use anyhow::Result;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Isolate {
    pub start: usize,
    pub end: usize,
    pub body: String,
}

#[derive(Debug)]
pub struct TexSource {
    pub path: PathBuf,
    pub closure: SourceClosure,
    pub live: String,
    pub structural: String,
    pub comments: Vec<(usize, usize)>,
    pub literals: Vec<(usize, usize)>,
    pub isolates: Vec<Isolate>,
    pub identity: Vec<(usize, usize)>,
    pub protected: Vec<(usize, usize)>,
    pub direction_scopes: BTreeMap<String, Vec<(usize, usize)>>,
    pub preamble_end: usize,
    pub body_end: usize,
    waivers: BTreeMap<(PathBuf, usize), BTreeSet<String>>,
}

impl TexSource {
    pub fn load(path: &Path) -> Result<Self> {
        let path = std::fs::canonicalize(path)?;
        let closure = source_closure(&path, None)?;
        let live = live_tex(&closure.text)?;
        let mut structural = live.as_bytes().to_vec();
        let (preamble_end, body_end) = document_extent(&live);
        let mut source = Self {
            path,
            closure,
            live,
            structural: String::new(),
            comments: Vec::new(),
            literals: Vec::new(),
            isolates: Vec::new(),
            identity: Vec::new(),
            protected: Vec::new(),
            direction_scopes: ["latin", "LTR", "LR"]
                .map(|s| (s.to_owned(), Vec::new()))
                .into(),
            preamble_end,
            body_end,
            waivers: BTreeMap::new(),
        };
        for region in ignored_regions(source.text())? {
            source.protected.push((region.start, region.end));
            match region.kind {
                RegionKind::Comment => source.comments.push((region.start, region.end)),
                RegionKind::Literal => {
                    source.literals.push((region.start, region.end));
                    if source.text()[region.start..].starts_with("\\begin{") {
                        let end =
                            region.start + source.text()[region.start..].find('}').unwrap() + 1;
                        structural[region.start..end]
                            .copy_from_slice(&source.text().as_bytes()[region.start..end]);
                    }
                }
            }
        }
        source.structural =
            String::from_utf8(structural).expect("ASCII literal opener replacement");
        let mut stack: Vec<(String, usize)> = Vec::new();
        for cap in Regex::new(r"\\(begin|end)\{([^{}]+)\}")?.captures_iter(&source.live) {
            let full = cap.get(0).unwrap();
            if &cap[1] == "begin" {
                stack.push((cap[2].to_owned(), full.end()));
            } else if stack.last().is_some_and(|(name, _)| name == &cap[2]) {
                let (name, start) = stack.pop().unwrap();
                if let Some(scopes) = source.direction_scopes.get_mut(&name) {
                    scopes.push((start, full.start()));
                }
            }
        }
        for cap in Regex::new(r"\\([A-Za-z]+)\s*\{")?.captures_iter(&source.live) {
            if &cap[1] == "LR" {
                let open = cap.get(0).unwrap().end() - 1;
                if let Ok(end) = balanced_argument(&source.live, open) {
                    source
                        .direction_scopes
                        .get_mut("LR")
                        .unwrap()
                        .push((open + 1, end - 1));
                }
            }
        }
        source
            .protected
            .extend([(0, preamble_end), (body_end, source.text().len())]);
        for env in [
            "verbatim",
            "Verbatim",
            "lstlisting",
            "latin",
            "equation",
            "equation*",
            "align",
            "align*",
            "minted",
        ] {
            let pattern = format!(
                "(?s){}.*?{}",
                regex::escape(&format!("\\begin{{{env}}}")),
                regex::escape(&format!("\\end{{{env}}}"))
            );
            for item in Regex::new(&pattern)?.find_iter(&source.live) {
                source.protected.push((item.start(), item.end()));
                if env == "latin" {
                    source.identity.push((item.start(), item.end()));
                }
            }
        }
        source.protected.extend(math_regions(&source.live));
        let arg_only = [
            "begin",
            "end",
            "label",
            "ref",
            "eqref",
            "cite",
            "url",
            "href",
            "input",
            "include",
            "includegraphics",
            "bibitem",
            "bibliography",
            "usepackage",
            "documentclass",
            "settextfont",
            "setlatintextfont",
            "setmonofont",
            "setdigitfont",
            "hypersetup",
            "setlength",
            "hspace",
            "vspace",
            "rule",
            "newcommand",
            "renewcommand",
            "texttt",
            "citetitle",
            "definecolor",
            "geometry",
            "addcontentsline",
            "pdfstringdefDisableCommands",
            "IfFontExistsTF",
        ];
        for item in Regex::new(r"\\[A-Za-z@]+\*?\s*\[")?.find_iter(&source.live) {
            let start = item.end() - 1;
            let mut nesting = 0;
            for (offset, c) in source.live[start..].char_indices() {
                if c == '[' {
                    nesting += 1;
                } else if c == ']' {
                    nesting -= 1;
                    if nesting == 0 {
                        source.protected.push((start, start + offset + 1));
                        break;
                    }
                }
            }
        }
        for cap in
            Regex::new(r"\\([A-Za-z@]+)\*?\s*(?:\[[^\]]*\])?\s*\{")?.captures_iter(&source.live)
        {
            let full = cap.get(0).unwrap();
            if source.inert(full.start()) {
                continue;
            }
            let open = full.end() - 1;
            let end = balanced_argument(&source.live, open).unwrap_or(source.live.len());
            let close = if end > open && source.live.as_bytes().get(end - 1) == Some(&b'}') {
                end - 1
            } else {
                end
            };
            if ["lr", "en", "textenglish", "lasttext"].contains(&&cap[1]) {
                source.protected.push((open + 1, close));
                source.isolates.push(Isolate {
                    start: full.start(),
                    end,
                    body: source.live[open + 1..close].to_owned(),
                });
            } else if arg_only.contains(&&cap[1]) {
                source.protected.push((full.start(), end));
            } else {
                source.protected.push((full.start(), open));
            }
        }
        for item in Regex::new(r"\\[A-Za-z@]+\*?")?.find_iter(&source.live) {
            source.protected.push((item.start(), item.end()));
        }
        // Directives inside a protected identity/code/math region are data,
        // even when their comment token shares a line with later live prose.
        let waiver_comments: Vec<_> = source
            .comments
            .iter()
            .copied()
            .filter(|comment| {
                !source.protected.iter().any(|region| {
                    region != comment && region.0 <= comment.0 && comment.0 < region.1
                })
            })
            .collect();
        source.protected.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for &(start, end) in &source.protected {
            if end <= start {
                continue;
            }
            if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        source.protected = merged;
        let waiver_pattern = Regex::new(r"fa-lint:\s*allow\s+([\w-]+)")?;
        for &(start, end) in &waiver_comments {
            let mut additions = Vec::new();
            for cap in waiver_pattern.captures_iter(&source.text()[start..end]) {
                let key = source.location(start + cap.get(0).unwrap().start());
                additions.push((key, cap[1].to_owned()));
            }
            for (key, check) in additions {
                source.waivers.entry(key).or_default().insert(check);
            }
        }
        Ok(source)
    }

    pub fn text(&self) -> &str {
        &self.closure.text
    }

    pub fn location(&self, pos: usize) -> (PathBuf, usize) {
        self.closure.location(pos as isize)
    }

    pub fn is_protected(&self, pos: usize) -> bool {
        let index = self.protected.partition_point(|(start, _)| *start <= pos);
        index > 0 && pos < self.protected[index - 1].1
    }

    pub fn inert(&self, pos: usize) -> bool {
        if pos < self.preamble_end || pos >= self.body_end {
            return true;
        }
        if self
            .comments
            .iter()
            .any(|(start, end)| *start <= pos && pos < *end)
        {
            return true;
        }
        self.literals.iter().any(|(start, end)| {
            *start <= pos
                && pos < *end
                && !(pos == *start && self.text()[*start..].starts_with("\\begin{"))
        })
    }

    pub fn suppressed(&self, pos: usize, check: &str) -> bool {
        let (path, line) = self.location(pos);
        [line, line.saturating_sub(1)].into_iter().any(|line| {
            self.waivers
                .get(&(path.clone(), line))
                .is_some_and(|allowed| allowed.contains(check) || allowed.contains("all"))
        })
    }

    pub fn in_direction_scope(&self, pos: usize, names: &[&str]) -> bool {
        names.iter().any(|name| {
            self.direction_scopes.get(*name).is_some_and(|scopes| {
                scopes
                    .iter()
                    .any(|(start, end)| *start <= pos && pos < *end)
            })
        })
    }

    pub fn image_references(&self) -> Vec<(usize, String)> {
        Regex::new(r"\\includegraphics\*?\s*(?:\[[^\]]*\]\s*)?\{([^{}]+)\}")
            .unwrap()
            .captures_iter(&self.live)
            .filter(|cap| !self.inert(cap.get(0).unwrap().start()))
            .map(|cap| (cap.get(0).unwrap().start(), cap[1].trim().to_owned()))
            .collect()
    }
}

fn math_regions(text: &str) -> Vec<(usize, usize)> {
    let mut regions = Vec::new();
    let mut pos = 0;
    while pos < text.len() {
        let tail = &text[pos..];
        let matched = [("$$", "$$"), ("$", "$"), ("\\[", "\\]"), ("\\(", "\\)")]
            .into_iter()
            .find(|(open, _)| {
                tail.starts_with(open)
                    && !(open.starts_with('$') && pos > 0 && text.as_bytes()[pos - 1] == b'\\')
            });
        if let Some((open, close)) = matched {
            let begin = pos + open.len();
            let mut end = begin;
            while end < text.len() {
                if text[end..].starts_with(close)
                    && !(close.starts_with('$') && end > 0 && text.as_bytes()[end - 1] == b'\\')
                {
                    break;
                }
                end += text[end..].chars().next().unwrap().len_utf8();
            }
            if end < text.len() {
                regions.push((pos, end + close.len()));
                pos = end + close.len();
                continue;
            }
        }
        pos += tail.chars().next().unwrap().len_utf8();
    }
    regions
}
