//! Mechanical Persian document checks over the same static source used to build.
use crate::{
    html::HtmlSource,
    ledger::{self, Pair},
    resource::{bounded_read, percent_decode},
    source::{Isolate, TexSource},
    terms,
};
use anyhow::{Context, Result, bail};
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
const FA: &str = "\\u{0600}-\\u{06ff}\\u{fb50}-\\u{fdff}\\u{fe70}-\\u{feff}";
const VERBS: &str = "میشود میشوند میشد میکند میکنند میکنید میکنم میکرد میتوان میتواند میتوانند میتوانید میدهد میدهند میگیرد میگیرند میباشد میباشند میگردد میرود میآید میسازد میخواهد میگوید میداند میآورد میماند میافتد میپردازد میکنیم میدانیم نمیشود نمیشوند نمیکند نمیکنند نمیتوان نمیتواند نمیدهد نمیباشد نمیگردد نمیآید";
const HEADS: &str = "خوشه|خوشه‌های|سرویس‌های|بسته‌های|بستهٔ|مخزن|مخازن|گره‌های|نیازمندی‌های|جریان‌های|دیوارهای|بلوک|بلوک‌های";
const STOPWORDS: &str = "pt em ex cm mm bp dd cc sp true htbp htb hbp tbp here center left right linewidth textwidth columnwidth paperwidth paperheight figure table tabular longtable itemize enumerate description quote quotation flushleft flushright small footnotesize scriptsize tiny large Large LARGE huge Huge normalsize single frame framesep fontsize baselinestretch numbers none width height scale angle keepaspectratio page trim clip";
const PLURAL_EXCEPTIONS: &str = "windows kubernetes redis postgres ios macos https http tls ssl aws gcs nfs dns bios cosmos analysis thesis basis crisis physics mathematics economics news series species means always towards perhaps plus minus canvas atlas this is was has does his its as us across process access address status bus";
pub fn english_plural_stem(word: &str) -> Option<String> {
    if word.len() > 2
        && word.ends_with('s')
        && word[..word.len() - 1]
            .bytes()
            .all(|b| b.is_ascii_uppercase())
    {
        return Some(word[..word.len() - 1].into());
    }
    if word.len() < 4 || word.bytes().all(|b| !b.is_ascii_lowercase()) {
        return None;
    }
    let lower = word.to_ascii_lowercase();
    if crate::html::member(PLURAL_EXCEPTIONS, &lower) {
        return None;
    }
    if lower.ends_with("ies") && word.len() > 4 {
        return Some(format!(
            "{}{}",
            &word[..word.len() - 3],
            if word.as_bytes()[word.len() - 4].is_ascii_uppercase() {
                "Y"
            } else {
                "y"
            }
        ));
    }
    if lower.ends_with("es")
        && word.len() > 4
        && (lower.ends_with("ches")
            || lower.ends_with("shes")
            || b"sxz".contains(&lower.as_bytes()[lower.len() - 3]))
    {
        return Some(word[..word.len() - 2].into());
    }
    if lower.ends_with('s')
        && !lower.ends_with("ss")
        && !lower.ends_with("us")
        && !lower.ends_with("is")
        && !lower.ends_with("os")
        && !lower.ends_with("as")
    {
        return Some(word[..word.len() - 1].into());
    }
    None
}
#[derive(Debug)]
pub enum Source {
    Tex(TexSource),
    Html(HtmlSource),
}
impl Source {
    pub fn load(path: &Path) -> Result<Self> {
        match path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "tex" => Ok(Self::Tex(TexSource::load(path)?)),
            "html" | "htm" => Ok(Self::Html(HtmlSource::load(path)?)),
            _ => bail!("expected an existing .tex or .html source"),
        }
    }
    pub fn path(&self) -> &Path {
        match self {
            Self::Tex(s) => &s.path,
            Self::Html(s) => &s.path,
        }
    }
    pub fn text(&self) -> &str {
        match self {
            Self::Tex(s) => s.text(),
            Self::Html(s) => &s.html.text,
        }
    }
    pub fn location(&self, pos: usize) -> (PathBuf, usize) {
        match self {
            Self::Tex(s) => s.location(pos),
            Self::Html(s) => s.location(pos),
        }
    }
    pub fn is_protected(&self, pos: usize) -> bool {
        match self {
            Self::Tex(s) => s.is_protected(pos),
            Self::Html(s) => s.is_protected(pos),
        }
    }
    pub fn inert(&self, pos: usize) -> bool {
        match self {
            Self::Tex(s) => s.inert(pos),
            Self::Html(s) => s.inert(pos),
        }
    }
    pub fn suppressed(&self, pos: usize, check: &str) -> bool {
        match self {
            Self::Tex(s) => s.suppressed(pos, check),
            Self::Html(s) => s.suppressed(pos, check),
        }
    }
    pub fn isolates(&self) -> &[Isolate] {
        match self {
            Self::Tex(s) => &s.isolates,
            Self::Html(s) => &s.html.isolates,
        }
    }
    pub fn identity(&self) -> &[(usize, usize)] {
        match self {
            Self::Tex(s) => &s.identity,
            Self::Html(s) => &s.html.identity,
        }
    }
    pub fn image_references(&self) -> Vec<(usize, String)> {
        match self {
            Self::Tex(s) => s.image_references(),
            Self::Html(s) => s.html.image_references(),
        }
    }
    fn structural(&self) -> &str {
        match self {
            Self::Tex(s) => &s.structural,
            Self::Html(s) => &s.html.text,
        }
    }
    fn prose(&self) -> (String, Vec<(usize, usize)>) {
        match self {
            Self::Tex(s) => (s.text().into(), vec![(0, 0)]),
            Self::Html(s) => s.html.lint_prose(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub level: String,
    pub check: String,
    pub line: usize,
    pub message: String,
    pub excerpt: String,
    pub path: PathBuf,
}
fn fa(c: char) -> bool {
    ('\u{0600}'..='\u{06ff}').contains(&c)
        || ('\u{fb50}'..='\u{fdff}').contains(&c)
        || ('\u{fe70}'..='\u{feff}').contains(&c)
}
fn boundaries(text: &str, start: usize, end: usize, before: bool, after: bool) -> bool {
    (!before || !text[..start].chars().next_back().is_some_and(fa))
        && (!after || !text[end..].chars().next().is_some_and(fa))
}
pub fn fa_pattern(word: &str) -> String {
    word.split(['\u{200c}', ' '])
        .map(regex::escape)
        .collect::<Vec<_>>()
        .join("[\u{200c} ]?")
}
fn excerpt(text: &str, pos: usize) -> String {
    let mut start = pos.min(text.len());
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    let before = text[..start]
        .char_indices()
        .rev()
        .nth(19)
        .map_or(0, |(i, _)| i);
    text[before..]
        .chars()
        .take(60)
        .collect::<String>()
        .replace('\n', " ")
        .trim()
        .into()
}
pub fn check(
    src: &Source,
    pairs: &[Pair],
    manifest: Option<&[String]>,
    level: &str,
) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let text = src.text();
    let structural = src.structural();
    let (prose, segments) = src.prose();
    let located = |offset: usize| {
        let i = segments.partition_point(|&(a, _)| a <= offset);
        if i == 0 {
            offset
        } else {
            let (a, b) = segments[i - 1];
            b + offset - a
        }
    };
    let mut add = |severity: &str, id: &str, pos: usize, message: String| {
        if !src.suppressed(pos, id) {
            let (path, line) = src.location(pos);
            out.push(Finding {
                level: severity.into(),
                check: id.into(),
                line,
                message,
                excerpt: excerpt(text, pos),
                path,
            });
        }
    };
    let prose_hits = |pattern: &str| -> Result<Vec<(usize, usize, usize, String)>> {
        let re = Regex::new(pattern)?;
        Ok(re
            .find_iter(&prose)
            .filter_map(|m| {
                let pos = located(m.start());
                if matches!(src, Source::Tex(_)) && src.is_protected(pos) {
                    None
                } else {
                    Some((m.start(), m.end(), pos, m.as_str().into()))
                }
            })
            .collect())
    };
    let live_hits = |pattern: &str| -> Result<Vec<(usize, String)>> {
        Ok(Regex::new(pattern)?
            .find_iter(structural)
            .filter(|m| !src.inert(m.start()))
            .map(|m| (m.start(), m.as_str().into()))
            .collect())
    };
    for (_, _, pos, token) in prose_hits("[كي]")? {
        add(
            "error",
            "arabic-letters",
            pos,
            format!("Arabic letter {token:?}; use ک / ی"),
        );
    }
    for (_, _, pos, token) in prose_hits("[\u{06f0}-\u{06f9}\u{0660}-\u{0669}\u{066b}\u{066c}]")? {
        add(
            "error",
            "eastern-digits",
            pos,
            format!("eastern digit or Arabic decimal {token:?}; digits stay Western (3.14)"),
        );
    }
    for verb in VERBS.split_whitespace() {
        for (start, end, pos, _) in prose_hits(&regex::escape(verb))? {
            if boundaries(&prose, start, end, true, false) {
                add(
                    "error",
                    "zwnj-verb",
                    pos,
                    format!("missing ZWNJ in {verb:?}"),
                );
            }
        }
    }
    for (start, end, pos, token) in prose_hits(&format!("[{FA}]ه(?:هایی|های|ها)"))? {
        if boundaries(&prose, start, end, false, true) {
            add(
                "error",
                "zwnj-plural",
                pos,
                format!("{token:?} looks like a missing ZWNJ before the plural"),
            );
        }
    }
    for (_, _, pos, _) in prose_hits(&format!("[{FA}]\\s?[,;]|[,;]\\s?[{FA}]"))? {
        add(
            "error",
            "latin-punct",
            pos,
            "Latin comma/semicolon in Persian prose; use ، or ؛".into(),
        );
    }
    for (_, _, pos, _) in prose_hits(&format!("[{FA}]\\s?\\?"))? {
        add(
            "error",
            "latin-punct",
            pos,
            "Latin question mark in Persian prose; use ؟".into(),
        );
    }
    let mut pairs = pairs.to_vec();
    pairs.sort_by_key(|r| std::cmp::Reverse(r.1.chars().count()));
    let mut consumed = Vec::new();
    for (en, term, scope) in &pairs {
        for (start, end, pos, token) in prose_hits(&fa_pattern(term))? {
            if !boundaries(&prose, start, end, true, true)
                || consumed.iter().any(|&(a, b)| a < end && start < b)
            {
                continue;
            }
            consumed.push((start, end));
            add(
                "error",
                "forbidden-fa",
                pos,
                format!("{token:?} is a calque of {en:?} ({scope}); keep {en:?} in an LTR isolate"),
            );
        }
    }
    if level == "system-docs" {
        for head in HEADS.split('|') {
            let pattern = format!(
                r"{}\s*(?:\\(?:lr|en|textenglish)\s*\{{|<span[^>]*>|<bdi[^>]*>|)\s*[A-Za-z]",
                fa_pattern(head)
            );
            for m in Regex::new(&pattern)?.find_iter(text) {
                if !src.is_protected(m.start()) && boundaries(text, m.start(), m.end(), true, false)
                {
                    add("error","half-translation",m.start(),"Persian head noun in front of an English name; keep the whole source noun phrase English in one isolate".into());
                }
            }
        }
    }
    for (pos, token) in live_hits(r"(?:\}|</span>|</bdi>|[A-Za-z])ی")? {
        if boundaries(structural, pos, pos + token.len(), false, true) {
            add("error","fa-morphology",pos,"Persian suffix ی attached to an English token; do not add ezafe. Plurals are ها after the isolate".into());
        }
    }
    let english_tokens = Regex::new("[A-Za-z]+")?;
    for isolate in src.isolates() {
        if src
            .identity()
            .iter()
            .any(|&(a, b)| a <= isolate.start && isolate.start < b)
            || ["/", "://", "@", "->"]
                .iter()
                .any(|x| isolate.body.contains(x))
        {
            continue;
        }
        for token in english_tokens.find_iter(&isolate.body) {
            if let Some(stem) = english_plural_stem(token.as_str()) {
                add(
                    "error",
                    "en-plural",
                    isolate.start,
                    format!(
                        "English plural {:?}; write the singular stem in the isolate and Persian ها after it ({stem}ها)",
                        token.as_str()
                    ),
                );
            }
        }
    }
    let mut ordered = src.isolates().to_vec();
    ordered.sort_by_key(|i| i.start);
    let gap_re = Regex::new(r"^[\s~/()\[\]{}:.,+=<>\-–—]*$")?;
    for pair in ordered.windows(2) {
        let a = &pair[0];
        let b = &pair[1];
        if b.start > a.end {
            let gap = text[a.end..b.start]
                .replace("&nbsp;", " ")
                .replace("->", "");
            if gap_re.is_match(&gap) {
                add("error","split-isolate",a.end,"two LTR isolates with only space or punctuation between them; wrap the whole cluster in one isolate".into());
            }
        }
    }
    for (_, _, pos, run) in prose_hits(r"[A-Za-z][A-Za-z0-9._/+-]{2,}")? {
        if !crate::html::member(STOPWORDS, &run)
            && !crate::html::member(
                STOPWORDS,
                run.trim_end_matches(|c: char| c.is_ascii_digit()),
            )
        {
            add(
                "error",
                "unisolated-latin",
                pos,
                format!("Latin run {run:?} is not inside an LTR isolate"),
            );
        }
    }
    for (_, _, pos, token) in prose_hits(r"\d+(?:[.\-–/:]\d+)*")? {
        add(
            "error",
            "unisolated-number",
            pos,
            format!(
                "number cluster {token:?} is not inside an LTR isolate (ranges and dates reverse on an RTL page)"
            ),
        );
    }
    let mut seen = BTreeMap::new();
    for i in src.isolates() {
        if src
            .identity()
            .iter()
            .any(|&(a, b)| a <= i.start && i.start < b)
        {
            continue;
        }
        let term = i.body.split_whitespace().collect::<Vec<_>>().join(" ");
        if term.is_empty() || !term.bytes().any(|b| b.is_ascii_alphabetic()) {
            continue;
        }
        let lower = term.to_lowercase();
        let key = lower.strip_suffix('s').unwrap_or(&lower).to_owned();
        if let Some(previous) = seen.get(&key)
            && previous != &term
        {
            add(
                "error",
                "terminology-drift",
                i.start,
                format!(
                    "isolate {term:?} also appears as {previous:?}; use one English form per concept"
                ),
            );
        }
        seen.entry(key).or_insert(term);
    }
    match src {
        Source::Html(s) => {
            let right_aligned = Regex::new(r"(?i)text-align\s*:\s*right")?;
            for n in &s.html.nodes {
                if n.tag == "pre" && !n.attr("dir").eq_ignore_ascii_case("ltr") {
                    add(
                        "error",
                        "code-direction",
                        n.start,
                        "<pre> requires dir=\"ltr\"".into(),
                    );
                }
                if ["pre", "code"].contains(&n.tag.as_str())
                    && (n.attr("dir").eq_ignore_ascii_case("rtl")
                        || right_aligned.is_match(n.attr("style")))
                {
                    add(
                        "error",
                        "code-direction",
                        n.start,
                        "listing forced RTL or right-aligned".into(),
                    );
                }
            }
            let roots: Vec<_> = s.html.nodes.iter().filter(|n| n.tag == "html").collect();
            if roots.len() != 1
                || !roots[0].attr("lang").eq_ignore_ascii_case("fa")
                || !roots[0].attr("dir").eq_ignore_ascii_case("rtl")
            {
                add(
                    "error",
                    "html-root",
                    0,
                    "root element must be <html lang=\"fa\" dir=\"rtl\">".into(),
                );
            }
            if !text.contains("pre-wrap")
                && let Some(n) = s
                    .html
                    .nodes
                    .iter()
                    .find(|n| ["pre", "code"].contains(&n.tag.as_str()))
            {
                add(
                    "warn",
                    "print-css",
                    n.start,
                    "no white-space: pre-wrap on pre; long code lines are clipped on paper".into(),
                );
            }
            for (pos, _) in live_hits(r"scaleX\(\s*-1\s*\)")? {
                add(
                    "error",
                    "mirrored-image",
                    pos,
                    "horizontal flip on artwork is forbidden".into(),
                );
            }
            for n in &s.html.nodes {
                if n.tag == "img" && !n.attr("dir").eq_ignore_ascii_case("ltr") {
                    add(
                        "error",
                        "figure-direction",
                        n.start,
                        "<img> requires dir=\"ltr\"".into(),
                    );
                }
            }
        }
        Source::Tex(s) => {
            for env in ["verbatim", "Verbatim", "lstlisting"] {
                for (pos, _) in live_hits(&format!(r"\\begin\{{{}\}}", regex::escape(env)))? {
                    if !s.in_direction_scope(pos, &["latin"]) {
                        add(
                            "error",
                            "code-direction",
                            pos,
                            format!(
                                "{env} is not wrapped in \\begin{{latin}}; listings are never RTL"
                            ),
                        );
                    }
                }
            }
            if let Some(m) = Regex::new(
                r"\\(?:section|subsection|subsubsection|chapter|caption)\*?\{[^}]*\\(?:lr|en)\b",
            )?
            .find(structural)
                && !Regex::new(r"\\pdfstringdefDisableCommands\b")?.is_match(structural)
            {
                add("warn","bookmark-guard",m.start(),"\\lr/\\en used in a heading or caption without \\pdfstringdefDisableCommands; hyperref bookmarks will break".into());
            }
            for (pos, _) in src.image_references() {
                if !s.in_direction_scope(pos, &["LTR", "latin", "LR"]) {
                    add("error","figure-direction",pos,"\\includegraphics is not inside LTR/latin; xepersian can paint the figure black or mirrored".into());
                }
            }
        }
    }
    let root = src
        .path()
        .parent()
        .context("source has no parent")?
        .canonicalize()?;
    let mut found = Vec::new();
    let full_page_raster = Regex::new(r"(?i)^(?:srcpage|page)-\d+\.(?:png|jpe?g|webp)$")?;
    for (pos, reference) in src.image_references() {
        let mut name = Path::new(&reference)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        match resolve_asset(&root, &reference) {
            Ok(asset) => {
                name = asset
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                found.push(name.clone());
            }
            Err(error) => add("error", "missing-image", pos, error.to_string()),
        }
        if full_page_raster.is_match(&name) {
            add(
                "error",
                "full-page-figure",
                pos,
                format!("image {name:?} is a full source-page raster; crop to the artwork"),
            );
        }
    }
    if let Some(manifest) = manifest {
        for name in manifest {
            if !found.contains(name) {
                add(
                    "error",
                    "missing-image",
                    0,
                    format!("{name:?} is in the source manifest but not in the translation"),
                );
            }
        }
    }
    Ok(out)
}
pub fn resolve_asset(root: &Path, reference: &str) -> Result<PathBuf> {
    if reference.starts_with("//") || url::Url::parse(reference).is_ok() {
        bail!("document assets must be approved local files");
    }
    let reference = reference.split(['?', '#']).next().unwrap_or("");
    let decoded = String::from_utf8(percent_decode(reference)?)?;
    let candidate = root.join(decoded);
    let mut paths = vec![candidate.clone()];
    if candidate.extension().is_none() {
        for ext in ["pdf", "png", "jpg", "jpeg", "eps"] {
            paths.push(candidate.with_extension(ext));
        }
    }
    let matches: Vec<_> = paths
        .into_iter()
        .filter(|p| p.is_file())
        .map(|p| p.canonicalize())
        .collect::<std::io::Result<_>>()?;
    if matches.len() != 1 {
        bail!("asset is missing or ambiguous: {reference}");
    }
    if !matches[0].starts_with(root) {
        bail!("asset leaves the approved job root");
    }
    Ok(matches[0].clone())
}
#[derive(Clone, Debug)]
pub struct LintOptions {
    pub level: String,
    pub pairs: Option<PathBuf>,
    pub terms: Option<PathBuf>,
    pub manifest: Option<PathBuf>,
    pub strict: bool,
}
impl Default for LintOptions {
    fn default() -> Self {
        Self {
            level: "system-docs".into(),
            pairs: None,
            terms: None,
            manifest: None,
            strict: false,
        }
    }
}
pub fn lint_file(path: &Path, options: &LintOptions) -> Result<Vec<Finding>> {
    if !["system-docs", "journal"].contains(&options.level.as_str()) {
        bail!("unsupported terminology level");
    }
    let source = path.canonicalize()?;
    let root = source.parent().context("source has no parent")?;
    let mut pairs = terms::house_pairs(&options.level)?;
    if let Some(extra) = &options.pairs {
        if !extra.is_file() {
            bail!("explicit --pairs file is missing");
        }
        pairs.extend(terms::load_pairs(
            std::slice::from_ref(extra),
            &options.level,
        )?);
    }
    let terms_path = options
        .terms
        .clone()
        .unwrap_or_else(|| root.join("terms.tsv"));
    if options.strict || options.terms.is_some() || terms_path.exists() {
        if !terms_path.is_file() {
            bail!("--strict requires --terms FILE (or terms.tsv next to the source)");
        }
        let data = bounded_read(&terms_path, 1024 * 1024)?;
        pairs.extend(
            ledger::terms_pairs(std::str::from_utf8(&data)?)
                .map_err(|error| anyhow::anyhow!("terms-calque: {error}"))?,
        );
    }
    let manifest_path = options
        .manifest
        .clone()
        .unwrap_or_else(|| root.join("manifest.txt"));
    let manifest = if options.strict || options.manifest.is_some() || manifest_path.exists() {
        if !manifest_path.is_file() {
            bail!("--strict requires --manifest FILE (or manifest.txt next to the source)");
        }
        let data = bounded_read(&manifest_path, 1024 * 1024)?;
        Some(
            std::str::from_utf8(&data)?
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.starts_with('#'))
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    let mut seen = BTreeSet::new();
    pairs.retain(|p| seen.insert((p.0.clone(), p.1.clone())));
    check(
        &Source::load(&source)?,
        &pairs,
        manifest.as_deref(),
        &options.level,
    )
}
#[derive(Parser)]
struct LintArgs {
    #[arg(required = true)]
    files: Vec<PathBuf>,
    #[arg(long,default_value="system-docs",value_parser=["system-docs","journal"])]
    level: String,
    #[arg(long)]
    pairs: Option<PathBuf>,
    #[arg(long)]
    terms: Option<PathBuf>,
    #[arg(long)]
    manifest: Option<PathBuf>,
    #[arg(long)]
    strict: bool,
    #[arg(long, default_value_t = 40)]
    max: usize,
}
pub fn cli_lint(args: &[String]) -> Result<i32> {
    let args =
        LintArgs::try_parse_from(std::iter::once("lint".to_owned()).chain(args.iter().cloned()))?;
    let options = LintOptions {
        level: args.level,
        pairs: args.pairs,
        terms: args.terms,
        manifest: args.manifest,
        strict: args.strict,
    };
    let mut errors = 0;
    let mut warnings = 0;
    for path in &args.files {
        let findings = lint_file(path, &options)?;
        errors += findings.iter().filter(|f| f.level == "error").count();
        warnings += findings.iter().filter(|f| f.level == "warn").count();
        println!("== {}", path.display());
        if findings.is_empty() {
            println!("   clean");
            continue;
        }
        let mut groups: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
        for f in &findings {
            groups.entry(f.check.clone()).or_default().push(f);
        }
        let mut groups: Vec<_> = groups.into_iter().collect();
        groups.sort_by_key(|(id, fs)| (fs[0].level != "error", id.clone()));
        for (id, group) in groups {
            println!("   [{}] {id} ({})", group[0].level, group.len());
            for f in group.iter().take(args.max) {
                println!(
                    "     {}:{}: {}\n       … {}",
                    f.path.display(),
                    f.line,
                    f.message,
                    f.excerpt
                );
            }
            if group.len() > args.max {
                println!("     … {} more", group.len() - args.max);
            }
        }
    }
    println!("\ncheck-fa: {errors} error(s), {warnings} warning(s)");
    Ok(i32::from(errors > 0 || (args.strict && warnings > 0)))
}
