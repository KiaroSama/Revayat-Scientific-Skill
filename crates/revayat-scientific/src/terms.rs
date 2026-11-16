//! House terminology and bounded, evidence-based multilingual term briefs.
use crate::{
    ledger::{self, Pair},
    resource::{bounded_read, sha256},
};
use anyhow::{Context, Result, bail};
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use unicode_casefold::UnicodeCaseFold;
const HOUSE: &str = include_str!("../../../skills/revayat-scientific/references/term-pairs.tsv");
const DEFAULTS: &[(&str, &str)] = &[
    ("node", "گره"),
    ("deployment", "استقرار"),
    ("configuration", "پیکربندی"),
    ("implementation", "پیاده‌سازی"),
    ("integration", "یکپارچه‌سازی"),
    ("firewall", "دیوار آتش"),
    ("encryption", "رمزنگاری"),
    ("command", "فرمان"),
];
pub fn parse_pairs(text: &str, level: &str) -> Result<Vec<Pair>> {
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    let mut record_seen = false;
    for (i, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split('\t').map(str::trim).collect();
        if parts.starts_with(&["english", "forbidden_fa"]) {
            if record_seen {
                bail!("row {}: duplicate terminology header", i + 1);
            }
            record_seen = true;
            if parts != ["english", "forbidden_fa", "scope"]
                && parts != ["english", "forbidden_fa", "scope", "levels"]
            {
                bail!("row {}: invalid terminology header", i + 1);
            }
            continue;
        }
        record_seen = true;
        if !(parts.len() == 3 || parts.len() == 4) || parts[..3].iter().any(|s| s.is_empty()) {
            bail!(
                "row {}: expected english, forbidden_fa, scope and optional levels",
                i + 1
            );
        }
        let levels = parts.get(3).copied().unwrap_or("all");
        if !["all", "system-docs", "journal"].contains(&levels) {
            bail!("row {}: unsupported terminology level", i + 1);
        }
        if (levels == "journal" && level != "journal")
            || (levels == "system-docs" && level == "journal")
        {
            continue;
        }
        if seen.insert((parts[0].to_owned(), parts[1].to_owned())) {
            rows.push((parts[0].into(), parts[1].into(), parts[2].into()));
        }
    }
    Ok(rows)
}
pub fn house_pairs(level: &str) -> Result<Vec<Pair>> {
    parse_pairs(HOUSE, level)
}
pub fn load_pairs(paths: &[PathBuf], level: &str) -> Result<Vec<Pair>> {
    let mut loaded = false;
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for path in paths {
        if !path.exists() {
            continue;
        }
        loaded = true;
        let data = bounded_read(path, 1024 * 1024)?;
        for row in parse_pairs(std::str::from_utf8(&data)?, level)? {
            if seen.insert((row.0.clone(), row.1.clone())) {
                rows.push(row);
            }
        }
    }
    if !loaded {
        rows.extend(
            DEFAULTS
                .iter()
                .map(|(en, fa)| (en.to_string(), fa.to_string(), "universal".into())),
        );
    }
    Ok(rows)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TermLocation {
    pub line: usize,
    pub column: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BriefTerm {
    pub source: String,
    pub output: String,
    pub ledger_line: u64,
    pub concept: String,
    pub locations: Vec<TermLocation>,
    pub more_matches: bool,
    pub ambiguous: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Brief {
    pub source_language: String,
    pub source_sha256: String,
    pub terms_sha256: String,
    pub status: String,
    pub terms: Vec<BriefTerm>,
}
pub fn approved_rows(text: &str) -> Result<Vec<BriefTerm>> {
    let records = ledger::ledger_records(text, &["source", "output"])?;
    let mut rows = Vec::new();
    for r in records {
        if r.approved() {
            rows.push(BriefTerm {
                source: r.get("source").into(),
                output: r.get("output").into(),
                ledger_line: r.ledger_line,
                concept: r.get("concept").into(),
                locations: Vec::new(),
                more_matches: false,
                ambiguous: false,
            });
            if rows.len() > 512 {
                bail!("term brief exceeds 512 approved rows");
            }
        }
    }
    Ok(rows)
}
fn cjk(s: &str) -> bool {
    s.chars()
        .any(|c| ('\u{3040}'..='\u{30ff}').contains(&c) || ('\u{3400}'..='\u{9fff}').contains(&c))
}
fn word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}
pub fn candidate_brief(source: &str, rows: Vec<BriefTerm>) -> Result<Vec<BriefTerm>> {
    let mut results = Vec::new();
    let starts: Vec<usize> = std::iter::once(0)
        .chain(source.match_indices('\n').map(|(i, _)| i + 1))
        .collect();
    for mut row in rows {
        let re = Regex::new(&format!("(?i){}", regex::escape(&row.source)))?;
        for m in re.find_iter(source) {
            if !cjk(&row.source)
                && (source[..m.start()].chars().next_back().is_some_and(word)
                    || source[m.end()..].chars().next().is_some_and(word))
            {
                continue;
            }
            if row.locations.len() == 64 {
                row.more_matches = true;
                break;
            }
            let line = starts.partition_point(|&i| i <= m.start());
            let column = source[starts[line - 1]..m.start()].chars().count() + 1;
            row.locations.push(TermLocation { line, column });
        }
        if !row.locations.is_empty() {
            results.push(row);
        }
    }
    results.sort_by_key(|r| (r.locations[0].line, r.locations[0].column, r.ledger_line));
    let mut variants: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new();
    for r in &results {
        variants
            .entry(r.source.to_lowercase().case_fold().collect::<String>())
            .or_default()
            .insert((r.output.clone(), r.concept.clone()));
    }
    for r in &mut results {
        r.ambiguous = variants[&r.source.to_lowercase().case_fold().collect::<String>()].len() > 1;
    }
    Ok(results)
}
pub fn term_brief(source: &Path, terms: &Path, language: &str) -> Result<Brief> {
    if !Regex::new(r"^[A-Za-z][A-Za-z0-9-]{1,31}$")?.is_match(language) {
        bail!("--language requires a language/variety identifier");
    }
    if !matches!(
        source
            .extension()
            .and_then(|s| s.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("txt" | "text" | "md")
    ) {
        bail!("term brief requires reviewed UTF-8 extracted text or Markdown");
    }
    let source_bytes = bounded_read(source, 4 * 1024 * 1024)?;
    let source_text = std::str::from_utf8(&source_bytes).context("source is not UTF-8")?;
    if source_text.starts_with("%PDF-") || source_text.contains('\0') {
        bail!("binary source is not reviewed extracted text");
    }
    let terms_bytes = bounded_read(terms, 1024 * 1024)?;
    let terms_text = std::str::from_utf8(&terms_bytes)?;
    let rows = candidate_brief(source_text, approved_rows(terms_text)?)?;
    Ok(Brief {
        source_language: language.into(),
        source_sha256: sha256(&source_bytes),
        terms_sha256: sha256(&terms_bytes),
        status: if rows.is_empty() {
            "no-matches"
        } else {
            "candidates"
        }
        .into(),
        terms: rows,
    })
}
#[derive(Parser)]
struct BriefArgs {
    source: PathBuf,
    #[arg(long)]
    terms: PathBuf,
    #[arg(long)]
    language: String,
}
pub fn cli_term_brief(args: &[String]) -> Result<i32> {
    let args = BriefArgs::try_parse_from(
        std::iter::once("term-brief".to_owned()).chain(args.iter().cloned()),
    )?;
    println!(
        "{}",
        serde_json::to_string(&term_brief(&args.source, &args.terms, &args.language)?)?
    );
    Ok(0)
}
