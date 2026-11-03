//! The shared bounded terminology schema. Validate every record before selecting
//! approved decisions, so a late malformed row cannot admit partial bans.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const MAX_LEDGER_BYTES: usize = 1024 * 1024;
pub const MAX_LEDGER_ROWS: usize = 10_000;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Record {
    #[serde(flatten)]
    pub fields: BTreeMap<String, String>,
    pub ledger_line: u64,
}

impl Record {
    pub fn get(&self, name: &str) -> &str {
        self.fields.get(name).map_or("", String::as_str)
    }

    pub fn approved(&self) -> bool {
        !self.get("output").is_empty()
            && self.fields.get("status").is_none_or(|status| {
                matches!(
                    status.to_ascii_lowercase().as_str(),
                    "preferred" | "approved"
                )
            })
    }
}

/// Read only a bounded prefix, including the extra byte needed to detect excess.
pub fn read_ledger(path: &Path, required: &[&str]) -> Result<Vec<Record>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((MAX_LEDGER_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ledger_records(
        std::str::from_utf8(&bytes).context("terms.tsv is not UTF-8")?,
        required,
    )
}

/// TSV fields may contain quoted tabs/newlines in notes. Source/output fields
/// must still be bounded single-line values, regardless of approval status.
pub fn ledger_records(text: &str, required: &[&str]) -> Result<Vec<Record>> {
    ensure!(text.len() <= MAX_LEDGER_BYTES, "terms.tsv exceeds 1 MiB");
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let newlines: Vec<usize> = text
        .bytes()
        .enumerate()
        .filter(|(_, byte)| *byte == b'\n')
        .map(|(offset, _)| offset)
        .collect();
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b'\t')
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut header: Option<Vec<String>> = None;
    let mut records = Vec::new();
    let mut values = csv::StringRecord::new();
    loop {
        let start = reader.position().byte() as usize;
        if !reader
            .read_record(&mut values)
            .context("invalid TSV record")?
        {
            break;
        }
        let end = reader.position().byte() as usize;
        let raw = &text[start..end];
        // The CSV reader skips empty physical records internally. Its record
        // position may precede those records; count original LF boundaries,
        // rather than its normalized record-line counter (notably with CRLF).
        let data_start = start + raw.len() - raw.trim_start_matches(['\r', '\n']).len();
        let line = (newlines.partition_point(|offset| *offset < data_start) + 1) as u64;
        if raw.trim_start_matches(' ').starts_with('#')
            || raw.trim_matches([' ', '\r', '\n']).is_empty()
        {
            continue;
        }
        // csv intentionally accepts malformed quoting. The legacy schema is
        // strict: independently validate delimiters before trusting parsed cells.
        validate_quoting(raw).with_context(|| format!("invalid TSV at physical line {line}"))?;
        if header.is_none() {
            let names: Vec<String> = values
                .iter()
                .map(|v| v.trim().to_ascii_lowercase())
                .collect();
            let unique: HashSet<&str> = names.iter().map(String::as_str).collect();
            ensure!(
                names.iter().all(|n| !n.is_empty())
                    && unique.len() == names.len()
                    && required.iter().all(|n| unique.contains(n)),
                "terms.tsv requires unique columns: {}",
                required.join(", ")
            );
            header = Some(names);
            continue;
        }
        let names = header.as_ref().expect("validated header");
        if values.len() != names.len() {
            let source_column = names
                .iter()
                .position(|name| name == "source")
                .expect("required source column validated");
            let source: String = values
                .get(source_column)
                .unwrap_or("")
                .chars()
                .take(256)
                .collect();
            bail!("terms.tsv row {line} source {source:?} does not match the header");
        }
        let mut fields = BTreeMap::new();
        for (name, value) in names.iter().zip(values.iter()) {
            if matches!(name.as_str(), "source" | "output") {
                ensure!(
                    value.trim().chars().count() <= 256
                        && (name != "source" || !value.trim().is_empty())
                        && !value
                            .chars()
                            .any(|c| c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&c)),
                    "terms.tsv row {line} has invalid source/output text"
                );
            }
            fields.insert(name.clone(), value.trim().to_owned());
        }
        records.push(Record {
            fields,
            ledger_line: line,
        });
        ensure!(
            records.len() <= MAX_LEDGER_ROWS,
            "terms.tsv exceeds 10000 records"
        );
    }
    ensure!(header.is_some(), "terms.tsv is missing its header");
    Ok(records)
}

fn validate_quoting(raw: &str) -> Result<()> {
    let bytes = raw.as_bytes();
    let mut index = 0;
    let mut cell_start = true;
    let mut quoted = false;
    let mut after_quote = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if quoted {
            if byte == b'"' {
                if bytes.get(index + 1) == Some(&b'"') {
                    index += 2;
                    continue;
                }
                quoted = false;
                after_quote = true;
            }
        } else if matches!(byte, b'\t' | b'\r' | b'\n') {
            cell_start = true;
            after_quote = false;
        } else if after_quote {
            bail!("unexpected data after closing quote");
        } else if cell_start && byte == b'"' {
            quoted = true;
            cell_start = false;
        } else {
            cell_start = false;
        }
        index += 1;
    }
    ensure!(!quoted, "unterminated quoted field");
    Ok(())
}

pub type Pair = (String, String, String);

pub fn terms_pairs(text: &str) -> Result<Vec<Pair>> {
    let records = ledger_records(text, &["source", "output", "step", "count", "forbidden_fa"])?;
    let mut pairs = Vec::new();
    let mut seen = HashSet::new();
    for row in records
        .iter()
        .filter(|r| r.approved() && r.get("output").contains(|c: char| c.is_ascii_alphabetic()))
    {
        ensure!(
            !row.get("forbidden_fa").is_empty(),
            "terms.tsv row {} source {:?}: keep-English output has empty forbidden_fa (terms-calque)",
            row.ledger_line,
            row.get("source")
        );
        for form in std::iter::once(row.get("forbidden_fa")).chain(
            row.get("deprecated")
                .split('|')
                .map(str::trim)
                .filter(|v| !v.is_empty()),
        ) {
            let key = (row.get("source").to_owned(), form.to_owned());
            if seen.insert(key.clone()) {
                pairs.push((key.0, key.1, "job".into()));
            }
        }
    }
    Ok(pairs)
}
