//! Source-token evidence for Persian Unicode extraction order.
use crate::{html::ParsedHtml, resource::bounded_read, tex};
use anyhow::{Result, bail};
use clap::Parser;
use regex::Regex;
use std::path::{Path, PathBuf};
#[path = "text_order_windows.rs"]
mod windows;
use unicode_normalization::UnicodeNormalization;
pub const MAX_PROBE_STEPS: usize = 2_000_000;
pub fn strip_bidi(s: &str) -> String {
    s.chars()
        .filter(
            |c| !matches!(c,'\u{200e}'|'\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'),
        )
        .collect()
}
pub fn fold(s: &str) -> String {
    strip_bidi(&s.nfkc().collect::<String>())
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '\u{200c}')
        .collect()
}
pub fn strip_html(text: &str) -> Result<String> {
    Ok(ParsedHtml::parse(text)?.text_content())
}
pub fn source_plain(path: &Path) -> Result<String> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ["tex", "ltx"].contains(&ext.as_str()) {
        let closure = tex::source_closure(path, None)?;
        tex::plain_tex(&closure.text)
    } else {
        let bytes = bounded_read(path, 16 * 1024 * 1024)?;
        let text = std::str::from_utf8(&bytes)?;
        if ["html", "htm"].contains(&ext.as_str()) {
            strip_html(text)
        } else {
            Ok(text.into())
        }
    }
}
pub fn persian_windows(plain: &str, min_letters: usize) -> Result<Vec<Vec<String>>> {
    persian_windows_bounded(plain, min_letters, MAX_PROBE_STEPS)
}
pub fn persian_windows_bounded(
    plain: &str,
    min_letters: usize,
    max_steps: usize,
) -> Result<Vec<Vec<String>>> {
    if !(1..=4096).contains(&min_letters) {
        bail!("minimum probe length must be an integer from 1 to 4096");
    }
    let re = Regex::new(
        r"[\u{0600}-\u{06ff}\u{0750}-\u{077f}\u{08a0}-\u{08ff}\u{fb50}-\u{fdff}\u{fe70}-\u{feff}\u{200c}]+",
    )?;
    let words: Vec<String> = re
        .find_iter(plain)
        .map(|m| fold(m.as_str()))
        .filter(|s| !s.is_empty())
        .collect();
    let counts: Vec<_> = words.iter().map(|s| s.chars().count()).collect();
    windows::token_windows(&words, &counts, min_letters, max_steps)
}
pub fn classify(windows: &[Vec<String>], extracted: &str, min_letters: usize) -> &'static str {
    let hay = fold(extracted);
    if hay.is_empty() || windows.is_empty() {
        return "inconclusive";
    }
    let (mut logical, mut visual) = (0, 0);
    for acc in windows {
        let logi = acc.concat();
        if logi.chars().count() < min_letters {
            continue;
        }
        let char_vis: String = logi.chars().rev().collect();
        let word_vis = acc.iter().rev().cloned().collect::<Vec<_>>().concat();
        let in_log = hay.contains(&logi);
        let in_vis = (char_vis != logi && hay.contains(&char_vis))
            || (word_vis != logi && hay.contains(&word_vis));
        if in_log && !in_vis {
            logical += 1;
        } else if in_vis && !in_log {
            visual += 1;
        }
    }
    if visual >= 1 && visual > logical {
        "visual"
    } else if logical >= 1 && logical > visual {
        "logical"
    } else {
        "inconclusive"
    }
}
#[derive(Parser)]
struct Args {
    pdf: Option<PathBuf>,
    #[arg(long)]
    source: PathBuf,
    #[arg(long)]
    extracted: Option<PathBuf>,
    #[arg(long, default_value_t = 12)]
    min_letters: usize,
    #[arg(long)]
    json: bool,
}
pub fn cli_text_order(args: &[String]) -> Result<i32> {
    let a = Args::try_parse_from(
        std::iter::once("check-pdf-text-order".to_owned()).chain(args.iter().cloned()),
    )?;
    let windows = persian_windows(&source_plain(&a.source)?, a.min_letters)?;
    let extracted = if let Some(path) = a.extracted {
        String::from_utf8(bounded_read(&path, 64 * 1024 * 1024)?)?
    } else if let Some(pdf) = a.pdf {
        crate::pdf::pdf_text(&pdf)?
    } else {
        bail!("pass a PDF or --extracted");
    };
    let kind = classify(&windows, &extracted, a.min_letters);
    if a.json {
        println!(
            "{}",
            serde_json::json!({"check":"text-order","status":match kind{"logical"=>"passed","visual"=>"failed",_=>"inconclusive"},"order":kind,"probes":windows.len()})
        );
        Ok(match kind {
            "logical" => 0,
            "visual" => 2,
            _ => 3,
        })
    } else {
        eprintln!(
            "check-pdf-text-order: {kind} ({} Persian phrase probes)",
            windows.len()
        );
        if kind == "visual" {
            eprintln!(
                "Native PDF extraction is visual order; selectable Persian is not verified. Check font and ActualText mapping."
            );
            Ok(2)
        } else {
            Ok(0)
        }
    }
}
/// Scientific builds require positive source-token evidence, including ActualText.
pub fn verify_source(pdf: &Path, source: &Path) -> Result<()> {
    let windows = persian_windows(&source_plain(source)?, 12)?;
    let extracted = crate::pdf::pdf_text(pdf)?;
    let kind = classify(&windows, &extracted, 12);
    if kind != "logical" {
        bail!(
            "text-order verification {kind}: {} Persian phrase probes",
            windows.len()
        );
    }
    Ok(())
}
