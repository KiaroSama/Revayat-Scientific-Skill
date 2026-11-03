//! Native ports of source-token extraction evidence; no serialized markup evidence.
use revayat_scientific::text_order::*;
use std::{fs, process::Command};
const VISIBLE: &str = "متن علمی اصلی برای بررسی دقیق ترتیب حروف";
const HIDDEN: &str = "داده آزمایشی غیر قابل نمایش در سند";
#[test]
fn test_hidden_attribute_text_is_not_evidence() {
    let plain = strip_html(&format!("<p title=\"a > {HIDDEN}\">{VISIBLE}</p>")).unwrap();
    assert!(plain.contains(VISIBLE));
    assert!(!plain.contains(HIDDEN));
    assert_eq!(
        classify(&persian_windows(&plain, 12).unwrap(), HIDDEN, 12),
        "inconclusive"
    );
}
#[test]
fn test_ignored_end_tags_cannot_expose_hidden_source_evidence() {
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("source.html");
    let extracted = d.path().join("extracted.txt");
    let body = format!("<span hidden><p>A</span><p>{VISIBLE}</p>");
    assert!(!strip_html(&body).unwrap().contains(VISIBLE));
    let text = format!("<html lang=\"fa\"><body>{body}</body></html>");
    fs::write(&source, &text).unwrap();
    fs::write(&extracted, VISIBLE).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args([
            "text-order",
            "--source",
            source.to_str().unwrap(),
            "--extracted",
            extracted.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("inconclusive"));
    assert_eq!(fs::read_to_string(source).unwrap(), text);
    assert_eq!(fs::read_to_string(extracted).unwrap(), VISIBLE);
}
#[test]
fn test_comment_tail_with_angle_bracket_is_not_evidence() {
    for comment in [
        format!("<!-- <span>{HIDDEN}</span> -->"),
        format!("<!-- a > {HIDDEN} --!>"),
    ] {
        assert!(
            !strip_html(&format!("{comment}<p>{VISIBLE}</p>"))
                .unwrap()
                .contains(HIDDEN)
        );
    }
}
#[test]
fn test_title_head_script_style_and_hidden_subtrees_are_excluded() {
    for (start, end) in [
        ("<head><title>", "</title></head>"),
        ("<script>", "</script>"),
        ("<style>", "</style>"),
        ("<div hidden><span>", "</span></div>"),
    ] {
        let p = strip_html(&format!("{start}{HIDDEN}{end}<p>{VISIBLE}</p>")).unwrap();
        assert!(!p.contains(HIDDEN));
        assert!(p.contains(VISIBLE));
    }
}
#[test]
fn test_textarea_markup_is_preserved_as_displayed_text() {
    let p = strip_html(&format!("<textarea><script>{VISIBLE}</script></textarea>")).unwrap();
    assert!(p.contains(VISIBLE));
    assert!(p.contains("<script>"));
    assert_eq!(
        classify(&persian_windows(&p, 12).unwrap(), VISIBLE, 12),
        "logical"
    );
}
#[test]
fn test_raw_text_entities_and_escaped_literal_tag_text_keep_semantics() {
    let p = strip_html(&format!(
        "<xmp>&amp; {VISIBLE}</xmp><p>&lt;b&gt; متن &amp; واژه</p>"
    ))
    .unwrap();
    assert!(p.contains("&amp;"));
    assert!(p.contains("<b> متن & واژه"));
    assert!(!p.contains("<p>"));
}
#[test]
fn test_inline_boundaries_preserve_words_but_block_elements_separate_them() {
    assert!(
        strip_html("<p>آز<b>ما</b>یش</p>")
            .unwrap()
            .contains("آزمایش")
    );
    assert_eq!(
        strip_html("<p>آزمایش</p><p>علمی</p>").unwrap(),
        "آزمایش علمی"
    );
}
#[test]
fn test_invalid_raw_context_is_not_certified_by_another_parser() {
    for s in [
        "<textarea>unclosed".into(),
        format!("<template>{VISIBLE}</template>"),
    ] {
        assert!(strip_html(&s).is_err());
    }
}
fn legacy(text: &str, threshold: usize) -> Vec<Vec<String>> {
    let words: Vec<String> = text.split_whitespace().map(fold).collect();
    let mut result = Vec::new();
    for start in 0..words.len() {
        let mut letters = 0;
        let mut acc = Vec::new();
        for word in &words[start..] {
            if word.is_empty() {
                continue;
            }
            letters += word.chars().count();
            acc.push(word.clone());
            if letters >= threshold {
                if !result.contains(&acc) {
                    result.push(acc);
                }
                break;
            }
        }
    }
    result
}
#[test]
fn test_window_results_match_legacy_algorithm_on_bounded_inputs() {
    let words: Vec<_> = VISIBLE.split_whitespace().collect();
    let mut state = 20261004u64;
    for threshold in [1, 4, 12, 50] {
        for _ in 0..12 {
            let text = (0..40)
                .map(|_| {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    words[(state >> 32) as usize % words.len()]
                })
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(
                persian_windows(&text, threshold).unwrap(),
                legacy(&text, threshold)
            );
        }
    }
}
#[test]
fn test_windows_do_not_copy_whole_remaining_source_for_every_probe() {
    let text = "آزمایش علمی ".repeat(1000);
    let actual = persian_windows_bounded(&text, 12, 10_000).unwrap();
    assert!(!actual.is_empty());
    assert!(actual.iter().all(|w| w.len() <= 3));
    assert_eq!(actual, legacy(&text, 12));
}
#[test]
fn test_invalid_threshold_and_excessive_work_are_explicit_errors() {
    for n in [0, 4097] {
        assert!(persian_windows(VISIBLE, n).is_err());
    }
    assert!(persian_windows_bounded(&VISIBLE.repeat(10), 12, 10).is_err());
    let result = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args([
            "text-order",
            "--source",
            "missing.html",
            "--min-letters",
            "-1",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
}
#[test]
fn test_cli_cannot_pass_using_attribute_only_evidence() {
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("source.html");
    let extracted = d.path().join("extracted.txt");
    fs::write(
        &source,
        format!("<html lang=\"fa\"><body><p title=\"a > {HIDDEN}\">{VISIBLE}</p></body></html>"),
    )
    .unwrap();
    fs::write(&extracted, HIDDEN).unwrap();
    let r = Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args([
            "text-order",
            "--source",
            source.to_str().unwrap(),
            "--extracted",
            extracted.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        r.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert!(String::from_utf8_lossy(&r.stdout).contains("inconclusive"));
}
#[test]
#[ignore = "requires sandboxed Chromium and Persian fonts; scientific CI must execute this real PDF source-token test"]
fn test_real_two_page_pdf_matches_source_tokens() -> anyhow::Result<()> {
    let d = tempfile::tempdir()?;
    let source = d.path().join("source.html");
    let pdf = d.path().join("source.pdf");
    let text = format!(
        "<!doctype html><html lang=\"fa\" dir=\"rtl\"><head><style>@page{{size:A5;margin:16mm}} body{{font-family:'DejaVu Sans'}} .next{{break-before:page}}</style></head><body><p title=\"metadata > {HIDDEN}\">{VISIBLE}</p><p class=\"next\">{VISIBLE}</p></body></html>"
    );
    fs::write(&source, &text)?;
    let plain = strip_html(&text)?;
    assert!(!plain.contains(HIDDEN));
    let browser = revayat_scientific::render::discover_browser(None)?;
    revayat_scientific::render::render_html(&source, &pdf, &browser, None)?;
    let doc = revayat_scientific::pdf::open_pdf(&pdf, false)?;
    assert_eq!(revayat_scientific::pdf::page_ids(&doc)?.len(), 2);
    let extracted = revayat_scientific::pdf::pdf_text(&pdf)?;
    assert_eq!(
        classify(&persian_windows(&plain, 12)?, &extracted, 12),
        "logical",
        "native extracted text: {extracted:?}"
    );
    assert_eq!(fs::read_to_string(source)?, text);
    Ok(())
}
#[test]
fn native_classifier_distinguishes_logical_visual_and_inconclusive() {
    let windows = persian_windows(VISIBLE, 12).unwrap();
    assert_eq!(classify(&windows, VISIBLE, 12), "logical");
    let visual: String = VISIBLE.chars().rev().collect();
    assert_eq!(classify(&windows, &visual, 12), "visual");
    assert_eq!(classify(&windows, "", 12), "inconclusive");
    assert_eq!(fold("ﻋﻠﻤﯽ\u{200f} می\u{200c}شود"), "علمیمیشود");
}
