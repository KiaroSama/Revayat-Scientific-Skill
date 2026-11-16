//! Behavioral ports of tests/test_term_ledger_contract.py; names are retained
//! so the migration inventory can compare cases rather than just totals.
use revayat_scientific::ledger::{ledger_records, terms_pairs};

const HEADER: &str = "source\toutput\tstep\tcount\tforbidden_fa";
fn brief(text: &str) -> anyhow::Result<Vec<revayat_scientific::ledger::Record>> {
    Ok(ledger_records(text, &["source", "output"])?
        .into_iter()
        .filter(|r| r.approved())
        .collect())
}
fn pair(source: &str, form: &str) -> (String, String, String) {
    (source.into(), form.into(), "job".into())
}

#[test]
fn test_source_and_english_are_data_after_the_header() {
    for source in ["source", "english"] {
        assert_eq!(
            terms_pairs(&format!("{HEADER}\n{source}\tOriginal\t1\t1\tمنبع\n")).unwrap(),
            vec![pair(source, "منبع")]
        );
    }
}

#[test]
fn test_raw_record_boundaries_are_validated_before_decision_selection() {
    let quoted = format!("{HEADER}\n\"#node\"\tNode\t1\t1\tگره\n");
    assert_eq!(terms_pairs(&quoted).unwrap(), vec![pair("#node", "گره")]);
    assert_eq!(brief(&quoted).unwrap()[0].get("source"), "#node");
    let valid = format!("{HEADER}\nnode\tNode\t1\t1\tگره\n");
    for row in [
        "\t\t\n",
        "\t\t\t\t\n",
        "node\t\"Node\n\"\t1\t1\tگره\n",
        "\"\t node\"\tNode\t1\t1\tگره\n",
        "node\t\"Node\u{7f}\"\t1\t1\tگره\n",
    ] {
        let bad = format!("{valid}{row}");
        assert!(terms_pairs(&bad).is_err(), "{row:?}");
        assert!(brief(&bad).is_err(), "{row:?}");
    }
    assert_eq!(
        terms_pairs(&format!("{valid}  \n# retained comment\n")).unwrap(),
        vec![pair("node", "گره")]
    );
}

#[test]
fn test_reordered_columns_resolve_by_header_not_position() {
    let text = "output\tcount\tforbidden_fa\tsource\tstep\nOriginal\t1\tمنبع\tsource\t1\n";
    assert_eq!(terms_pairs(text).unwrap(), vec![pair("source", "منبع")]);
    assert_eq!(brief(text).unwrap()[0].get("source"), "source");
}

#[test]
fn test_bom_comments_blank_lines_and_crlf_share_the_same_parser() {
    let text = format!("\u{feff}# approved fixture\r\n\r\n{HEADER}\r\nnode\tNode\t1\t1\tگره\r\n");
    assert_eq!(terms_pairs(&text).unwrap(), vec![pair("node", "گره")]);
    assert_eq!(brief(&text).unwrap()[0].ledger_line, 4);
}

#[test]
fn test_short_and_long_rows_fail_even_for_persian_output() {
    for row in ["node\tگره", "node\tNode\t1\t1\tگره\textra"] {
        let text = format!("{HEADER}\n{row}\n");
        assert!(terms_pairs(&text).is_err());
        assert!(brief(&text).is_err());
    }
}

#[test]
fn test_missing_and_duplicate_headers_are_not_accepted() {
    for text in [
        "",
        "# comment only\n",
        "node\tNode\t1\t1\tگره\n",
        "source\toutput\tstep\tcount\tforbidden_fa\toutput\n",
        "source\tOutput\tstep\tcount\tforbidden_fa\tOUTPUT\n",
    ] {
        assert!(terms_pairs(text).is_err(), "{text}");
        assert!(brief(text).is_err(), "{text}");
    }
}

#[test]
fn test_lint_requires_its_documented_columns_but_brief_keeps_minimal_schema() {
    let text = "source\toutput\nnode\tگره\n";
    assert!(terms_pairs(text).is_err());
    assert_eq!(brief(text).unwrap()[0].get("output"), "گره");
}

#[test]
fn test_only_approved_rows_drive_bans_when_status_is_present() {
    for status in ["rejected", "unresolved", "provisional", ""] {
        let text = format!("{HEADER}\tstatus\nnode\tNode\t1\t1\tگره\t{status}\n");
        assert!(terms_pairs(&text).unwrap().is_empty());
        assert!(brief(&text).unwrap().is_empty());
    }
    for status in ["preferred", "approved", " APPROVED "] {
        let text = format!("{HEADER}\tstatus\nnode\tNode\t1\t1\tگره\t{status}\n");
        assert_eq!(terms_pairs(&text).unwrap(), vec![pair("node", "گره")]);
        assert_eq!(brief(&text).unwrap().len(), 1);
    }
}

#[test]
fn test_quoted_cells_and_multiline_notes_keep_physical_row_locations() {
    let text = format!(
        "{HEADER}\tevidence\nnode\tNode\t1\t1\tگره\t\"line one\nline two\"\nsource\tOriginal\t1\t1\tمنبع\tnote\n"
    );
    assert_eq!(
        terms_pairs(&text).unwrap(),
        vec![pair("node", "گره"), pair("source", "منبع")]
    );
    assert_eq!(
        brief(&text)
            .unwrap()
            .iter()
            .map(|r| r.ledger_line)
            .collect::<Vec<_>>(),
        [2, 4]
    );
}

#[test]
fn test_header_only_is_valid_and_does_not_invent_bans() {
    assert!(terms_pairs(&format!("{HEADER}\n")).unwrap().is_empty());
    assert!(brief(&format!("{HEADER}\n")).unwrap().is_empty());
}

#[test]
fn test_deprecated_bans_and_missing_counterform_remain_enforced() {
    let text = format!("{HEADER}\tdeprecated\nnode\tNode\t1\t1\tگره\tرأس|نود\n");
    assert_eq!(
        terms_pairs(&text).unwrap(),
        ["گره", "رأس", "نود"].map(|s| pair("node", s))
    );
    assert!(terms_pairs(&format!("{HEADER}\nnode\tNode\t1\t1\t\n")).is_err());
}

#[test]
fn test_late_invalid_row_returns_no_partial_bans() {
    let text = format!("{HEADER}\nnode\tNode\t1\t1\tگره\nbroken\tخراب\n");
    assert!(terms_pairs(&text).is_err());
}

#[test]
fn test_oversized_and_malformed_csv_fail_before_any_bans() {
    for text in [
        format!("{HEADER}\n{}", "x".repeat(1024 * 1024)),
        format!("{HEADER}\n\"unterminated"),
    ] {
        assert!(terms_pairs(&text).is_err());
        assert!(brief(&text).is_err());
    }
}
