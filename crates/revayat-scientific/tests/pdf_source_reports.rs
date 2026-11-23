#[path = "common/pdf.rs"]
mod common;
use revayat_scientific::pdf::{self, PdfBoundary};
use std::fs;

#[test]
fn changed_source_during_table_discovery_preserves_report() {
    let fixture = common::Fixture::new();
    let mut doc = common::blank();
    common::table(&mut doc);
    fixture.save(doc);
    fixture.previous();
    let mut replacement = None;
    let result = revayat_scientific::pdf_extract::extract_tables_observed(
        &fixture.source,
        &fixture.output,
        |boundary, _| {
            if boundary == PdfBoundary::TableDiscovery {
                fixture.save(common::document(2));
                replacement = Some(fs::read(&fixture.source)?);
            }
            Ok(())
        },
    );
    let replacement = replacement.expect("the source replacement boundary must be reached");
    assert!(result.is_err(), "table report used a changed source");
    fixture.preserved();
    assert_eq!(fs::read(&fixture.source).unwrap(), replacement);
    assert_eq!(fs::read_dir(fixture.temp.path()).unwrap().count(), 2);
}

#[test]
fn changed_source_during_report_publication_preserves_previous_report() {
    let fixture = common::Fixture::new();
    fixture.save(common::document(1));
    fixture.previous();
    let mut replacement = None;
    let result = pdf::write_report_observed(
        &serde_json::json!({"page_count": 1}),
        &fixture.output,
        std::slice::from_ref(&fixture.source),
        |boundary, _| {
            if boundary == PdfBoundary::StageWritten {
                fixture.save(common::document(2));
                replacement = Some(fs::read(&fixture.source)?);
            }
            Ok(())
        },
    );
    let replacement = replacement.expect("the source replacement boundary must be reached");
    assert!(result.is_err(), "report publication used a changed source");
    fixture.preserved();
    assert_eq!(fs::read(&fixture.source).unwrap(), replacement);
    assert_eq!(fs::read_dir(fixture.temp.path()).unwrap().count(), 2);
}

#[test]
fn substituted_valid_json_preserves_previous_report() {
    let fixture = common::Fixture::new();
    fixture.save(common::document(1));
    fixture.previous();
    let original = fs::read(&fixture.source).unwrap();
    let mut reached = false;
    let result = pdf::write_report_observed(
        &serde_json::json!({"page_count": 1, "value": "-0.25 mV"}),
        &fixture.output,
        std::slice::from_ref(&fixture.source),
        |boundary, path| {
            if boundary == PdfBoundary::StageWritten {
                fs::write(path, b"null\n")?;
                reached = true;
            }
            Ok(())
        },
    );
    assert!(reached);
    assert!(
        result.is_err(),
        "different valid JSON was published as the verified report"
    );
    fixture.preserved();
    assert_eq!(fs::read(&fixture.source).unwrap(), original);
    assert_eq!(fs::read_dir(fixture.temp.path()).unwrap().count(), 2);
}

#[test]
fn substituted_pdf_with_equal_geometry_preserves_previous_delivery() {
    let fixture = common::Fixture::new();
    let mut doc = common::document(1);
    fixture.save(doc.clone());
    fixture.previous();
    let original = fs::read(&fixture.source).unwrap();
    let geometry = pdf::geometry(&doc).unwrap();
    let mut reached = false;
    let result = pdf::save_document_observed(
        &mut doc,
        &fixture.output,
        std::slice::from_ref(&fixture.source),
        &geometry,
        |_| Ok(()),
        |boundary, path| {
            if boundary == PdfBoundary::StageWritten {
                let mut replacement = common::blank();
                replacement.change_page_content(
                    common::pages(&replacement)[0],
                    b"BT /F1 12 Tf 30 250 Td (Substituted scientific result) Tj ET".to_vec(),
                )?;
                replacement.save(path)?;
                reached = true;
            }
            Ok(())
        },
    );
    assert!(reached);
    assert!(
        result.is_err(),
        "different PDF content passed the geometry-only check"
    );
    fixture.preserved();
    assert_eq!(fs::read(&fixture.source).unwrap(), original);
    assert_eq!(fs::read_dir(fixture.temp.path()).unwrap().count(), 2);
}
