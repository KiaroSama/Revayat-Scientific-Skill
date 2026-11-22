#[path = "common/pdf.rs"]
mod common;
use common::*;
#[path = "support/pdf_encryption.rs"]
mod encryption;
use revayat_scientific::pdf as p;
use std::fs;
#[test]
fn test_same_path_keeps_complete_source() {
    let x = Fixture::new();
    x.save(document(3));
    let before = fs::read(&x.source).unwrap();
    assert!(p::extract_pages(&x.source, &x.source, 1, 1).is_err());
    assert_eq!(fs::read(&x.source).unwrap(), before);
    assert_eq!(
        p::page_ids(&p::open_pdf(&x.source, false).unwrap())
            .unwrap()
            .len(),
        3
    );
}
#[test]
fn test_range_validation_aliases_and_rollback() {
    let x = Fixture::new();
    let mut source = document(3);
    for (index, page) in pages(&source).into_iter().enumerate() {
        source
            .get_object_mut(page)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set(
                "MediaBox",
                vec![
                    0.into(),
                    0.into(),
                    (250 + index as i64 * 10).into(),
                    400.into(),
                ],
            );
    }
    x.save(source);
    let before = fs::read(&x.source).unwrap();
    x.previous();
    for range in ["0", "-1", "1.5", "2-1", "1-4", "nan"] {
        assert!(
            p::pages_cli(&[
                x.source.to_string_lossy().into(),
                x.output.to_string_lossy().into(),
                range.into()
            ])
            .is_err()
        );
        x.preserved();
    }
    let alias = x.temp.path().join("hardlink.pdf");
    fs::hard_link(&x.source, &alias).unwrap();
    assert!(p::extract_pages(&x.source, &alias, 1, 1).is_err());
    let mut d = p::open_pdf(&x.source, true).unwrap();
    let g = p::geometry(&d).unwrap();
    assert!(
        p::save_document(
            &mut d,
            &x.output,
            std::slice::from_ref(&x.source),
            &g,
            |_| anyhow::bail!("injected late failure")
        )
        .is_err()
    );
    x.preserved();
    let mut reached = false;
    assert!(
        p::extract_pages_observed(
            &x.source,
            &x.output,
            1,
            2,
            p::AdmissionLimits::default(),
            |boundary, _| {
                if boundary
                    == p::PdfBoundary::Publication(
                        revayat_scientific::publication::Boundary::BeforeCommit,
                    )
                {
                    reached = true;
                    anyhow::bail!("injected replacement failure");
                }
                Ok(())
            }
        )
        .is_err()
    );
    assert!(reached);
    x.preserved();
    p::extract_pages(&x.source, &x.output, 2, 3).unwrap();
    let d = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(p::page_ids(&d).unwrap().len(), 2);
    assert_eq!(p::page_text(&d, 1).unwrap().trim(), "Untouched source 2");
    assert_eq!(p::page_text(&d, 2).unwrap().trim(), "Untouched source 3");
    assert_eq!(
        p::geometry(&d)
            .unwrap()
            .iter()
            .map(|page| page.rect[2])
            .collect::<Vec<_>>(),
        vec![260.0, 270.0]
    );
    assert_eq!(fs::read(&x.source).unwrap(), before);
    assert!(
        !fs::read_dir(x.temp.path())
            .unwrap()
            .any(|entry| entry.unwrap().path().is_dir())
    );
}
#[test]
fn test_encrypted_and_malformed_inputs_leave_output_unchanged() {
    let x = Fixture::new();
    for encrypted in [true, false] {
        let mut d = document(1);
        if encrypted {
            encryption::encrypt(&mut d, "fixture-user");
            x.save(d);
        } else {
            fs::write(&x.source, b"not a PDF").unwrap();
        }
        x.previous();
        assert!(p::extract_pages(&x.source, &x.output, 1, 1).is_err());
        x.preserved();
        assert_eq!(fs::read_dir(x.temp.path()).unwrap().count(), 2);
    }
}

#[test]
fn test_changed_source_during_extraction_preserves_delivery() {
    for boundary in [
        p::PdfBoundary::StageWritten,
        p::PdfBoundary::Publication(revayat_scientific::publication::Boundary::BeforeCommit),
    ] {
        let fixture = Fixture::new();
        fixture.save(document(3));
        fixture.previous();
        let mut replacement = None;
        let result = p::extract_pages_observed(
            &fixture.source,
            &fixture.output,
            1,
            1,
            p::AdmissionLimits::default(),
            |event, _| {
                if event == boundary {
                    fixture.save(document(2));
                    replacement = Some(fs::read(&fixture.source)?);
                }
                Ok(())
            },
        );
        let replacement = replacement.expect("the source replacement boundary must be reached");
        assert!(
            result.is_err(),
            "changed source was published at {boundary:?}"
        );
        fixture.preserved();
        assert_eq!(fs::read(&fixture.source).unwrap(), replacement);
        assert_eq!(fs::read_dir(fixture.temp.path()).unwrap().count(), 2);
    }
}

#[test]
fn test_changed_merge_input_preserves_delivery() {
    let fixture = Fixture::new();
    fixture.save(document(1));
    fixture.previous();
    let second = fixture.temp.path().join("second.pdf");
    document(3).save(&second).unwrap();
    let original = fs::read(&fixture.source).unwrap();
    let mut replacement = None;
    let result = p::merge_pdfs_observed(
        &[fixture.source.clone(), second.clone()],
        &fixture.output,
        |boundary, _| {
            if boundary == p::PdfBoundary::StageWritten {
                document(2).save(&second)?;
                replacement = Some(fs::read(&second)?);
            }
            Ok(())
        },
    );
    let replacement = replacement.expect("the merge source replacement boundary must be reached");
    assert!(result.is_err(), "changed merge input was published");
    fixture.preserved();
    assert_eq!(fs::read(&fixture.source).unwrap(), original);
    assert_eq!(fs::read(&second).unwrap(), replacement);
    assert_eq!(fs::read_dir(fixture.temp.path()).unwrap().count(), 3);
}

#[test]
fn test_changed_fill_input_preserves_delivery() {
    let fixture = Fixture::new();
    let mut doc = document(1);
    textfield(&mut doc, "Quantity");
    fixture.save(doc);
    fixture.previous();
    let original = fs::read(&fixture.source).unwrap();
    let field_source = fixture.temp.path().join("fields.json");
    fs::write(&field_source, br#"{"Quantity":"23.5 C"}"#).unwrap();
    let values = serde_json::json!({"Quantity":"23.5 C"});
    let mut reached = false;
    let result = p::fill_pdf_observed(
        &fixture.source,
        &fixture.output,
        values.as_object().unwrap(),
        std::slice::from_ref(&field_source),
        |boundary, _| {
            if boundary == p::PdfBoundary::StageWritten {
                reached = true;
                fs::write(&field_source, br#"{"Quantity":"-0.25 mV"}"#)?;
            }
            Ok(())
        },
    );
    assert!(
        reached,
        "the field input replacement boundary must be reached"
    );
    assert!(result.is_err(), "changed fill input was published");
    fixture.preserved();
    assert_eq!(fs::read(&fixture.source).unwrap(), original);
    assert_eq!(
        fs::read(&field_source).unwrap(),
        br#"{"Quantity":"-0.25 mV"}"#
    );
    assert_eq!(fs::read_dir(fixture.temp.path()).unwrap().count(), 3);
}
