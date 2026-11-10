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
