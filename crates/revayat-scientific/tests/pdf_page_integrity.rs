#[path = "common/pdf.rs"]
mod common;
use common::*;
use lopdf::dictionary;
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
    x.save(document(3));
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
    p::extract_pages(&x.source, &x.output, 2, 3).unwrap();
    let d = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(p::page_ids(&d).unwrap().len(), 2);
    assert!(p::page_text(&d, 1).unwrap().contains("source 2"));
    assert_eq!(fs::read(&x.source).unwrap(), before);
}
#[test]
fn test_encrypted_and_malformed_inputs_leave_output_unchanged() {
    let x = Fixture::new();
    for encrypted in [true, false] {
        let mut d = document(1);
        if encrypted {
            let id = d.add_object(dictionary! {"Filter"=>"Standard","V"=>1,"R"=>2});
            d.trailer.set("Encrypt", id);
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
