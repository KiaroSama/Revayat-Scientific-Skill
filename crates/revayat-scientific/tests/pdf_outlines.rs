#[path = "common/pdf.rs"]
mod common;
use common::*;
use lopdf::{Object, dictionary};
use revayat_scientific::{pdf as p, pdf_navigation as n};
use std::fs;
#[test]
fn test_destinations_styles_and_uri_actions_survive() {
    let x = Fixture::new();
    let mut d = document(2);
    outline(&mut d, "XYZ", vec![90.into(), 210.into(), 1.25.into()]);
    let expected = n::outlines(&d, 0).unwrap().0;
    x.save(d);
    p::merge_pdfs(std::slice::from_ref(&x.source), &x.output).unwrap();
    let out = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(n::outlines(&out, 0).unwrap().0, expected);
}
#[test]
#[ignore = "requires Poppler"]
fn test_rotations_crop_offsets_and_page_pixels_are_unchanged() {
    for rotation in [0, 90, 180, 270] {
        let x = Fixture::new();
        let mut d = document(2);
        for id in pages(&d) {
            let p = d.get_object_mut(id).unwrap().as_dict_mut().unwrap();
            p.set("Rotate", rotation);
            p.set(
                "CropBox",
                vec![30.into(), 40.into(), 370.into(), 460.into()],
            );
        }
        outline(&mut d, "XYZ", vec![90.into(), 210.into(), 1.25.into()]);
        x.save(d);
        p::merge_pdfs(std::slice::from_ref(&x.source), &x.output).unwrap();
        assert_eq!(
            p::geometry(&p::open_pdf(&x.source, false).unwrap()).unwrap(),
            p::geometry(&p::open_pdf(&x.output, false).unwrap()).unwrap()
        );
        for n in 1..=2 {
            assert_eq!(render(&x.source, n), render(&x.output, n));
        }
    }
}
#[test]
fn test_standard_fit_destinations_and_null_coordinates_are_preserved() {
    for (mode, args) in [
        ("XYZ", vec![Object::Null, 220.into(), Object::Null]),
        ("Fit", vec![]),
        ("FitH", vec![240.into()]),
        ("FitV", vec![Object::Null]),
        ("FitR", vec![20.into(), 30.into(), 220.into(), 330.into()]),
        ("FitB", vec![]),
        ("FitBH", vec![Object::Null]),
        ("FitBV", vec![30.into()]),
    ] {
        let x = Fixture::new();
        let mut d = document(2);
        outline(&mut d, mode, args);
        let expected = n::outlines(&d, 0).unwrap().0;
        x.save(d);
        p::merge_pdfs(std::slice::from_ref(&x.source), &x.output).unwrap();
        assert_eq!(
            n::outlines(&p::open_pdf(&x.output, false).unwrap(), 0)
                .unwrap()
                .0,
            expected
        );
    }
}
#[test]
fn test_repeated_source_remaps_each_copy_and_preserves_inputs() {
    let x = Fixture::new();
    let mut d = document(2);
    outline(&mut d, "Fit", vec![]);
    x.save(d);
    let before = fs::read(&x.source).unwrap();
    p::merge_pdfs(&[x.source.clone(), x.source.clone()], &x.output).unwrap();
    let out = p::open_pdf(&x.output, false).unwrap();
    let rows = n::outlines(&out, 0).unwrap().0;
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0]["navigation"]["direct"]["page"], 1);
    assert_eq!(rows[2]["navigation"]["direct"]["page"], 3);
    assert_eq!(before, fs::read(&x.source).unwrap());
}
#[test]
fn test_no_outline_is_not_fabricated() {
    let x = Fixture::new();
    x.save(document(2));
    p::merge_pdfs(std::slice::from_ref(&x.source), &x.output).unwrap();
    assert!(
        n::outlines(&p::open_pdf(&x.output, false).unwrap(), 0)
            .unwrap()
            .0
            .is_empty()
    );
}
#[test]
fn test_advanced_or_chained_actions_refuse_before_publication() {
    for chained in [false, true] {
        let x = Fixture::new();
        let mut d = document(2);
        let id = outline(&mut d, "Fit", vec![]);
        let mut action = if chained {
            dictionary! {"S"=>"URI","URI"=>Object::string_literal("https://example.org"),"Next"=>dictionary!{"S"=>"Named","N"=>"FirstPage"}}
        } else {
            dictionary! {"S"=>"Named","N"=>"FirstPage"}
        };
        action.set("Type", "Action");
        let item = d.get_object_mut(id).unwrap().as_dict_mut().unwrap();
        item.remove(b"Dest");
        item.set("A", action);
        x.save(d);
        x.previous();
        assert!(p::merge_pdfs(std::slice::from_ref(&x.source), &x.output).is_err());
        x.preserved();
    }
}
#[test]
fn test_failed_staged_outline_verification_preserves_destination() {
    let x = Fixture::new();
    let mut d = document(2);
    outline(&mut d, "Fit", vec![]);
    x.save(d.clone());
    x.previous();
    let expected = p::geometry(&d).unwrap();
    assert!(
        p::save_document(
            &mut d,
            &x.output,
            std::slice::from_ref(&x.source),
            &expected,
            |_| anyhow::bail!("injected outline verification failure")
        )
        .is_err()
    );
    x.preserved();
}
