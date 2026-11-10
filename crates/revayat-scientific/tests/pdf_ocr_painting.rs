#[path = "common/pdf.rs"]
mod common;
use common::*;
use lopdf::{
    Object,
    content::{Content, Operation},
    dictionary,
};
use revayat_scientific::{pdf as p, pdf_forms as f, pdf_ocr};
use std::fs;
fn layer(paint: Option<&str>) -> lopdf::Document {
    let mut d = document(1);
    let page = pages(&d)[0];
    let mut content = Content::decode(&d.get_page_content(page).unwrap()).unwrap();
    for operation in &mut content.operations {
        if operation.operator == "Tj" {
            operation.operands = vec![Object::string_literal("OCRMarker Untouched source 1")];
        }
    }
    content
        .operations
        .insert(1, Operation::new("Tr", vec![3.into()]));
    d.change_page_content(page, content.encode().unwrap())
        .unwrap();
    if let Some(paint) = paint {
        d.add_page_contents(page, paint.as_bytes().to_vec())
            .unwrap();
    }
    d
}
fn painted_source() -> lopdf::Document {
    let mut doc = blank();
    let page = pages(&doc)[0];
    doc.add_page_contents(
        page,
        b"q 0.2 0.4 0.8 rg 20 20 90 90 re f 0.8 0.1 0.2 RG 3 w 30 150 m 220 150 l S Q".to_vec(),
    )
    .unwrap();
    doc
}
fn refuse(layer: lopdf::Document) {
    let x = Fixture::new();
    x.save(painted_source());
    x.previous();
    let before = fs::read(&x.source).unwrap();
    assert!(pdf_ocr::ocr_with_backend(&x.source, &x.output, |_, _| Ok(layer.clone())).is_err());
    x.preserved();
    assert_eq!(fs::read(&x.source).unwrap(), before);
    assert_eq!(fs::read_dir(x.temp.path()).unwrap().count(), 2);
}
#[test]
fn test_filled_stroked_and_shaded_layers_are_rejected() {
    for paint in [
        "q 0 0 100 100 re f Q",
        "q 0 0 100 100 re S Q",
        "q /Paint sh Q",
    ] {
        refuse(layer(Some(paint)));
    }
}
#[test]
fn test_nested_form_painting_is_rejected() {
    let mut d = layer(None);
    let form=d.add_object(lopdf::Stream::new(dictionary!{"Type"=>"XObject","Subtype"=>"Form","BBox"=>vec![0.into(),0.into(),400.into(),500.into()]},b"0 0 400 500 re f".to_vec()));
    let page = pages(&d)[0];
    let mut resources = f::inherited(&d, page, b"Resources")
        .unwrap()
        .unwrap()
        .as_dict()
        .unwrap()
        .clone();
    resources.set("XObject", dictionary! {"Paint"=>form});
    d.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Resources", resources);
    d.add_page_contents(page, b"q /Paint Do Q".to_vec())
        .unwrap();
    refuse(d);
}
#[test]
fn test_visible_text_and_images_still_fail() {
    refuse(layer(Some("BT 0 Tr /F1 12 Tf (visible) Tj ET")));
    let mut d = layer(None);
    image_page(&mut d, 10, 10, vec![0; 300], false);
    refuse(d);
}
#[test]
fn test_empty_layer_is_not_claimed_as_success() {
    refuse(blank());
}
#[test]
#[ignore = "requires Poppler"]
fn test_valid_invisible_text_keeps_every_pixel_and_source_byte() {
    let x = Fixture::new();
    x.save(painted_source());
    let before = fs::read(&x.source).unwrap();
    let pixels = render(&x.source, 1);
    pdf_ocr::ocr_with_backend(&x.source, &x.output, |_, _| Ok(layer(None))).unwrap();
    assert_eq!(render(&x.output, 1), pixels);
    assert!(p::pdf_text(&x.output).unwrap().contains("OCRMarker"));
    assert!(p::pdf_text(&x.output).unwrap().contains("Untouched source"));
    assert_eq!(
        p::geometry(&p::open_pdf(&x.output, false).unwrap()).unwrap(),
        p::geometry(&p::open_pdf(&x.source, false).unwrap()).unwrap()
    );
    assert_eq!(fs::read(&x.source).unwrap(), before);
}
#[test]
fn test_late_bad_layer_rolls_back_whole_document() {
    let x = Fixture::new();
    let mut d = painted_source();
    let first = pages(&d)[0];
    let parent = d
        .get_dictionary(first)
        .unwrap()
        .get(b"Parent")
        .unwrap()
        .as_reference()
        .unwrap();
    let page = d.add_object(d.get_dictionary(first).unwrap().clone());
    let root = d.get_object_mut(parent).unwrap().as_dict_mut().unwrap();
    root.set(
        "Kids",
        vec![Object::Reference(first), Object::Reference(page)],
    );
    root.set("Count", 2);
    x.save(d);
    x.previous();
    let before = fs::read(&x.source).unwrap();
    let mut calls = Vec::new();
    assert!(
        pdf_ocr::ocr_with_backend(&x.source, &x.output, |index, _| {
            calls.push(index);
            Ok(layer(if index == 0 {
                None
            } else {
                Some("0 0 400 500 re f")
            }))
        })
        .is_err()
    );
    assert_eq!(calls, vec![0, 1]);
    x.preserved();
    assert_eq!(fs::read(&x.source).unwrap(), before);
    assert!(
        !fs::read_dir(x.temp.path())
            .unwrap()
            .any(|entry| entry.unwrap().path().is_dir())
    );
}
#[test]
#[ignore = "requires Poppler"]
fn test_rotation_and_nonzero_crop_keep_geometry_and_pixels() {
    for rotation in [0, 90, 180, 270] {
        let x = Fixture::new();
        let mut d = painted_source();
        let page = pages(&d)[0];
        let page = d.get_object_mut(page).unwrap().as_dict_mut().unwrap();
        page.set(
            "CropBox",
            vec![20.into(), 30.into(), 380.into(), 470.into()],
        );
        page.set("Rotate", rotation);
        x.save(d);
        let before = fs::read(&x.source).unwrap();
        let geometry = p::geometry(&p::open_pdf(&x.source, false).unwrap()).unwrap();
        let pixels = render(&x.source, 1);
        pdf_ocr::ocr_with_backend(&x.source, &x.output, |_, _| {
            let mut d = layer(None);
            d.get_object_mut(pages(&d)[0])?
                .as_dict_mut()?
                .set("MediaBox", vec![0.into(), 0.into(), 360.into(), 440.into()]);
            Ok(d)
        })
        .unwrap();
        assert_eq!(render(&x.output, 1), pixels);
        assert!(p::pdf_text(&x.output).unwrap().contains("OCRMarker"));
        assert!(p::pdf_text(&x.output).unwrap().contains("Untouched source"));
        assert_eq!(
            p::geometry(&p::open_pdf(&x.output, false).unwrap()).unwrap(),
            geometry
        );
        assert_eq!(fs::read(&x.source).unwrap(), before);
    }
}
#[test]
fn test_dimension_mismatch_remains_blocking() {
    let mut d = layer(None);
    d.get_object_mut(pages(&d)[0])
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("MediaBox", vec![0.into(), 0.into(), 410.into(), 500.into()]);
    refuse(d);
}
#[test]
fn test_backend_failure_and_deadline_keep_previous_output() {
    let x = Fixture::new();
    x.save(painted_source());
    x.previous();
    let before = fs::read(&x.source).unwrap();
    for deadline in [false, true] {
        let result = pdf_ocr::ocr_with_backend(&x.source, &x.output, |_, _| {
            if deadline {
                Err(revayat_scientific::runtime::DeadlineExceeded {
                    idle: false,
                    limit: std::time::Duration::from_secs(1),
                }
                .into())
            } else {
                anyhow::bail!("injected backend failure")
            }
        });
        assert!(result.is_err());
        if !deadline {
            assert!(
                result
                    .as_ref()
                    .unwrap_err()
                    .to_string()
                    .contains("injected backend failure")
            );
        }
        if deadline {
            assert!(
                result
                    .unwrap_err()
                    .downcast_ref::<revayat_scientific::runtime::DeadlineExceeded>()
                    .is_some()
            );
        }
        x.preserved();
        assert_eq!(fs::read(&x.source).unwrap(), before);
    }
}
#[test]
fn test_original_alias_refuses_before_backend_invocation() {
    let x = Fixture::new();
    x.save(painted_source());
    let before = fs::read(&x.source).unwrap();
    let mut called = false;
    assert!(
        pdf_ocr::ocr_with_backend(&x.source, &x.source, |_, _| {
            called = true;
            Ok(layer(None))
        })
        .is_err()
    );
    assert!(!called);
    assert_eq!(fs::read(&x.source).unwrap(), before);
}
