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
    let title = outline(&mut d, "XYZ", vec![90.into(), 210.into(), 1.25.into()]);
    let mut text = vec![0xfe, 0xff];
    for unit in "عنوان علمی".encode_utf16() {
        text.extend(unit.to_be_bytes());
    }
    d.get_object_mut(title).unwrap().as_dict_mut().unwrap().set(
        "Title",
        Object::String(text, lopdf::StringFormat::Hexadecimal),
    );
    let expected = n::outlines(&d, 0).unwrap().0;
    x.save(d);
    let prefix = x.temp.path().join("prefix.pdf");
    document(1).save(&prefix).unwrap();
    let prefix_before = fs::read(&prefix).unwrap();
    let before = fs::read(&x.source).unwrap();
    p::merge_pdfs(&[prefix.clone(), x.source.clone()], &x.output).unwrap();
    let out = p::open_pdf(&x.output, false).unwrap();
    let actual = n::outlines(&out, 0).unwrap().0;
    let mut shifted = expected;
    shifted[0]["navigation"]["direct"]["page"] = serde_json::json!(2);
    assert_eq!(actual, shifted);
    assert_eq!(actual.len(), 2);
    assert_eq!(actual[0]["level"], 1);
    assert_eq!(actual[1]["level"], 2);
    assert_eq!(actual[0]["navigation"]["direct"]["page"], 2);
    assert_eq!(actual[0]["navigation"]["direct"]["fit"], "XYZ");
    assert_eq!(
        actual[0]["navigation"]["direct"]["args"],
        serde_json::json!([90.0, 210.0, 1.25])
    );
    assert_eq!(
        actual[0]["attributes"]["Title"]["string_hex"],
        "feff06390646064806270646002006390644064506cc"
    );
    assert_eq!(actual[0]["attributes"]["F"], 3);
    assert_eq!(actual[0]["attributes"]["Count"], -1);
    assert_eq!(
        actual[0]["attributes"]["C"],
        serde_json::json!([0.2f32, 0.4f32, 0.6f32])
    );
    assert_eq!(actual[1]["navigation"]["uri"]["IsMap"], true);
    assert_eq!(
        actual[1]["navigation"]["uri"]["URI"]["string_hex"],
        serde_json::json!(
            b"https://example.org/paper?q=1&v=2"
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    );
    assert_eq!(fs::read(&x.source).unwrap(), before);
    assert_eq!(fs::read(prefix).unwrap(), prefix_before);
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
        let before = fs::read(&x.source).unwrap();
        let prefix = x.temp.path().join("prefix.pdf");
        document(1).save(&prefix).unwrap();
        p::merge_pdfs(&[prefix, x.source.clone()], &x.output).unwrap();
        let original = p::open_pdf(&x.source, false).unwrap();
        let output = p::open_pdf(&x.output, false).unwrap();
        let source_geometry = p::geometry(&original).unwrap();
        let selected_geometry = p::geometry(&output).unwrap();
        for n in 1..=2 {
            assert_eq!(render(&x.source, n), render(&x.output, n + 1));
            assert_eq!(source_geometry[n - 1].rect, selected_geometry[n].rect);
            assert_eq!(source_geometry[n - 1].cropbox, selected_geometry[n].cropbox);
            assert_eq!(
                source_geometry[n - 1].rotation,
                selected_geometry[n].rotation
            );
        }
        let destination = &n::outlines(&output, 0).unwrap().0[0]["navigation"]["direct"];
        assert_eq!(destination["page"], 2);
        assert_eq!(destination["args"], serde_json::json!([90.0, 210.0, 1.25]));
        assert_eq!(fs::read(&x.source).unwrap(), before);
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
        let literal_args: Vec<_> = args
            .iter()
            .map(|arg| match arg {
                Object::Null => serde_json::Value::Null,
                Object::Integer(number) => serde_json::json!(*number as f64),
                _ => panic!("fixture only uses null or integer coordinates"),
            })
            .collect();
        outline(&mut d, mode, args);
        let mut expected = n::outlines(&d, 0).unwrap().0;
        expected[0]["navigation"]["direct"]["page"] = serde_json::json!(2);
        x.save(d);
        let prefix = x.temp.path().join("prefix.pdf");
        document(1).save(&prefix).unwrap();
        p::merge_pdfs(&[prefix, x.source.clone()], &x.output).unwrap();
        let output = p::open_pdf(&x.output, false).unwrap();
        let rows = n::outlines(&output, 0).unwrap().0;
        assert_eq!(rows[0]["navigation"]["direct"]["fit"], mode);
        assert_eq!(
            rows[0]["navigation"]["direct"]["args"],
            serde_json::json!(literal_args)
        );
        assert_eq!(rows[0]["navigation"]["direct"]["page"], 2);
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
    for (mode, args) in [
        ("Fit", vec![]),
        ("XYZ", vec![90.into(), 210.into(), 1.25.into()]),
    ] {
        let x = Fixture::new();
        let mut d = document(2);
        outline(&mut d, mode, args);
        x.save(d);
        let before = fs::read(&x.source).unwrap();
        p::merge_pdfs(&[x.source.clone(), x.source.clone()], &x.output).unwrap();
        let out = p::open_pdf(&x.output, false).unwrap();
        let rows = n::outlines(&out, 0).unwrap().0;
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0]["navigation"]["direct"]["page"], 1);
        assert_eq!(rows[2]["navigation"]["direct"]["page"], 3);
        assert_eq!(
            rows[0]["navigation"]["direct"]["args"],
            rows[2]["navigation"]["direct"]["args"]
        );
        assert_eq!(before, fs::read(&x.source).unwrap());
    }
}
#[test]
fn test_no_outline_is_not_fabricated() {
    let x = Fixture::new();
    x.save(document(2));
    let prefix = x.temp.path().join("prefix.pdf");
    document(1).save(&prefix).unwrap();
    p::merge_pdfs(&[prefix, x.source.clone()], &x.output).unwrap();
    assert_eq!(pages(&p::open_pdf(&x.output, false).unwrap()).len(), 3);
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
        let before = fs::read(&x.source).unwrap();
        assert!(p::merge_pdfs(std::slice::from_ref(&x.source), &x.output).is_err());
        x.preserved();
        assert_eq!(fs::read(&x.source).unwrap(), before);
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
    let before = fs::read(&x.source).unwrap();
    let mut reached = false;
    assert!(
        p::merge_pdfs_observed(
            std::slice::from_ref(&x.source),
            &x.output,
            |boundary, path| {
                if boundary == p::PdfBoundary::StageWritten {
                    reached = true;
                    let mut saved = p::open_pdf(path, false)?;
                    saved.catalog_mut()?.remove(b"Outlines");
                    saved.save(path)?;
                }
                Ok(())
            }
        )
        .unwrap_err()
        .to_string()
        .contains("changed outlines")
    );
    assert!(reached);
    x.preserved();
    assert_eq!(fs::read(&x.source).unwrap(), before);
    assert!(
        !fs::read_dir(x.temp.path())
            .unwrap()
            .any(|entry| entry.unwrap().path().is_dir())
    );
}
