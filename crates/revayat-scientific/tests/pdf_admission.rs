#[path = "common/pdf.rs"]
mod common;
use common::*;
use lopdf::{Object, dictionary};
use revayat_scientific::{pdf as p, pdf_navigation as n};
use std::fs;
#[test]
fn test_all_transforms_use_the_same_encryption_signature_xfa_admission() {
    for kind in [
        "signature-field",
        "signature-dictionary",
        "xfa",
        "encryption",
    ] {
        let x = Fixture::new();
        let mut d = document(3);
        match kind {
            "signature-field" => {
                let id = textfield(&mut d, "Signature");
                d.get_object_mut(id)
                    .unwrap()
                    .as_dict_mut()
                    .unwrap()
                    .set("FT", "Sig");
            }
            "signature-dictionary" => {
                d.add_object(dictionary!{"Type"=>"Sig","ByteRange"=>vec![0.into(),10.into(),20.into(),30.into()]});
            }
            "xfa" => d.catalog_mut().unwrap().set(
                "AcroForm",
                dictionary! {"XFA"=>Object::string_literal("unsupported")},
            ),
            _ => {
                let id = d.add_object(dictionary! {"Filter"=>"Standard","V"=>1,"R"=>2});
                d.trailer.set("Encrypt", id);
            }
        }
        x.save(d);
        let before = fs::read(&x.source).unwrap();
        x.previous();
        assert!(p::open_pdf(&x.source, true).is_err());
        assert!(p::extract_pages(&x.source, &x.output, 1, 2).is_err());
        assert!(p::merge_pdfs(std::slice::from_ref(&x.source), &x.output).is_err());
        x.preserved();
        assert_eq!(fs::read(&x.source).unwrap(), before);
    }
}
#[test]
fn test_parser_repaired_source_is_not_silently_certified() {
    let x = Fixture::new();
    x.save(document(1));
    let raw = fs::read(&x.source).unwrap();
    let offset = raw.windows(9).position(|w| w == b"startxref").unwrap();
    fs::write(&x.source, [&raw[..offset], b"%%EOF\n"].concat()).unwrap();
    x.previous();
    assert!(p::extract_pages(&x.source, &x.output, 1, 1).is_err());
    x.preserved();
}
#[test]
#[ignore = "requires Poppler"]
fn test_valid_contiguous_range_keeps_geometry_pixels_and_shared_resources() {
    let x = Fixture::new();
    let mut d = document(3);
    link(
        &mut d,
        1,
        2,
        vec![
            Object::Name(b"XYZ".to_vec()),
            30.into(),
            50.into(),
            Object::Null,
        ],
    );
    x.save(d);
    let before = fs::read(&x.source).unwrap();
    p::extract_pages(&x.source, &x.output, 2, 3).unwrap();
    let output = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(p::page_ids(&output).unwrap().len(), 2);
    assert_eq!(
        n::links(&output, 0, 1, 0).unwrap()[0]["navigation"]["direct"]["page"],
        1
    );
    for n in 1..=2 {
        assert_eq!(render(&x.output, n), render(&x.source, n + 1));
    }
    assert_eq!(fs::read(&x.source).unwrap(), before);
}
#[test]
fn test_late_write_failure_preserves_existing_output() {
    let x = Fixture::new();
    let mut d = document(2);
    x.save(d.clone());
    x.previous();
    let mut invalid = p::geometry(&d).unwrap();
    invalid[1].cropbox[2] = 1.;
    assert!(
        p::save_document(
            &mut d,
            &x.output,
            std::slice::from_ref(&x.source),
            &invalid,
            |_| Ok(())
        )
        .is_err()
    );
    x.preserved();
    assert_eq!(fs::read_dir(x.temp.path()).unwrap().count(), 2);
}
#[test]
fn test_admission_limits_apply_before_publication() {
    let x = Fixture::new();
    let mut d = document(1);
    let page = pages(&d)[0];
    d.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Rotate", 45);
    x.save(d);
    x.previous();
    assert!(p::extract_pages(&x.source, &x.output, 1, 1).is_err());
    x.preserved();
    let mut d = document(1);
    d.objects.insert((200001, 0), Object::Integer(1));
    d.max_id = 200001;
    x.save(d);
    assert!(p::open_pdf(&x.source, false).is_err());
    x.preserved();
}
#[test]
fn test_memory_mode_and_ordinary_nontransform_inspection_remain_supported() {
    let x = Fixture::new();
    let mut d = document(1);
    let id = textfield(&mut d, "UnsignedSignature");
    d.get_object_mut(id)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("FT", "Sig");
    x.save(d);
    assert!(p::open_pdf(&x.source, false).is_ok());
    let report = p::inspect_pdf(&x.source).unwrap();
    assert_eq!(report["signature_bearing"], true);
    assert_eq!(report["pages"].as_array().unwrap().len(), 1);
}
#[test]
fn test_public_pages_command_refuses_restricted_input() {
    let x = Fixture::new();
    let mut d = document(1);
    d.catalog_mut().unwrap().set(
        "AcroForm",
        dictionary! {"XFA"=>Object::string_literal("unsupported")},
    );
    x.save(d);
    x.previous();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args([
            "pages",
            x.source.to_str().unwrap(),
            x.output.to_str().unwrap(),
            "1",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    x.preserved();
}
#[test]
fn test_shared_resource_identity_and_full_page_boxes_survive() {
    let x = Fixture::new();
    let mut d = document(3);
    for id in pages(&d) {
        let p = d.get_object_mut(id).unwrap().as_dict_mut().unwrap();
        p.set(
            "CropBox",
            vec![10.into(), 20.into(), 390.into(), 480.into()],
        );
        p.set(
            "BleedBox",
            vec![5.into(), 10.into(), 395.into(), 490.into()],
        );
        p.set(
            "TrimBox",
            vec![15.into(), 25.into(), 385.into(), 475.into()],
        );
        p.set("ArtBox", vec![20.into(), 30.into(), 380.into(), 470.into()]);
        p.set("Rotate", 90);
    }
    x.save(d);
    p::extract_pages(&x.source, &x.output, 1, 2).unwrap();
    let doc = p::open_pdf(&x.output, false).unwrap();
    let ids = pages(&doc);
    let a = doc.get_dictionary(ids[0]).unwrap();
    let b = doc.get_dictionary(ids[1]).unwrap();
    assert_eq!(a.get(b"Resources").unwrap(), b.get(b"Resources").unwrap());
    for key in [b"CropBox".as_slice(), b"BleedBox", b"TrimBox", b"ArtBox"] {
        assert_eq!(a.get(key).unwrap(), b.get(key).unwrap());
    }
    assert_eq!(p::geometry(&doc).unwrap()[0].rect, [0., 0., 460., 380.]);
}

#[test]
fn preview_batch_preflights_every_destination_before_replacing_any_sample() {
    let x = Fixture::new();
    x.save(document(3));
    let prefix = x.temp.path().join("sample");
    let first = x.temp.path().join("sample-1.png");
    let last = x.temp.path().join("sample-3.png");
    fs::write(&first, b"previous approved preview").unwrap();
    fs::hard_link(&x.source, &last).unwrap();
    let source = fs::read(&x.source).unwrap();
    assert!(p::render_sample_set(&x.source, &prefix).is_err());
    assert_eq!(fs::read(first).unwrap(), b"previous approved preview");
    assert_eq!(fs::read(&x.source).unwrap(), source);
    assert!(!x.temp.path().join("sample-2.png").exists());
}
