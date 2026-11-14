#[path = "common/pdf.rs"]
mod common;
use common::*;
use lopdf::{Object, dictionary};
use revayat_scientific::{pdf as p, pdf_navigation as n};
use std::fs;
#[path = "support/pdf_encryption.rs"]
mod encryption;
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
                let signature = d.add_object(dictionary!{"Type"=>"Sig","ByteRange"=>vec![0.into(),10.into(),20.into(),30.into()]});
                d.catalog_mut()
                    .unwrap()
                    .set("Perms", dictionary! {"DocMDP"=>signature});
                let perms = d
                    .catalog()
                    .unwrap()
                    .get(b"Perms")
                    .unwrap()
                    .as_dict()
                    .unwrap();
                assert_eq!(
                    perms.get(b"DocMDP").unwrap().as_reference().unwrap(),
                    signature
                );
                assert_eq!(
                    d.get_dictionary(signature)
                        .unwrap()
                        .get(b"ByteRange")
                        .unwrap(),
                    &Object::Array(vec![0.into(), 10.into(), 20.into(), 30.into()])
                );
            }
            "xfa" => d.catalog_mut().unwrap().set(
                "AcroForm",
                dictionary! {"XFA"=>Object::string_literal("unsupported")},
            ),
            _ => encryption::encrypt(&mut d, ""),
        }
        x.save(d);
        let before = fs::read(&x.source).unwrap();
        if kind == "encryption" {
            let encrypted = lopdf::Document::load_mem(&before).unwrap();
            assert_eq!(pages(&encrypted).len(), 3);
            assert!(encrypted.trailer.has(b"Encrypt") || encrypted.encryption_state.is_some());
        }
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
    let repaired = [&raw[..offset], b"%%EOF\n"].concat();
    let recovered = lopdf::Document::load_mem(&repaired).unwrap();
    assert!(recovered.xref_recovery.is_some());
    assert_eq!(pages(&recovered).len(), 1);
    fs::write(&x.source, &repaired).unwrap();
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
    let ids = pages(&d);
    for (index, id) in ids.iter().enumerate() {
        d.get_object_mut(*id).unwrap().as_dict_mut().unwrap().set(
            "MediaBox",
            vec![
                0.into(),
                0.into(),
                (250 + index as i64 * 20).into(),
                400.into(),
            ],
        );
    }
    x.save(d);
    let before = fs::read(&x.source).unwrap();
    let original = p::open_pdf(&x.source, false).unwrap();
    p::extract_pages(&x.source, &x.output, 2, 3).unwrap();
    let output = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(p::page_ids(&output).unwrap().len(), 2);
    assert_eq!(
        n::links(&output, 0, 1, 0).unwrap()[0]["navigation"]["direct"]["page"],
        1
    );
    let source_geometry = p::geometry(&original).unwrap();
    let selected_geometry = p::geometry(&output).unwrap();
    for n in 1..=2 {
        assert_eq!(render(&x.output, n), render(&x.source, n + 1));
        assert_eq!(
            p::page_text(&output, n).unwrap(),
            p::page_text(&original, n + 1).unwrap()
        );
        assert_eq!(selected_geometry[n - 1].rect, source_geometry[n].rect);
        assert_eq!(
            selected_geometry[n - 1].mediabox,
            source_geometry[n].mediabox
        );
    }
    let navigation = n::links(&output, 0, 1, 0).unwrap();
    assert_eq!(navigation.len(), 1);
    assert_eq!(
        navigation[0]["navigation"]["direct"]["args"],
        serde_json::json!([30.0, 50.0, null])
    );
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
    let before = fs::read(&x.source).unwrap();
    let mut reached = false;
    let result = p::extract_pages_observed(
        &x.source,
        &x.output,
        1,
        1,
        p::AdmissionLimits::default(),
        |boundary, _| {
            if boundary
                == p::PdfBoundary::Publication(
                    revayat_scientific::publication::Boundary::BeforeCommit,
                )
            {
                reached = true;
                anyhow::bail!("injected commit failure");
            }
            Ok(())
        },
    );
    assert!(reached);
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("injected commit failure")
    );
    x.preserved();
    assert_eq!(fs::read(&x.source).unwrap(), before);
    assert_eq!(fs::read_dir(x.temp.path()).unwrap().count(), 2);
}
#[test]
fn test_admission_limits_apply_before_publication() {
    let x = Fixture::new();
    x.save(document(3));
    let source = fs::read(&x.source).unwrap();
    x.previous();
    let defaults = p::AdmissionLimits::default();
    assert!(p::open_pdf_with_limits(&x.source, true, defaults).is_ok());
    assert_eq!(
        (defaults.max_bytes, defaults.max_pages, defaults.max_objects),
        (512 * 1024 * 1024, 10000, 200000)
    );
    for limits in [
        p::AdmissionLimits {
            max_bytes: 1,
            ..defaults
        },
        p::AdmissionLimits {
            max_pages: 2,
            ..defaults
        },
        p::AdmissionLimits {
            max_objects: 1,
            ..defaults
        },
    ] {
        assert!(p::open_pdf_with_limits(&x.source, true, limits).is_err());
        let mut published = false;
        assert!(
            p::extract_pages_observed(&x.source, &x.output, 1, 1, limits, |_, _| {
                published = true;
                Ok(())
            })
            .is_err()
        );
        assert!(!published);
        x.preserved();
        assert_eq!(fs::read(&x.source).unwrap(), source);
    }
    assert!(
        !fs::read_dir(x.temp.path())
            .unwrap()
            .any(|entry| entry.unwrap().path().is_dir())
    );
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
    let mut d = document(3);
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
    assert_eq!(report["pages"].as_array().unwrap().len(), 3);
    assert!(p::open_pdf(&x.source, true).is_err());
}
#[test]
fn test_public_pages_command_refuses_restricted_input() {
    let x = Fixture::new();
    let mut d = document(1);
    encryption::encrypt(&mut d, "");
    x.save(d);
    let before = fs::read(&x.source).unwrap();
    x.previous();
    let mut spec =
        revayat_scientific::runtime::CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific"));
    spec.args = vec![
        "pages".into(),
        x.source.as_os_str().to_owned(),
        x.output.as_os_str().to_owned(),
        "1".into(),
    ];
    spec.timeout = std::time::Duration::from_secs(20);
    spec.env.insert(
        "REVAYAT_LOG_DIR".into(),
        x.temp.path().join("logs").into_os_string(),
    );
    let result = revayat_scientific::runtime::run(&spec).unwrap();
    assert!(!result.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("wrote "));
    x.preserved();
    assert_eq!(fs::read(&x.source).unwrap(), before);
}
#[test]
#[ignore = "requires Poppler"]
fn test_shared_resource_identity_and_full_page_boxes_survive() {
    let x = Fixture::new();
    let mut d = document(4);
    image_page(&mut d, 20, 20, vec![150; 20 * 20 * 3], false);
    let ids = pages(&d);
    let shared = d
        .get_dictionary(ids[0])
        .unwrap()
        .get(b"Resources")
        .unwrap()
        .clone();
    let image_stream = d.get_page_content(ids[0]);
    for (index, id) in ids.into_iter().enumerate() {
        d.change_page_content(id, image_stream.clone()).unwrap();
        let page = d.get_object_mut(id).unwrap().as_dict_mut().unwrap();
        page.set("Resources", shared.clone());
        page.set(
            "CropBox",
            vec![10.into(), 20.into(), 390.into(), 480.into()],
        );
        page.set(
            "BleedBox",
            vec![12.into(), 22.into(), 388.into(), 478.into()],
        );
        page.set(
            "TrimBox",
            vec![15.into(), 25.into(), 385.into(), 475.into()],
        );
        page.set("ArtBox", vec![20.into(), 30.into(), 380.into(), 470.into()]);
        page.set("Rotate", (index as i64) * 90);
    }
    x.save(d);
    let before = fs::read(&x.source).unwrap();
    let original = p::open_pdf(&x.source, false).unwrap();
    p::extract_pages(&x.source, &x.output, 1, 4).unwrap();
    let doc = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(p::geometry(&doc).unwrap(), p::geometry(&original).unwrap());
    let mut images = std::collections::HashSet::new();
    for (index, (source, selected)) in pages(&original).into_iter().zip(pages(&doc)).enumerate() {
        let a = original.get_dictionary(source).unwrap();
        let b = doc.get_dictionary(selected).unwrap();
        for key in [
            b"MediaBox".as_slice(),
            b"CropBox",
            b"BleedBox",
            b"TrimBox",
            b"ArtBox",
            b"Rotate",
        ] {
            assert_eq!(a.get(key).unwrap(), b.get(key).unwrap());
        }
        let resources = n::resolved(&doc, b.get(b"Resources").unwrap())
            .unwrap()
            .as_dict()
            .unwrap();
        let xobjects = n::resolved(&doc, resources.get(b"XObject").unwrap())
            .unwrap()
            .as_dict()
            .unwrap();
        images.insert(xobjects.get(b"Im1").unwrap().as_reference().unwrap());
        assert_eq!(render(&x.source, index + 1), render(&x.output, index + 1));
    }
    assert_eq!(images.len(), 1);
    assert_eq!(p::geometry(&doc).unwrap()[1].rect, [0., 0., 460., 380.]);
    let ids = pages(&doc);
    assert_eq!(
        doc.get_dictionary(ids[0])
            .unwrap()
            .get(b"Resources")
            .unwrap(),
        doc.get_dictionary(ids[1])
            .unwrap()
            .get(b"Resources")
            .unwrap()
    );
    assert_eq!(fs::read(&x.source).unwrap(), before);
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
