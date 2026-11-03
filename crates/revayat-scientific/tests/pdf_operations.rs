#[path = "common/pdf.rs"]
mod common;
use common::*;
use lopdf::{
    Object,
    content::{Content, Operation},
    dictionary,
};
use revayat_scientific::{
    pdf as p, pdf_content as c, pdf_forms as f, pdf_navigation as n, pdf_ocr,
};
use serde_json::json;
use std::fs;
fn fields(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    v.as_object().unwrap().clone()
}
#[test]
fn test_fill_zero_false_preserves_source_and_geometry() {
    let x = Fixture::new();
    let mut d = document(1);
    let text = textfield(&mut d, "Quantity");
    let button = checkbox(&mut d, "Approved", "Yes");
    x.save(d);
    let before = fs::read(&x.source).unwrap();
    let g = p::geometry(&p::open_pdf(&x.source, false).unwrap()).unwrap();
    p::fill_pdf(
        &x.source,
        &x.output,
        &fields(json!({"Quantity":0,"Approved":false})),
        &[],
    )
    .unwrap();
    let result = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(
        f::stored_value(&result, text).unwrap().as_deref(),
        Some("0")
    );
    assert_eq!(
        f::stored_value(&result, button).unwrap().as_deref(),
        Some("Off")
    );
    assert_eq!(p::geometry(&result).unwrap(), g);
    assert_eq!(fs::read(&x.source).unwrap(), before);
}
#[test]
fn test_fill_preflight_and_existing_output_survive_failures() {
    let x = Fixture::new();
    let mut d = document(1);
    textfield(&mut d, "Quantity");
    checkbox(&mut d, "Approved", "Yes");
    x.save(d);
    let source = fs::read(&x.source).unwrap();
    x.previous();
    for bad in [
        json!({"Unknown":0}),
        json!({"Quantity":false}),
        json!({"Approved":0}),
        json!({"Quantity":12,"Approved":"Maybe"}),
        json!({}),
    ] {
        assert!(p::fill_pdf(&x.source, &x.output, &fields(bad), &[]).is_err());
        x.preserved();
        assert_eq!(fs::read(&x.source).unwrap(), source);
    }
    let duplicate = serde_json::from_str::<c::UniqueFields>("{\"Quantity\":1,\"Quantity\":2}");
    assert!(duplicate.is_err());
}
#[test]
fn test_radio_group_and_single_choice_values() {
    let x = Fixture::new();
    let mut d = document(1);
    let (parent, _) = radio(&mut d, "Mode", &["One", "Two"]);
    let choice = textfield(&mut d, "Selection");
    let f = d.get_object_mut(choice).unwrap().as_dict_mut().unwrap();
    f.set("FT", "Ch");
    f.set(
        "Opt",
        vec![
            Object::string_literal("Small"),
            Object::string_literal("Large"),
        ],
    );
    x.save(d);
    p::fill_pdf(
        &x.source,
        &x.output,
        &fields(json!({"Mode":"Two","Selection":"Large"})),
        &[],
    )
    .unwrap();
    let d = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(f::stored_value(&d, parent).unwrap().as_deref(), Some("Two"));
    assert_eq!(
        f::stored_value(&d, choice).unwrap().as_deref(),
        Some("Large")
    );
    assert!(
        p::fill_pdf(
            &x.source,
            &x.output,
            &fields(json!({"Selection":"Other"})),
            &[]
        )
        .is_err()
    );
}
#[test]
fn test_text_table_image_provenance_and_original_image_stream() {
    let x = Fixture::new();
    let mut d = document(1);
    table(&mut d);
    let mut jpeg = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
        96,
        48,
        image::Rgb([100, 150, 200]),
    ))
    .write_to(&mut jpeg, image::ImageFormat::Jpeg)
    .unwrap();
    let jpeg = jpeg.into_inner();
    image_page(&mut d, 96, 48, jpeg.clone(), true);
    x.save(d);
    let before = fs::read(&x.source).unwrap();
    let text = x.temp.path().join("text.json");
    p::extract_text(&x.source, &text).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&fs::read(text).unwrap()).unwrap();
    assert!(
        v["pages"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Temperature")
    );
    let tables = x.temp.path().join("tables.json");
    c::extract_tables(&x.source, &tables).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&fs::read(tables).unwrap()).unwrap();
    assert_eq!(
        v["pages"][0]["tables"][0]["cells"][1],
        json!(["Temperature", "23.5 C"])
    );
    let images = x.temp.path().join("images");
    c::extract_images(&x.source, &images).unwrap();
    let v: serde_json::Value =
        serde_json::from_slice(&fs::read(images.join("images.json")).unwrap()).unwrap();
    assert_eq!(
        fs::read(images.join(v["images"][0]["file"].as_str().unwrap())).unwrap(),
        jpeg
    );
    assert_eq!(
        fs::read(images.join(v["images"][0]["original_stream"].as_str().unwrap())).unwrap(),
        jpeg
    );
    assert_eq!(v["placements"][0]["page"], 1);
    assert_eq!(fs::read(&x.source).unwrap(), before);
}
#[test]
fn test_table_decimals_and_grid_preserve_rotation_and_caller_settings() {
    let x = Fixture::new();
    let mut d = document(1);
    table(&mut d);
    d.get_object_mut(pages(&d)[0])
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Rotate", 90);
    x.save(d);
    let before = fs::read(&x.source).unwrap();
    let mut threads = Vec::new();
    for i in 0..4 {
        let source = x.source.clone();
        let output = x.temp.path().join(format!("tables-{i}.json"));
        threads.push(std::thread::spawn(move || {
            c::extract_tables(&source, &output).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
            assert_eq!(v["pages"][0]["tables"][0]["cells"][1][1], "23.5 C");
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(fs::read(&x.source).unwrap(), before);
    assert_eq!(
        p::geometry(&p::open_pdf(&x.source, false).unwrap()).unwrap()[0].rotation,
        90
    );
}
#[test]
fn test_table_failure_restores_settings_and_preserves_previous_output() {
    let x = Fixture::new();
    let mut d = document(1);
    let page = pages(&d)[0];
    d.add_page_contents(page, b"BT /Missing 12 Tf (corrupt font) Tj ET".to_vec())
        .unwrap();
    x.save(d);
    let before = fs::read(&x.source).unwrap();
    x.previous();
    assert!(c::extract_tables(&x.source, &x.output).is_err());
    x.preserved();
    assert_eq!(fs::read(&x.source).unwrap(), before);
    let clean = x.temp.path().join("clean.pdf");
    document(1).save(&clean).unwrap();
    c::extract_tables(&clean, &x.output).unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&fs::read(&x.output).unwrap()).is_ok());
}
#[test]
fn test_merge_geometry_and_late_input_failure() {
    let x = Fixture::new();
    let second = x.temp.path().join("second.pdf");
    let d = document(1);
    x.save(d);
    let mut d = document(1);
    let page = pages(&d)[0];
    let pd = d.get_object_mut(page).unwrap().as_dict_mut().unwrap();
    pd.set("MediaBox", vec![0.into(), 0.into(), 500.into(), 600.into()]);
    pd.set("Rotate", 90);
    d.save(&second).unwrap();
    p::merge_pdfs(&[x.source.clone(), second.clone()], &x.output).unwrap();
    let g = p::geometry(&p::open_pdf(&x.output, false).unwrap()).unwrap();
    assert_eq!(g.len(), 2);
    assert_eq!(g[1].rect, [0., 0., 600., 500.]);
    let previous = fs::read(&x.output).unwrap();
    fs::write(&second, b"broken").unwrap();
    assert!(p::merge_pdfs(&[x.source.clone(), second], &x.output).is_err());
    assert_eq!(fs::read(&x.output).unwrap(), previous);
}
#[test]
#[ignore = "requires Poppler"]
fn test_ocr_preflight_and_overlay_preserve_visible_page() {
    let x = Fixture::new();
    x.save(blank());
    x.previous();
    for (language, dpi, timeout) in [("eng;exec", 300, 30), ("eng", 0, 30), ("eng", 300, 0)] {
        assert!(pdf_ocr::ocr_pdf(&x.source, &x.output, language, dpi, timeout).is_err());
        x.preserved();
    }
    let mut layer = document(1);
    let page = pages(&layer)[0];
    let mut content = Content::decode(&layer.get_page_content(page)).unwrap();
    content
        .operations
        .insert(1, Operation::new("Tr", vec![3.into()]));
    layer
        .change_page_content(page, content.encode().unwrap())
        .unwrap();
    assert!(pdf_ocr::validate_text_layer(&layer, 400., 500.).unwrap());
    for visible in [
        "0 0 100 100 re f",
        "/Im1 Do",
        "/GS1 gs",
        "0 Tr BT (paint) Tj ET",
    ] {
        let mut bad = layer.clone();
        bad.add_page_contents(page, visible.as_bytes().to_vec())
            .unwrap();
        assert!(pdf_ocr::validate_text_layer(&bad, 400., 500.).is_err());
    }
    let before = render(&x.source, 1);
    let mut d = p::open_pdf(&x.source, true).unwrap();
    pdf_ocr::graft_text_layer(&mut d, 0, layer).unwrap();
    let g = p::geometry(&d).unwrap();
    p::save_document(
        &mut d,
        &x.output,
        std::slice::from_ref(&x.source),
        &g,
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(render(&x.output, 1), before);
    assert!(p::pdf_text(&x.output).unwrap().contains("Untouched source"));
}
#[test]
fn test_encryption_and_signature_limits() {
    let x = Fixture::new();
    for kind in ["encryption", "signature", "xfa"] {
        let mut d = document(1);
        match kind {
            "encryption" => {
                let id = d.add_object(dictionary! {"Filter"=>"Standard","V"=>1,"R"=>2});
                d.trailer.set("Encrypt", id);
            }
            "signature" => {
                d.add_object(dictionary!{"Type"=>"Sig","ByteRange"=>vec![0.into(),10.into(),20.into(),30.into()]});
            }
            _ => d.catalog_mut().unwrap().set(
                "AcroForm",
                dictionary! {"XFA"=>Object::string_literal("unsupported")},
            ),
        }
        x.save(d);
        x.previous();
        assert!(p::merge_pdfs(std::slice::from_ref(&x.source), &x.output).is_err());
        assert!(p::extract_pages(&x.source, &x.output, 1, 1).is_err());
        x.preserved();
    }
}
#[test]
#[ignore = "requires Poppler and real Tesseract eng data"]
fn test_real_tesseract_searchable_derivative() {
    let x = Fixture::new();
    let mut source = blank();
    let page = pages(&source)[0];
    let (font, ops) = revayat_scientific::pdf_font::appearance(
        &mut source,
        "Scientific specimen 2026\nTemperature 23.5 degrees",
        400.,
        100.,
    )
    .unwrap();
    source
        .get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set(
            "Resources",
            dictionary! {"Font"=>dictionary!{"RvForm"=>font}},
        );
    source
        .add_to_page_content(page, Content { operations: ops })
        .unwrap();
    x.save(source);
    let png = x.temp.path().join("scan.png");
    p::render_page(&x.source, 1, 200, &png).unwrap();
    let pixels = image::open(png).unwrap().to_rgb8();
    let mut scanned = blank();
    let id = pages(&scanned)[0];
    image_page(
        &mut scanned,
        pixels.width(),
        pixels.height(),
        pixels.into_raw(),
        false,
    );
    scanned
        .change_page_content(id, b"q 400 0 0 500 0 0 cm /Im1 Do Q".to_vec())
        .unwrap();
    x.save(scanned);
    let before = render(&x.source, 1);
    let raw = fs::read(&x.source).unwrap();
    pdf_ocr::ocr_pdf(&x.source, &x.output, "eng", 200, 60).unwrap();
    let extracted = p::pdf_text(&x.output).unwrap();
    assert!(
        extracted.to_lowercase().contains("scientific"),
        "OCR actual={extracted:?}"
    );
    assert_eq!(render(&x.output, 1), before);
    assert_eq!(fs::read(&x.source).unwrap(), raw);
}
#[test]
#[ignore = "requires Poppler"]
fn persian_form_appearance_is_shaped_embedded_and_logical() {
    let x = Fixture::new();
    let mut d = document(1);
    let id = textfield(&mut d, "Quantity");
    x.save(d);
    let value = "گزارش علمی ۱۲۳ فارسی";
    p::fill_pdf(
        &x.source,
        &x.output,
        &fields(json!({"Quantity":value})),
        &[],
    )
    .unwrap();
    let d = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(f::stored_value(&d, id).unwrap().as_deref(), Some(value));
    let ap = n::resolved(&d, d.get_dictionary(id).unwrap().get(b"AP").unwrap())
        .unwrap()
        .as_dict()
        .unwrap();
    let stream = n::resolved(&d, ap.get(b"N").unwrap())
        .unwrap()
        .as_stream()
        .unwrap();
    let content = Content::decode(&c::decoded(stream).unwrap()).unwrap();
    assert!(content.operations.iter().any(|o| o.operator == "BDC"));
    assert!(d.objects.values().any(|o| {
        o.as_dict().is_ok_and(|f| {
            f.get(b"Subtype").and_then(Object::as_name).ok() == Some(b"CIDFontType2")
        })
    }));
    assert_ne!(render(&x.source, 1), render(&x.output, 1));
}
