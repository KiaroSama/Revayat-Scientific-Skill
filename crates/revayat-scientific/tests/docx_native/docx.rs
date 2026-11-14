use super::*;
#[test]
fn test_edit_preserves_untouched_members_and_source() {
    let f = Fixture::new();
    let m = f.base();
    let before = fs::read(&f.source).unwrap();
    f.patch("word/document.xml", "Original text", " ترجمهٔ علمی ");
    let expected = String::from_utf8(m["word/document.xml"].clone())
        .unwrap()
        .replace(
            "<w:t>Original text</w:t>",
            "<w:t xml:space=\"preserve\"> ترجمهٔ علمی </w:t>",
        );
    exact_except(
        &m,
        &read_zip(&f.output),
        "word/document.xml",
        expected.as_bytes(),
    );
    assert_eq!(fs::read(&f.source).unwrap(), before);
    assert!(has_node(
        &d::inspect_package(&f.output).unwrap(),
        "word/document.xml",
        " ترجمهٔ علمی "
    ));
}
#[test]
fn test_rejected_edits_preserve_existing_output() {
    let f = Fixture::new();
    f.base();
    fs::write(&f.output, b"previous delivery").unwrap();
    for (key, value) in [
        ("expected", json!("stale")),
        ("index", json!(-1)),
        ("index", json!(true)),
        ("text", json!("line\nbreak")),
        ("part", json!("../document.xml")),
    ] {
        let mut p = patch("Original text", "متن");
        p[0][key] = value;
        assert!(d::edit_package(&f.source, &f.output, &p, &[]).is_err());
        assert_eq!(fs::read(&f.output).unwrap(), b"previous delivery");
    }
    let p = patch("Original text", "متن");
    for target in [&f.source, &f.root] {
        assert!(d::edit_package(&f.source, target, &p, &[]).is_err());
    }
    assert!(d::edit_package(&f.source, &f.output, &json!([p[0], p[0]]), &[]).is_err());
    fail_commit(&f, &p);
    assert_eq!(fs::read(&f.output).unwrap(), b"previous delivery");
}
#[test]
fn test_archive_and_xml_boundaries() {
    let f = Fixture::new();
    for name in [
        "../escape",
        "/absolute",
        "word\\escape",
        "C:escape",
        "WORD/DOCUMENT.XML",
    ] {
        let mut m = base();
        m.insert(name.into(), b"not extracted".to_vec());
        f.write(&m);
        assert!(d::read_package(&f.source).is_err(), "accepted {name}");
    }
    for declaration in [
        "<!DOCTYPE document [<!ENTITY x \"expanded\">]>",
        "<!DOCTYPE document SYSTEM \"file:///outside\">",
    ] {
        let mut m = base();
        let data = format!(
            "{declaration}{}",
            String::from_utf8(m["word/document.xml"].clone()).unwrap()
        );
        m.insert("word/document.xml".into(), data.into_bytes());
        f.write(&m);
        assert!(d::read_package(&f.source).is_err());
    }
    let mut m = base();
    m.insert(
        "word/vbaProject.bin".into(),
        b"opaque macro content".to_vec(),
    );
    f.write(&m);
    assert!(
        d::read_package(&f.source)
            .unwrap()
            .unsupported
            .contains(&"macros".into())
    );
    assert!(d::require_editable(&d::read_package(&f.source).unwrap().unsupported).is_err());
    let mut m = base();
    m.insert("word/large.bin".into(), vec![0; d::MAX_MEMBER as usize + 1]);
    f.write(&m);
    assert!(d::read_package(&f.source).is_err());
}
#[test]
fn test_empty_nodes_entities_and_field_markup_preserved() {
    let f = Fixture::new();
    let mut m = base();
    replace(
        &mut m,
        "word/document.xml",
        "<w:t>Original text</w:t>",
        "<w:fldChar w:fldCharType=\"begin\"/><w:t/><w:t>A &amp; B</w:t><w:fldChar w:fldCharType=\"end\"/>",
    );
    f.write(&m);
    d::edit_package(&f.source,&f.output,&json!([{"part":"word/document.xml","index":0,"expected":"","text":"<متن>"},{"part":"word/document.xml","index":1,"expected":"A & B","text":"A & C"}]),&[]).unwrap();
    let expected = String::from_utf8(m["word/document.xml"].clone())
        .unwrap()
        .replace("<w:t/>", "<w:t>&lt;متن&gt;</w:t>")
        .replace("A &amp; B", "A &amp; C");
    exact_except(
        &m,
        &read_zip(&f.output),
        "word/document.xml",
        expected.as_bytes(),
    );
    assert_eq!(
        d::inspect_package(&f.output).unwrap()["structures"]["fldChar"],
        2
    );
}
#[test]
fn test_relationship_boundaries_and_signed_refusal() {
    let f = Fixture::new();
    let mut m = base();
    let rel = format!(
        "<Relationships xmlns=\"{}\"><Relationship Id=\"rId9\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"https://example.invalid/private\" TargetMode=\"External\"/></Relationships>",
        d::R
    );
    m.insert(
        "word/_rels/document.xml.rels".into(),
        rel.as_bytes().to_vec(),
    );
    f.write(&m);
    assert!(
        d::inspect_package(&f.source).unwrap()["relationships"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["mode"] == "External")
    );
    for target in [
        "../../escape.xml",
        "%2e%2e/%2e%2e/escape.xml",
        "file:///outside.xml",
    ] {
        m.insert(
            "word/_rels/document.xml.rels".into(),
            rel.replace("https://example.invalid/private", target)
                .replace("External", "Internal")
                .into_bytes(),
        );
        f.write(&m);
        assert!(d::read_package(&f.source).is_err());
    }
    let mut m = base();
    m.insert("_xmlsignatures/sig1.xml".into(), b"<signature/>".to_vec());
    f.write(&m);
    assert!(
        d::inspect_package(&f.source).unwrap()["unsupported"]
            .as_array()
            .unwrap()
            .contains(&json!("digital-signatures"))
    );
    assert!(d::edit_package(&f.source, &f.output, &patch("Original text", "متن"), &[]).is_err());
    assert!(!f.output.exists());
}
#[test]
fn test_create_sections_rtl_tables_images_and_edit() {
    let f = Fixture::new();
    image::RgbImage::from_pixel(24, 12, image::Rgb([20, 80, 120]))
        .save(f.root.join("figure.png"))
        .unwrap();
    let data: Value =
        serde_json::from_str(include_str!("../../../../tests/fixtures/docx-content.json")).unwrap();
    create(&f, &data);
    let report = d::inspect_package(&f.source).unwrap();
    assert_eq!(report["sections"].as_array().unwrap().len(), 2);
    assert_eq!(report["structures"]["tbl"], 1);
    assert_eq!(report["structures"]["drawing"], 1);
    let first = &report["sections"][0]["geometry_twips"]["pgSz"];
    assert!(
        (first["w"].as_str().unwrap().parse::<f64>().unwrap() - 160. / 25.4 * 1440.).abs() <= 1.
    );
    assert!(
        (first["h"].as_str().unwrap().parse::<f64>().unwrap() - 240. / 25.4 * 1440.).abs() <= 1.
    );
    let m = read_zip(&f.source);
    let part = report["media"][0]["part"].as_str().unwrap();
    assert_eq!(m[part], fs::read(f.root.join("figure.png")).unwrap());
    let body = String::from_utf8(m["word/document.xml"].clone()).unwrap();
    let xml = roxmltree::Document::parse(&body).unwrap();
    assert!(xml.descendants().any(|n| n.has_tag_name((d::W, "bidi"))));
    assert!(xml.descendants().any(|n| n.has_tag_name((d::W, "rtl"))));
    assert!(xml.descendants().any(|n| n.has_tag_name((d::W,"lang")) && n.attribute((d::W,"bidi")) == Some("fa-IR")));
    let run = xml
        .descendants()
        .find(|n| {
            n.has_tag_name((d::W, "rFonts")) && n.attribute((d::W, "cs")) == Some("Vazirmatn")
        })
        .unwrap();
    assert_eq!(run.attribute((d::W, "ascii")), Some("Vazirmatn"));
    assert_eq!(run.attribute((d::W, "hAnsi")), Some("Vazirmatn"));
    let scientific = xml
        .descendants()
        .find(|n| {
            n.has_tag_name((d::W, "p"))
                && n.descendants()
                    .any(|n| n.has_tag_name((d::W, "t")) && n.text() == Some("23.5 °C"))
        })
        .unwrap();
    for name in ["bidi", "rtl"] {
        assert_eq!(
            scientific
                .descendants()
                .find(|n| n.has_tag_name((d::W, name)))
                .unwrap()
                .attribute((d::W, "val")),
            Some("0")
        );
    }
    assert_eq!(
        scientific
            .descendants()
            .find(|n| n.has_tag_name((d::W, "lang")))
            .unwrap()
            .attribute((d::W, "val")),
        Some("en-US")
    );
    let node = report["text_nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["text"] == "Scientific example")
        .unwrap();
    d::edit_package(&f.source,&f.output,&json!([{"part":node["part"],"index":node["index"],"expected":node["text"],"text":"نمونهٔ علمی"}]),&[]).unwrap();
    let after = d::inspect_package(&f.output).unwrap();
    assert_eq!(after["sections"], report["sections"]);
    assert_eq!(after["media"], report["media"]);
    for (name, bytes) in &m {
        if name != node["part"].as_str().unwrap() {
            assert_eq!(read_zip(&f.output)[name], *bytes);
        }
    }
}
