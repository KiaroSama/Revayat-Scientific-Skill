use super::*;
fn paragraph(run: &Value, style: Option<&str>) -> String {
    let mut value = json!({"runs":[run]});
    if let Some(style) = style {
        value["style"] = json!(style);
    }
    format!(
        "<w:root xmlns:w=\"{}\">{}</w:root>",
        d::W,
        d::paragraph_xml(&value, "fa-IR", true).unwrap()
    )
}
fn val(xml: &roxmltree::Document<'_>, name: &str) -> Option<String> {
    xml.descendants()
        .find(|n| n.has_tag_name((d::W, name)))
        .map(|n| n.attribute((d::W, "val")).unwrap_or("1").to_owned())
}
#[test]
fn test_explicit_true_sets_both_script_properties() {
    for rtl in [true, false] {
        let s = paragraph(
            &json!({"text":"علم Science","rtl":rtl,"bold":true,"italic":true}),
            None,
        );
        let xml = roxmltree::Document::parse(&s).unwrap();
        for name in ["b", "i", "bCs", "iCs"] {
            assert_eq!(val(&xml, name).as_deref(), Some("1"));
        }
        assert_eq!(
            val(&xml, "rtl").as_deref(),
            Some(if rtl { "1" } else { "0" })
        );
    }
}
#[test]
fn test_explicit_false_overrides_both_script_properties() {
    let s = paragraph(
        &json!({"text":"متن","bold":false,"italic":false}),
        Some("Heading 1"),
    );
    let xml = roxmltree::Document::parse(&s).unwrap();
    for name in ["b", "i", "bCs", "iCs"] {
        assert_eq!(val(&xml, name).as_deref(), Some("0"));
    }
    assert_eq!(val(&xml, "pStyle").as_deref(), Some("Heading1"));
}
#[test]
fn test_omitted_properties_preserve_style_inheritance() {
    let s = paragraph(&json!({"text":"متن"}), Some("Heading 1"));
    let xml = roxmltree::Document::parse(&s).unwrap();
    for name in ["b", "i", "bCs", "iCs"] {
        assert_eq!(val(&xml, name), None);
    }
    assert_eq!(val(&xml, "pStyle").as_deref(), Some("Heading1"));
}
#[test]
fn test_fractional_sizes_use_identical_serialized_half_points() {
    for size in [1.0_f64, 10.25, 11.3, 11.75, 12.8, 200.] {
        let s = paragraph(&json!({"text":"علم A","size_pt":size}), None);
        let xml = roxmltree::Document::parse(&s).unwrap();
        assert_eq!(val(&xml, "sz"), val(&xml, "szCs"));
        assert_eq!(
            val(&xml, "sz").unwrap().parse::<u32>().unwrap(),
            (size * 2.).floor() as u32
        );
    }
}
#[test]
fn test_created_package_keeps_body_table_header_footer_formatting() {
    let f = Fixture::new();
    create(
        &f,
        &content(json!({"text":"علم A","bold":true,"italic":false,"size_pt":11.3})),
    );
    d::read_package(&f.source).unwrap();
    let m = read_zip(&f.source);
    let mut checked = 0;
    for part in ["word/document.xml", "word/header1.xml", "word/footer1.xml"] {
        let s = std::str::from_utf8(&m[part]).unwrap();
        let xml = roxmltree::Document::parse(s).unwrap();
        for run in xml.descendants().filter(|n| {
            n.has_tag_name((d::W, "r"))
                && n.descendants()
                    .any(|n| n.has_tag_name((d::W, "t")) && n.text() == Some("علم A"))
        }) {
            let properties = run
                .children()
                .find(|n| n.has_tag_name((d::W, "rPr")))
                .unwrap();
            let property = |name| {
                properties
                    .children()
                    .find(|n| n.has_tag_name((d::W, name)))
                    .unwrap()
                    .attribute((d::W, "val"))
                    .unwrap()
            };
            assert_eq!(property("bCs"), "1");
            assert_eq!(property("iCs"), "0");
            assert_eq!(property("sz"), property("szCs"));
            checked += 1;
        }
    }
    assert_eq!(checked, 4);
}
#[test]
fn test_invalid_style_boolean_preserves_existing_destination() {
    let f = Fixture::new();
    let source = f.root.join("content.json");
    fs::write(&f.output, b"previous approved document").unwrap();
    fs::write(
        &source,
        serde_json::to_vec(&content(json!({"text":"علم","bold":"false"}))).unwrap(),
    )
    .unwrap();
    assert!(d::create_document(&source, &f.output).is_err());
    assert_eq!(fs::read(&f.output).unwrap(), b"previous approved document");
}
