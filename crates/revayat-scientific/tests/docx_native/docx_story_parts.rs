use super::*;
const KINDS: [&str; 5] = ["header", "footer", "footnotes", "endnotes", "comments"];
#[test]
fn test_all_five_story_kinds_use_declared_names() {
    let f = Fixture::new();
    for kind in KINDS {
        for part in ["word/stories/named.xml", "other/named.part", "named"] {
            f.story(kind, part, false, false, None, "");
            assert!(
                has_node(&d::inspect_package(&f.source).unwrap(), part, "Original"),
                "{kind}:{part}"
            );
        }
    }
}
#[test]
fn test_inspected_address_is_editable_without_changing_other_bytes() {
    let f = Fixture::new();
    for kind in KINDS {
        let part = format!("shared/{kind}.story");
        let m = f.story(kind, &part, false, false, None, "");
        let before = fs::read(&f.source).unwrap();
        f.patch(&part, "Original", " متن & <x> ");
        let expected = String::from_utf8(m[&part].clone()).unwrap().replace(
            "<w:t>Original</w:t>",
            "<w:t xml:space=\"preserve\"> متن &amp; &lt;x&gt; </w:t>",
        );
        exact_except(&m, &read_zip(&f.output), &part, expected.as_bytes());
        assert_eq!(
            ZipArchive::new(File::open(&f.output).unwrap())
                .unwrap()
                .comment(),
            b"untouched package comment"
        );
        assert_eq!(fs::read(&f.source).unwrap(), before);
    }
}
#[test]
fn test_default_story_type_and_override_precedence() {
    let f = Fixture::new();
    let part = "word/custom.hdr";
    f.story("header", part, false, true, None, "");
    assert!(has_node(
        &d::inspect_package(&f.source).unwrap(),
        part,
        "Original"
    ));
    f.story(
        "header",
        part,
        false,
        true,
        None,
        &format!("<Override PartName=\"/{part}\" ContentType=\"application/xml\"/>"),
    );
    assert!(!has_node(
        &d::inspect_package(&f.source).unwrap(),
        part,
        "Original"
    ));
}
#[test]
fn test_content_type_keys_are_ascii_insensitive_and_unique() {
    let f = Fixture::new();
    let part = "word/stories/first.hdr";
    for variant in [
        "override",
        "default",
        "duplicate-override",
        "duplicate-default",
        "main-default",
    ] {
        let mut m = f.story(
            "header",
            part,
            false,
            matches!(variant, "default" | "duplicate-default"),
            None,
            "",
        );
        match variant {
            "override" => {
                replace(
                    &mut m,
                    "[Content_Types].xml",
                    "PartName=\"/word/stories/first.hdr\"",
                    "PartName=\"/WORD/STORIES/FIRST.HDR\"",
                );
                replace(
                    &mut m,
                    "[Content_Types].xml",
                    "PartName=\"/word/document.xml\"",
                    "PartName=\"/WORD/DOCUMENT.XML\"",
                );
            }
            "default" => replace(
                &mut m,
                "[Content_Types].xml",
                "Extension=\"hdr\"",
                "Extension=\"HDR\"",
            ),
            "duplicate-override" => append(
                &mut m,
                "[Content_Types].xml",
                "</Types>",
                "<Override PartName=\"/WORD/STORIES/FIRST.HDR\" ContentType=\"application/xml\"/>",
            ),
            "duplicate-default" => append(
                &mut m,
                "[Content_Types].xml",
                "</Types>",
                "<Default Extension=\"HDR\" ContentType=\"application/xml\"/>",
            ),
            _ => {
                replace(
                    &mut m,
                    "[Content_Types].xml",
                    "ContentType=\"application/xml\"",
                    &format!("ContentType=\"{}\"", d::MAIN_TYPE),
                );
                replace(
                    &mut m,
                    "[Content_Types].xml",
                    &format!(
                        "<Override PartName=\"/word/document.xml\" ContentType=\"{}\"/>",
                        d::MAIN_TYPE
                    ),
                    "",
                );
            }
        }
        f.write(&m);
        if variant.starts_with("duplicate") {
            assert!(d::read_package(&f.source).is_err());
        } else {
            assert!(has_node(
                &d::inspect_package(&f.source).unwrap(),
                part,
                "Original"
            ));
        }
    }
}
#[test]
fn test_generic_custom_xml_is_not_authorized_by_a_text_node() {
    let f = Fixture::new();
    let part = "customXml/item.xml";
    f.story("header", part, true, false, None, "");
    assert!(!has_node(
        &d::inspect_package(&f.source).unwrap(),
        part,
        "Original"
    ));
    assert!(
        d::edit_package(
            &f.source,
            &f.output,
            &json!([{"part":part,"index":0,"expected":"Original","text":"Changed"}]),
            &[]
        )
        .is_err()
    );
    assert!(!f.output.exists());
}
#[test]
fn test_legacy_canonical_generic_story_remains_supported() {
    let f = Fixture::new();
    let part = "word/header1.xml";
    f.story("header", part, true, false, None, "");
    f.patch(part, "Original", "Changed");
    assert!(has_node(
        &d::inspect_package(&f.output).unwrap(),
        part,
        "Changed"
    ));
}
#[test]
fn test_primary_document_stays_editable_with_authoritative_main_type() {
    let f = Fixture::new();
    let m = f.story("header", "word/stories/first.xml", false, false, None, "");
    assert!(has_node(
        &d::inspect_package(&f.source).unwrap(),
        "word/document.xml",
        "Body"
    ));
    f.patch("word/document.xml", "Body", "Changed body");
    let expected = String::from_utf8(m["word/document.xml"].clone())
        .unwrap()
        .replace("Body", "Changed body");
    exact_except(
        &m,
        &read_zip(&f.output),
        "word/document.xml",
        expected.as_bytes(),
    );
}
#[test]
fn test_canonical_names_do_not_override_custom_types_or_wrong_roots() {
    let f = Fixture::new();
    let part = "word/header1.xml";
    for (declaration, root, excluded) in [
        ("application/custom+xml", "hdr", true),
        ("application/xml", "ftr", false),
        ("text/xml", "custom", false),
    ] {
        let mut m = f.story("header", part, true, false, Some(root), "");
        replace(
            &mut m,
            "[Content_Types].xml",
            "PartName=\"/word/header1.xml\" ContentType=\"application/xml\"",
            &format!("PartName=\"/word/header1.xml\" ContentType=\"{declaration}\""),
        );
        f.write(&m);
        let before = fs::read(&f.source).unwrap();
        fs::write(&f.output, b"previous delivery").unwrap();
        if excluded {
            assert!(!has_node(
                &d::inspect_package(&f.source).unwrap(),
                part,
                "Original"
            ));
        }
        assert!(
            d::edit_package(
                &f.source,
                &f.output,
                &json!([{"part":part,"index":0,"expected":"Original","text":"Changed"}]),
                &[]
            )
            .is_err()
        );
        assert_eq!(fs::read(&f.source).unwrap(), before);
        assert_eq!(fs::read(&f.output).unwrap(), b"previous delivery");
    }
}
#[test]
fn test_wrong_declared_story_root_fails_before_publication() {
    let f = Fixture::new();
    for root in ["document", "ftr", "custom"] {
        f.story(
            "header",
            "word/stories/first.xml",
            false,
            false,
            Some(root),
            "",
        );
        fs::write(&f.output, b"previous delivery").unwrap();
        assert!(d::edit_package(&f.source,&f.output,&json!([{"part":"word/stories/first.xml","index":0,"expected":"Original","text":"Changed"}]),&[]).is_err());
        assert_eq!(fs::read(&f.output).unwrap(), b"previous delivery");
    }
}
#[test]
fn test_duplicate_declarations_are_not_silently_selected() {
    let f = Fixture::new();
    f.story(
        "header",
        "word/stories/first.xml",
        false,
        false,
        None,
        "<Override PartName=\"/word/stories/first.xml\" ContentType=\"application/xml\"/>",
    );
    assert!(d::read_package(&f.source).is_err());
}
#[test]
fn test_typed_nonxml_suffix_cannot_bypass_xml_limits() {
    let f = Fixture::new();
    for data in [
        format!("<!DOCTYPE hdr><w:hdr xmlns:w=\"{}\"/>", d::W).into_bytes(),
        vec![255],
        b"<broken".to_vec(),
        vec![b' '; d::MAX_XML + 1],
    ] {
        let mut m = f.story("header", "word/first.story", false, false, None, "");
        m.insert("word/first.story".into(), data);
        f.write(&m);
        assert!(d::read_package(&f.source).is_err());
    }
}
#[test]
fn test_late_stale_edit_keeps_source_and_destination() {
    let f = Fixture::new();
    f.story("header", "word/custom.xml", false, false, None, "");
    let before = fs::read(&f.source).unwrap();
    fs::write(&f.output, b"previous delivery").unwrap();
    let changes = json!([{"part":"word/document.xml","index":0,"expected":"Body","text":"New body"},{"part":"word/custom.xml","index":0,"expected":"Stale","text":"New header"}]);
    assert!(
        d::edit_package(&f.source, &f.output, &changes, &[])
            .unwrap_err()
            .to_string()
            .contains("stale")
    );
    assert_eq!(fs::read(&f.source).unwrap(), before);
    assert_eq!(fs::read(&f.output).unwrap(), b"previous delivery");
    f.clean();
}
#[test]
fn test_duplicate_addresses_and_publication_failure_are_recoverable() {
    let f = Fixture::new();
    let part = "word/custom.xml";
    f.story("header", part, false, false, None, "");
    let changes = json!([{"part":part,"index":0,"expected":"Original","text":"Changed"}]);
    fs::write(&f.output, b"previous delivery").unwrap();
    assert!(d::edit_package(&f.source, &f.output, &json!([changes[0], changes[0]]), &[]).is_err());
    fail_commit(&f, &changes);
    assert_eq!(fs::read(&f.output).unwrap(), b"previous delivery");
}
#[test]
fn test_python_docx_reads_and_edits_a_renamed_real_header() {
    let f = Fixture::new();
    let mut m = real();
    let part = "word/stories/first.xml";
    let header = m.remove("word/header1.xml").unwrap();
    m.insert(part.into(), header);
    replace(
        &mut m,
        "[Content_Types].xml",
        "/word/header1.xml",
        &format!("/{part}"),
    );
    replace(
        &mut m,
        "word/_rels/document.xml.rels",
        "Target=\"header1.xml\"",
        "Target=\"stories/first.xml\"",
    );
    f.write(&m);
    assert!(has_node(
        &d::inspect_package(&f.source).unwrap(),
        part,
        "HeaderOriginal"
    ));
    f.patch(part, "HeaderOriginal", "Changed");
    let expected = String::from_utf8(m[part].clone())
        .unwrap()
        .replace("HeaderOriginal", "Changed");
    exact_except(&m, &read_zip(&f.output), part, expected.as_bytes());
    let report = d::inspect_package(&f.output).unwrap();
    assert!(has_node(&report, part, "Changed"));
    assert!(
        report["relationships"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rel| rel["resolved"] == part)
    );
}
