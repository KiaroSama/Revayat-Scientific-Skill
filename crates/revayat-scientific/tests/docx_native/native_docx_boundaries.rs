use super::*;

#[test]
fn full_unicode_casefold_archive_collisions_are_rejected() {
    let f = Fixture::new();
    for (left, right) in [
        ("Straße", "STRASSE"),
        ("Σ", "ς"),
        ("ﬓ", "մն"),
        ("ﬃ", "FFI"),
        ("Ა", "ა"),
    ] {
        let mut members = base();
        members.insert(format!("word/{left}.bin"), b"first opaque part".to_vec());
        members.insert(format!("word/{right}.bin"), b"second opaque part".to_vec());
        f.write(&members);
        assert!(
            d::read_package(&f.source)
                .unwrap_err()
                .to_string()
                .contains("duplicate archive member")
        );
    }
}

#[test]
fn duplicate_json_keys_and_oversized_inputs_are_rejected_before_creation() {
    let f = Fixture::new();
    let input = f.root.join("input.json");
    for bytes in [
        br#"{"sections":[],"sections":[]}"#.as_slice(),
        br#"{"sections":[{"width_mm":210,"width_mm":220}]}"#.as_slice(),
    ] {
        fs::write(&input, bytes).unwrap();
        assert!(d::load_json(&input).is_err());
    }
    fs::write(&input, vec![b' '; 8 * 1024 * 1024 + 1]).unwrap();
    assert!(
        d::load_json(&input)
            .unwrap_err()
            .to_string()
            .contains("8 MiB")
    );
    assert!(!f.output.exists());
}

#[test]
fn corrupt_member_crc_is_rejected_without_publication() {
    let f = Fixture::new();
    f.base();
    let mut bytes = fs::read(&f.source).unwrap();
    let mut archive = ZipArchive::new(File::open(&f.source).unwrap()).unwrap();
    let member = archive.by_name("word/document.xml").unwrap();
    let offset = (member.data_start().unwrap() + member.compressed_size() / 2) as usize;
    bytes[offset] ^= 1;
    fs::write(&f.source, &bytes).unwrap();
    fs::write(&f.output, b"previous delivery").unwrap();
    assert!(d::read_package(&f.source).is_err());
    assert!(
        d::edit_package(
            &f.source,
            &f.output,
            &patch("Original text", "Changed"),
            &[]
        )
        .is_err()
    );
    assert_eq!(fs::read(&f.output).unwrap(), b"previous delivery");
    f.clean();
}

#[test]
fn markup_compatibility_prefixes_and_untouched_story_bytes_survive() {
    let f = Fixture::new();
    let mut members = base();
    let xml = format!(
        r#"<?xml version="1.0"?><doc:document xmlns:doc="{}" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" mc:Ignorable="w14"><doc:body><!--keep--><doc:p w14:paraId="00112233"><doc:r><doc:t xml:space='default'>Original text</doc:t></doc:r></doc:p></doc:body></doc:document>"#,
        d::W
    );
    members.insert("word/document.xml".into(), xml.as_bytes().to_vec());
    f.write(&members);
    f.patch("word/document.xml", "Original text", " متن ");
    let expected = xml
        .replace("xml:space='default'", "xml:space=\"preserve\"")
        .replace("Original text", " متن ");
    exact_except(
        &members,
        &read_zip(&f.output),
        "word/document.xml",
        expected.as_bytes(),
    );
}

#[test]
fn comments_processing_instructions_and_nested_text_markup_are_not_editable() {
    let f = Fixture::new();
    for content in [
        "Original<!--comment--> text",
        "Original<?data private?> text",
        "Original<w:br/> text",
    ] {
        let mut members = base();
        replace(&mut members, "word/document.xml", "Original text", content);
        f.write(&members);
        fs::write(&f.output, b"previous delivery").unwrap();
        let report = d::inspect_package(&f.source).unwrap();
        let old = report["text_nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["part"] == "word/document.xml")
            .unwrap()["text"]
            .as_str()
            .unwrap();
        assert!(d::edit_package(&f.source, &f.output, &patch(old, "Changed"), &[]).is_err());
        assert_eq!(fs::read(&f.output).unwrap(), b"previous delivery");
        f.clean();
    }
}

#[test]
fn source_revision_change_during_publication_preserves_external_revision_and_delivery() {
    let f = Fixture::new();
    f.base();
    fs::write(&f.output, b"previous delivery").unwrap();
    let mut changed = false;
    let result = d::edit_package_observed(
        &f.source,
        &f.output,
        &patch("Original text", "Changed"),
        &[],
        |event| {
            if matches!(
                event,
                d::EditEvent::Publication {
                    boundary: Boundary::BackupReady,
                    ..
                }
            ) {
                fs::write(&f.source, b"new external source revision")?;
                changed = true;
            }
            Ok(())
        },
    );
    assert!(changed);
    assert!(result.unwrap_err().to_string().contains("source changed"));
    assert_eq!(
        fs::read(&f.source).unwrap(),
        b"new external source revision"
    );
    assert_eq!(fs::read(&f.output).unwrap(), b"previous delivery");
    f.clean();
}

#[test]
fn content_and_image_aliases_and_unsafe_image_paths_preserve_inputs() {
    let f = Fixture::new();
    let image_path = f.root.join("figure.png");
    image::RgbImage::from_pixel(2, 2, image::Rgb([1, 2, 3]))
        .save(&image_path)
        .unwrap();
    let image_before = fs::read(&image_path).unwrap();
    let mut specification = content(json!({"text":"Scientific text"}));
    specification["sections"][0]["blocks"] =
        json!([{"type":"image","path":"figure.png","width_mm":10}]);
    let input = f.root.join("content.json");
    fs::write(&input, serde_json::to_vec(&specification).unwrap()).unwrap();
    let content_before = fs::read(&input).unwrap();
    assert!(d::create_document(&input, &input).is_err());
    assert!(d::create_document(&input, &image_path).is_err());
    assert_eq!(fs::read(&input).unwrap(), content_before);
    assert_eq!(fs::read(&image_path).unwrap(), image_before);
    for path in ["../figure.png", "/figure.png", "C:\\figure.png"] {
        specification["sections"][0]["blocks"][0]["path"] = json!(path);
        fs::write(&input, serde_json::to_vec(&specification).unwrap()).unwrap();
        fs::write(&f.output, b"previous delivery").unwrap();
        assert!(d::create_document(&input, &f.output).is_err());
        assert_eq!(fs::read(&f.output).unwrap(), b"previous delivery");
    }
    f.clean();
}
