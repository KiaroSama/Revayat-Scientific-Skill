use super::*;
#[test]
fn test_relocated_signature_parts_are_detected_by_type_and_relationship() {
    let f = Fixture::new();
    for feature in &features()[..3] {
        f.feature(feature, true, true, false, false);
        f.blocked("digital-signatures");
    }
}
#[test]
fn test_signature_content_types_are_sufficient_without_conventional_paths() {
    let f = Fixture::new();
    for feature in &features()[..3] {
        for default in [false, true] {
            f.feature(feature, true, false, false, default);
            f.blocked("digital-signatures");
        }
    }
}
#[test]
fn test_signature_relationships_are_sufficient_with_generic_content_type() {
    let f = Fixture::new();
    for feature in &features()[..3] {
        f.feature(feature, false, true, false, false);
        f.blocked("digital-signatures");
    }
}
#[test]
fn test_relocated_vba_parts_are_detected_without_macro_enabled_main() {
    let f = Fixture::new();
    for feature in &features()[3..] {
        for (typed, related) in [(true, true), (true, false), (false, true)] {
            f.feature(feature, typed, related, false, false);
            f.blocked("macros");
        }
    }
}
#[test]
fn test_external_restricted_relationship_is_data_not_fetch_permission() {
    let f = Fixture::new();
    f.feature(&features()[0], false, true, true, false);
    f.blocked("digital-signatures");
}
#[test]
fn test_override_precedence_does_not_inherit_an_unrelated_restricted_default() {
    let f = Fixture::new();
    let mut m = f.feature(&features()[0], true, false, false, true);
    append(
        &mut m,
        "[Content_Types].xml",
        "</Types>",
        "<Override PartName=\"/opaque/object.dat\" ContentType=\"application/octet-stream\"/>",
    );
    f.write(&m);
    assert_eq!(
        d::inspect_package(&f.source).unwrap()["unsupported"],
        json!([])
    );
    f.patch("word/document.xml", "Original text", "Changed");
    assert_eq!(read_zip(&f.output)["opaque/object.dat"], b"");
}
#[test]
fn test_lookalike_custom_types_and_relationships_do_not_grant_edit_restrictions() {
    let f = Fixture::new();
    let feature = Feature {
        mime: "application/example.digital-signature-origin".into(),
        relation: "https://example.invalid/relationships/digital-signature/origin".into(),
        payload: b"ordinary custom payload",
    };
    let m = f.feature(&feature, true, true, false, false);
    assert_eq!(
        d::inspect_package(&f.source).unwrap()["unsupported"],
        json!([])
    );
    f.patch("word/document.xml", "Original text", "Changed");
    let after = read_zip(&f.output);
    assert_eq!(after["opaque/object.dat"], m["opaque/object.dat"]);
    assert!(has_node(
        &d::inspect_package(&f.output).unwrap(),
        "word/document.xml",
        "Changed"
    ));
}
#[test]
fn test_existing_canonical_name_and_macro_main_guards_are_retained() {
    let f = Fixture::new();
    for (name, declaration, category) in [
        (
            Some("_xmlsignatures/legacy.bin"),
            None,
            "digital-signatures",
        ),
        (Some("word/vbaProject.bin"), None, "macros"),
        (
            None,
            Some("application/vnd.ms-word.document.macroEnabled.main+xml"),
            "macros",
        ),
    ] {
        let mut m = base();
        if let Some(name) = name {
            m.insert(name.into(), b"opaque synthetic legacy metadata".to_vec());
        }
        if let Some(declaration) = declaration {
            replace(&mut m, "[Content_Types].xml", d::MAIN_TYPE, declaration);
        }
        f.write(&m);
        f.blocked(category);
    }
}
#[test]
fn test_unsigned_real_document_stays_editable_without_unrelated_member_changes() {
    let f = Fixture::new();
    let m = real();
    f.write(&m);
    let before = fs::read(&f.source).unwrap();
    f.patch("word/document.xml", "Original text", "Changed");
    let expected = String::from_utf8(m["word/document.xml"].clone())
        .unwrap()
        .replace("Original text", "Changed");
    exact_except(
        &m,
        &read_zip(&f.output),
        "word/document.xml",
        expected.as_bytes(),
    );
    assert!(has_node(
        &d::inspect_package(&f.output).unwrap(),
        "word/document.xml",
        "Changed"
    ));
    assert_eq!(fs::read(&f.source).unwrap(), before);
}
#[test]
fn test_mime_type_case_cannot_hide_restricted_features() {
    let f = Fixture::new();
    for (index, feature) in features().iter().enumerate() {
        let feature = Feature {
            mime: feature.mime.to_uppercase(),
            relation: feature.relation.clone(),
            payload: feature.payload,
        };
        f.feature(&feature, true, false, false, false);
        f.blocked(if index < 3 {
            "digital-signatures"
        } else {
            "macros"
        });
    }
}
#[test]
fn test_complete_relocated_signature_metadata_chain_is_not_dropped() {
    let f = Fixture::new();
    let features = features();
    let mut m = f.feature(&features[0], true, true, false, false);
    m.insert("opaque/proof.xml".into(), features[1].payload.to_vec());
    m.insert("opaque/cert.bin".into(), features[2].payload.to_vec());
    for (part, feature) in [
        ("opaque/proof.xml", &features[1]),
        ("opaque/cert.bin", &features[2]),
    ] {
        append(
            &mut m,
            "[Content_Types].xml",
            "</Types>",
            &format!(
                "<Override PartName=\"/{part}\" ContentType=\"{}\"/>",
                feature.mime
            ),
        );
    }
    for (name, suffix, target) in [
        ("object.dat", "signature", "proof.xml"),
        ("proof.xml", "certificate", "cert.bin"),
    ] {
        m.insert(format!("opaque/_rels/{name}.rels"),format!("<Relationships xmlns=\"{}\"><Relationship Id=\"r1\" Type=\"{SIG}{suffix}\" Target=\"{target}\"/></Relationships>",d::R).into_bytes());
    }
    f.write(&m);
    let report = d::inspect_package(&f.source).unwrap();
    assert_eq!(
        report["relationships"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["type"].as_str().unwrap().starts_with(SIG))
            .count(),
        3
    );
    f.blocked("digital-signatures");
    assert_eq!(read_zip(&f.source), m);
}
#[test]
fn test_public_inspect_reports_restriction_and_edit_preserves_delivery() {
    let f = Fixture::new();
    f.feature(&features()[0], true, true, false, false);
    let before = fs::read(&f.source).unwrap();
    fs::write(&f.output, b"previous approved delivery").unwrap();
    let report = f.root.join("report.json");
    let patch_file = f.root.join("patch.json");
    fs::write(
        &patch_file,
        serde_json::to_vec(&patch("Original text", "Changed")).unwrap(),
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_revayat-scientific");
    use revayat_scientific::runtime::{CommandSpec, run};
    let inspected = run(&CommandSpec::new(binary).args([
        std::ffi::OsStr::new("docx"),
        std::ffi::OsStr::new("inspect"),
        f.source.as_os_str(),
        std::ffi::OsStr::new("--output"),
        report.as_os_str(),
    ]))
    .unwrap();
    assert!(
        inspected.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let inventory: Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    assert!(
        inventory["unsupported"]
            .as_array()
            .unwrap()
            .contains(&json!("digital-signatures"))
    );
    let edited = run(&CommandSpec::new(binary).args([
        std::ffi::OsStr::new("docx"),
        std::ffi::OsStr::new("edit"),
        f.source.as_os_str(),
        f.output.as_os_str(),
        std::ffi::OsStr::new("--patch"),
        patch_file.as_os_str(),
    ]))
    .unwrap();
    assert!(!edited.success());
    assert_eq!(fs::read(&f.output).unwrap(), b"previous approved delivery");
    assert_eq!(fs::read(&f.source).unwrap(), before);
}
