use super::*;
#[test]
fn test_noncanonical_signature_parts_are_reported_and_block_edits() {
    let f = Fixture::new();
    f.signatures(true, true, "signing", false);
    f.blocked("digital-signatures");
}
#[test]
fn test_relationship_signal_alone_cannot_be_hidden_by_generic_content_types() {
    let f = Fixture::new();
    f.signatures(false, true, "signing", false);
    f.blocked("digital-signatures");
}
#[test]
fn test_type_signal_alone_is_conservatively_protected() {
    let f = Fixture::new();
    f.signatures(true, false, "signing", false);
    f.blocked("digital-signatures");
}
#[test]
fn test_mime_case_does_not_hide_package_signature_metadata() {
    let f = Fixture::new();
    f.signatures(true, false, "signing", true);
    f.blocked("digital-signatures");
}
#[test]
fn test_conventional_signature_directory_policy_remains_in_force() {
    let f = Fixture::new();
    f.signatures(false, false, "_xmlsignatures", false);
    f.blocked("digital-signatures");
}
#[test]
fn test_readonly_inventory_preserves_metadata_and_document_text() {
    let f = Fixture::new();
    let m = f.signatures(true, true, "signing", false);
    let before = fs::read(&f.source).unwrap();
    let report = d::inspect_package(&f.source).unwrap();
    assert_eq!(report["validation"], "structural-only");
    assert_eq!(report["render_status"], "not-performed");
    assert!(has_node(&report, "word/document.xml", "Original text"));
    assert!(
        report["unsupported"]
            .as_array()
            .unwrap()
            .contains(&json!("digital-signatures"))
    );
    assert_eq!(fs::read(&f.source).unwrap(), before);
    assert_eq!(read_zip(&f.source), m);
}
#[test]
fn test_ordinary_unsigned_package_still_edits_with_exact_other_parts() {
    let f = Fixture::new();
    let m = real();
    f.write(&m);
    let before = fs::read(&f.source).unwrap();
    f.patch("word/document.xml", "Original text", "Edited text");
    let expected = String::from_utf8(m["word/document.xml"].clone())
        .unwrap()
        .replace("Original text", "Edited text");
    exact_except(
        &m,
        &read_zip(&f.output),
        "word/document.xml",
        expected.as_bytes(),
    );
    assert_eq!(fs::read(&f.source).unwrap(), before);
}
#[test]
fn test_arbitrary_signature_word_or_foreign_uri_is_not_opc_signature_metadata() {
    let f = Fixture::new();
    let mut m = f.signatures(false, false, "signing", false);
    append(
        &mut m,
        "_rels/.rels",
        "</Relationships>",
        "<Relationship Id=\"example\" Type=\"https://example.invalid/digital-signature/origin\" Target=\"/signing/origin.sigs\"/>",
    );
    f.write(&m);
    assert!(
        !d::read_package(&f.source)
            .unwrap()
            .unsupported
            .contains(&"digital-signatures".into())
    );
    f.patch("word/document.xml", "Original text", "Edited text");
    assert!(f.output.is_file());
}
