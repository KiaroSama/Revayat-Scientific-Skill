use super::*;
#[test]
fn test_story_tree_is_walked_once_not_once_per_patch() {
    let f = Fixture::new();
    batch(&f, 300);
    let mut visits = Vec::new();
    d::edit_package_observed(&f.source, &f.output, &edits(300), &[], |event| {
        if let d::EditEvent::StoryIndexed { part, text_nodes } = event {
            visits.push((part.to_owned(), text_nodes));
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(visits, vec![("word/document.xml".to_owned(), 300)]);
    assert!(has_node(
        &d::inspect_package(&f.output).unwrap(),
        "word/document.xml",
        "ترجمه 299"
    ));
}
#[test]
fn test_multistory_unsorted_edits_preserve_all_untouched_bytes() {
    let f = Fixture::new();
    let m = batch(&f, 1500);
    let before = fs::read(&f.source).unwrap();
    let mut changes = edits(1500);
    changes.as_array_mut().unwrap().extend([
        json!({"part":"word/header1.xml","index":0,"expected":"Header","text":" A & <B> "}),
        json!({"part":"word/header1.xml","index":1,"expected":"","text":"Empty filled"}),
    ]);
    d::edit_package(&f.source, &f.output, &changes, &[]).unwrap();
    let mut expected = m.clone();
    for i in 0..1500 {
        replace(
            &mut expected,
            "word/document.xml",
            &format!("<w:t>Original {i}</w:t>"),
            &format!("<w:t>ترجمه {i}</w:t>"),
        );
    }
    replace(
        &mut expected,
        "word/header1.xml",
        "<w:t>Header</w:t>",
        "<w:t xml:space=\"preserve\"> A &amp; &lt;B&gt; </w:t>",
    );
    replace(
        &mut expected,
        "word/header1.xml",
        "<w:t/>",
        "<w:t>Empty filled</w:t>",
    );
    assert_eq!(read_zip(&f.output), expected);
    let z = ZipArchive::new(File::open(&f.output).unwrap()).unwrap();
    assert_eq!(z.comment(), b"untouched package comment");
    assert_eq!(fs::read(&f.source).unwrap(), before);
}
#[test]
fn test_late_stale_patch_preserves_destination() {
    let f = Fixture::new();
    batch(&f, 100);
    let before = fs::read(&f.source).unwrap();
    fs::write(&f.output, b"previous approved output").unwrap();
    let mut changes = edits(100);
    changes[99]["expected"] = json!("stale");
    assert!(
        d::edit_package(&f.source, &f.output, &changes, &[])
            .unwrap_err()
            .to_string()
            .contains("stale")
    );
    assert_eq!(fs::read(&f.source).unwrap(), before);
    assert_eq!(fs::read(&f.output).unwrap(), b"previous approved output");
    f.clean();
}
#[test]
fn test_duplicate_addresses_and_invalid_characters_remain_rejected() {
    let f = Fixture::new();
    batch(&f, 10);
    fs::write(&f.output, b"previous").unwrap();
    let one = edits(1);
    for changes in [
        json!([one[0], one[0]]),
        patch("Original 0", "bad\0"),
        patch("Original 0", "bad\u{fffe}"),
    ] {
        assert!(d::edit_package(&f.source, &f.output, &changes, &[]).is_err());
        assert_eq!(fs::read(&f.output).unwrap(), b"previous");
    }
    let p = f.root.join("surrogate.json");
    fs::write(
        &p,
        br#"[{"part":"word/document.xml","index":0,"expected":"Original 0","text":"bad\ud800"}]"#,
    )
    .unwrap();
    assert!(d::load_json(&p).is_err());
}
#[test]
fn test_growing_part_limit_preserves_existing_delivery() {
    let f = Fixture::new();
    batch(&f, 2);
    fs::write(&f.output, b"previous").unwrap();
    let mut changes = edits(2);
    changes[0]["text"] = json!("x".repeat(d::MAX_XML));
    assert!(
        d::edit_package(&f.source, &f.output, &changes, &[])
            .unwrap_err()
            .to_string()
            .contains("16 MiB")
    );
    assert_eq!(fs::read(&f.output).unwrap(), b"previous");
}
#[test]
fn test_late_publication_failure_does_not_destroy_previous_output() {
    let f = Fixture::new();
    batch(&f, 40);
    fs::write(&f.output, b"previous").unwrap();
    fail_commit(&f, &edits(40));
    assert_eq!(fs::read(&f.output).unwrap(), b"previous");
}
#[test]
fn test_adjacent_empty_and_nonempty_text_nodes() {
    let f = Fixture::new();
    let mut m = batch(&f, 1);
    let data = document("<w:p><w:r><w:t/><w:t>A &amp; B</w:t><w:t>C</w:t></w:r></w:p>");
    m.insert("word/document.xml".into(), data.clone());
    f.write(&m);
    d::edit_package(&f.source,&f.output,&json!([{"part":"word/document.xml","index":2,"expected":"C","text":""},{"part":"word/document.xml","index":0,"expected":"","text":"<New>"},{"part":"word/document.xml","index":1,"expected":"A & B","text":" A & C "}]),&[]).unwrap();
    let expected = String::from_utf8(data)
        .unwrap()
        .replace("<w:t/>", "<w:t>&lt;New&gt;</w:t>")
        .replace(
            "<w:t>A &amp; B</w:t>",
            "<w:t xml:space=\"preserve\"> A &amp; C </w:t>",
        )
        .replace("<w:t>C</w:t>", "<w:t></w:t>");
    exact_except(
        &m,
        &read_zip(&f.output),
        "word/document.xml",
        expected.as_bytes(),
    );
}
