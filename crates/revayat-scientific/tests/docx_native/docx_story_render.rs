use super::*;
#[test]
#[ignore = "requires the scientific rendering tier: LibreOffice Writer and Poppler"]
fn test_two_page_renamed_header_footer_matches_independent_expected_render() {
    use revayat_scientific::runtime::{CommandSpec, executable, run};
    let office = executable("libreoffice")
        .or_else(|_| executable("soffice"))
        .expect("required DOCX rendering tier needs LibreOffice Writer");
    let raster =
        executable("pdftoppm").expect("required DOCX rendering tier needs Poppler pdftoppm");
    let text =
        executable("pdftotext").expect("required DOCX rendering tier needs Poppler pdftotext");
    let f = Fixture::new();
    let mut members = real();
    for (old, new) in [
        ("word/header1.xml", "word/stories/first.xml"),
        ("word/footer1.xml", "word/stories/last.xml"),
    ] {
        let bytes = members.remove(old).unwrap();
        members.insert(new.into(), bytes);
        replace(
            &mut members,
            "[Content_Types].xml",
            &format!("/{old}"),
            &format!("/{new}"),
        );
        replace(
            &mut members,
            "word/_rels/document.xml.rels",
            &format!("Target=\"{}\"", &old[5..]),
            &format!("Target=\"{}\"", &new[5..]),
        );
    }
    f.write(&members);
    let before = fs::read(&f.source).unwrap();
    let mut expected = members.clone();
    replace(
        &mut expected,
        "word/stories/first.xml",
        "HeaderOriginal",
        "HeaderUpdated",
    );
    replace(
        &mut expected,
        "word/stories/last.xml",
        "FooterOriginal",
        "FooterUpdated",
    );
    replace(
        &mut expected,
        "word/document.xml",
        "<w:t>Original text</w:t>",
        "<w:t>Changed</w:t>",
    );
    let expected_doc = f.root.join("expected.docx");
    write_zip(&expected_doc, &expected, b"untouched package comment");
    d::edit_package(&f.source,&f.output,&json!([{"part":"word/stories/first.xml","index":0,"expected":"HeaderOriginal","text":"HeaderUpdated"},{"part":"word/stories/last.xml","index":0,"expected":"FooterOriginal","text":"FooterUpdated"},{"part":"word/document.xml","index":0,"expected":"Original text","text":"Changed"}]),&[]).unwrap();
    assert_eq!(read_zip(&f.output), expected);
    for (index, path) in [&f.source, &expected_doc, &f.output].iter().enumerate() {
        let profile =
            url::Url::from_directory_path(f.root.join(format!("office-profile-{index}"))).unwrap();
        let output = run(&CommandSpec::new(&office).args([
            format!("-env:UserInstallation={profile}"),
            "--headless".into(),
            "--convert-to".into(),
            "pdf".into(),
            "--outdir".into(),
            f.root.to_string_lossy().into_owned(),
            path.to_string_lossy().into_owned(),
        ]))
        .unwrap();
        assert!(output.success(), "{}", output.stderr_text());
        assert!(path.with_extension("pdf").is_file());
    }
    let original_text = run(&CommandSpec::new(&text)
        .args([f.source.with_extension("pdf").into_os_string(), "-".into()]))
    .unwrap();
    assert!(original_text.success());
    let original_text = original_text.stdout_text();
    let original_pages: Vec<_> = original_text
        .split('\u{c}')
        .filter(|page| !page.trim().is_empty())
        .collect();
    assert_eq!(original_pages.len(), 2);
    assert!(original_pages[0].contains("Original text"));
    assert!(original_pages[1].contains("Scientific body page two: unchanged control."));
    for page in original_pages {
        assert!(page.contains("HeaderOriginal"));
        assert!(page.contains("FooterOriginal"));
    }
    let mut renders = Vec::new();
    for (index, path) in [&expected_doc, &f.output].iter().enumerate() {
        let prefix = f.root.join(format!("pages-{index}"));
        let output = run(&CommandSpec::new(&raster).args([
            "-png".into(),
            "-r".into(),
            "96".into(),
            path.with_extension("pdf").into_os_string(),
            prefix.clone().into_os_string(),
        ]))
        .unwrap();
        assert!(output.success(), "{}", output.stderr_text());
        let mut pages: Vec<_> = fs::read_dir(&f.root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(&format!("pages-{index}-"))
            })
            .collect();
        pages.sort();
        assert_eq!(pages.len(), 2);
        renders.push(
            pages
                .iter()
                .map(|p| {
                    let image = image::open(p).unwrap().to_rgb8();
                    (image.dimensions(), image.into_raw())
                })
                .collect::<Vec<_>>(),
        );
        let output = run(&CommandSpec::new(&text)
            .args([path.with_extension("pdf").into_os_string(), "-".into()]))
        .unwrap();
        assert!(output.success());
        let extracted = output.stdout_text();
        assert_eq!(extracted.matches("HeaderUpdated").count(), 2);
        assert_eq!(extracted.matches("FooterUpdated").count(), 2);
        let page_text: Vec<_> = extracted
            .split('\u{c}')
            .filter(|p| !p.trim().is_empty())
            .collect();
        assert_eq!(page_text.len(), 2);
        assert!(page_text[0].contains("Changed"));
        assert!(!page_text[0].contains("Original text"));
        assert!(page_text[1].contains("Scientific body page two: unchanged control."));
        for page in page_text {
            assert!(page.contains("HeaderUpdated"));
            assert!(page.contains("FooterUpdated"));
            assert!(!page.contains("HeaderOriginal") && !page.contains("FooterOriginal"));
        }
        if index == 1
            && let Some(evidence) = std::env::var_os("SCIENTIFIC_EVIDENCE_DIR")
        {
            fs::create_dir_all(&evidence).unwrap();
            for (page, path) in pages.iter().enumerate() {
                fs::copy(
                    path,
                    Path::new(&evidence).join(format!("docx-stories-page-{}.png", page + 1)),
                )
                .unwrap();
            }
            fs::copy(
                path.with_extension("pdf"),
                Path::new(&evidence).join("docx-stories.pdf"),
            )
            .unwrap();
        }
    }
    assert_eq!(renders[0], renders[1]);
    assert_eq!(fs::read(&f.source).unwrap(), before);
}
