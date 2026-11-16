use super::*;

#[test]
fn built_in_paragraph_styles_retain_numbering_and_theme_dependencies() {
    let f = Fixture::new();
    let mut specification = content(json!({"text":"Scientific text"}));
    specification["sections"][0]["blocks"] = json!([
        {"type":"paragraph","style":"Heading 9","text":"Last heading"},
        {"type":"paragraph","style":"List Bullet","text":"A listed quantity"},
        {"type":"paragraph","style":"Title","text":"Scientific title"},
        {"type":"paragraph","style":"Quote","text":"A quotation"}
    ]);
    create(&f, &specification);
    let members = read_zip(&f.source);
    let body = std::str::from_utf8(&members["word/document.xml"]).unwrap();
    for style in ["Heading9", "ListBullet", "Title", "Quote"] {
        assert!(body.contains(&format!("w:pStyle w:val=\"{style}\"")));
    }
    let styles =
        roxmltree::Document::parse(std::str::from_utf8(&members["word/styles.xml"]).unwrap())
            .unwrap();
    let bullet = styles
        .descendants()
        .find(|n| {
            n.has_tag_name((d::W, "style")) && n.attribute((d::W, "styleId")) == Some("ListBullet")
        })
        .unwrap();
    assert!(
        bullet
            .descendants()
            .any(|n| n.has_tag_name((d::W, "numPr")))
    );
    assert!(members.contains_key("word/numbering.xml"));
    assert!(members.contains_key("word/theme/theme1.xml"));
    let inventory = d::inspect_package(&f.source).unwrap();
    for kind in ["numbering", "theme", "fontTable", "styles"] {
        assert!(
            inventory["relationships"]
                .as_array()
                .unwrap()
                .iter()
                .any(
                    |r| r["type"].as_str().unwrap().ends_with(&format!("/{kind}"))
                        && r["resolved"].is_string()
                )
        );
    }
    let input = f.root.join("unknown-style.json");
    specification["sections"][0]["blocks"][0]["style"] = json!("Unknown private style");
    fs::write(&input, serde_json::to_vec(&specification).unwrap()).unwrap();
    fs::write(&f.output, b"approved output").unwrap();
    assert!(d::create_document(&input, &f.output).is_err());
    assert_eq!(fs::read(&f.output).unwrap(), b"approved output");
}

#[test]
#[ignore = "requires the scientific rendering tier: LibreOffice Writer and Poppler"]
fn native_created_sections_tables_and_images_render_at_requested_geometry() {
    use revayat_scientific::{
        pdf,
        runtime::{CommandSpec, executable, run},
    };
    let f = Fixture::new();
    let image_path = f.root.join("figure.png");
    image::RgbImage::from_pixel(24, 12, image::Rgb([20, 80, 120]))
        .save(&image_path)
        .unwrap();
    let specification: Value =
        serde_json::from_str(include_str!("../../../../tests/fixtures/docx-content.json")).unwrap();
    create(&f, &specification);
    let office = executable("libreoffice")
        .or_else(|_| executable("soffice"))
        .expect("required DOCX creation render needs LibreOffice Writer");
    let profile = url::Url::from_directory_path(f.root.join("office-profile")).unwrap();
    let rendered = run(&CommandSpec::new(office).args([
        format!("-env:UserInstallation={profile}"),
        "--headless".into(),
        "--convert-to".into(),
        "pdf".into(),
        "--outdir".into(),
        f.root.to_string_lossy().into_owned(),
        f.source.to_string_lossy().into_owned(),
    ]))
    .unwrap();
    assert!(rendered.success(), "{}", rendered.stderr_text());
    let pdf_path = f.source.with_extension("pdf");
    let document = pdf::open_pdf(&pdf_path, false).unwrap();
    let geometry = pdf::geometry(&document).unwrap();
    assert_eq!(geometry.len(), 2);
    for (page, (width, height)) in geometry.iter().zip([(160., 240.), (240., 160.)]) {
        assert!((page.rect[2] - width / 25.4 * 72.).abs() < 0.2);
        assert!((page.rect[3] - height / 25.4 * 72.).abs() < 0.2);
    }
    let extracted = run(&CommandSpec::new(executable("pdftotext").unwrap())
        .args([pdf_path.as_os_str(), std::ffi::OsStr::new("-")]))
    .unwrap();
    assert!(extracted.success());
    assert!(extracted.stdout_text().contains("Scientific example"));
    assert!(extracted.stdout_text().contains("23.5"));
    let png = f.root.join("created-page");
    let rasterized = run(&CommandSpec::new(executable("pdftoppm").unwrap()).args([
        "-f".into(),
        "1".into(),
        "-singlefile".into(),
        "-png".into(),
        "-scale-to".into(),
        "500".into(),
        pdf_path.into_os_string(),
        png.clone().into_os_string(),
    ]))
    .unwrap();
    assert!(rasterized.success());
    let pixels = image::open(png.with_extension("png")).unwrap().to_rgb8();
    let image_pixels = pixels
        .pixels()
        .filter(|p| {
            p.0.iter()
                .zip([20_i16, 80, 120])
                .all(|(&actual, wanted)| (actual as i16 - wanted).abs() <= 3)
        })
        .count();
    assert!(
        image_pixels > 50,
        "the retained source image must be visibly present in the native document render"
    );
}
