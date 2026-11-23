#[path = "common/pdf.rs"]
mod common;
use lopdf::{Stream, dictionary};
use revayat_scientific::{pdf::PdfBoundary, pdf_extract};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

fn fixture() -> common::Fixture {
    let fixture = common::Fixture::new();
    let mut doc = common::blank();
    let page = common::pages(&doc)[0];
    let image = doc.add_object(Stream::new(dictionary! {"Type"=>"XObject", "Subtype"=>"Image", "Width"=>2, "Height"=>2, "BitsPerComponent"=>8, "ColorSpace"=>"DeviceRGB"}, vec![10_u8; 12]));
    doc.get_dictionary_mut(page).unwrap().set(
        "Resources",
        dictionary! {"XObject"=>dictionary! {"I"=>image}},
    );
    doc.change_page_content(page, b"q 20 0 0 20 0 0 cm /I Do Q".to_vec())
        .unwrap();
    fixture.save(doc);
    fixture
}
fn contents(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (path.file_name().unwrap().into(), fs::read(path).unwrap())
        })
        .collect()
}

#[test]
fn image_export_rejects_a_valid_earlier_stage_substitution() {
    let f = fixture();
    let output = f.temp.path().join("images");
    pdf_extract::extract_images(&f.source, &output).unwrap();
    let previous = contents(&output);
    let original = fs::read(&f.source).unwrap();
    let mut first = None::<PathBuf>;
    let mut reached = false;
    let result = pdf_extract::extract_images_observed(&f.source, &output, |boundary, path| {
        if boundary == PdfBoundary::StageWritten {
            if let Some(first) = &first {
                image::RgbImage::from_pixel(2, 2, image::Rgb([250, 0, 0])).save(first)?;
                reached = true;
            } else if path.extension().is_some_and(|e| e == "png") {
                first = Some(path.to_owned());
            }
        }
        Ok(())
    });
    assert!(
        reached,
        "a complete encoded image must be substituted at a later stage boundary"
    );
    assert!(
        result.is_err(),
        "a substituted extracted image was published"
    );
    assert_eq!(contents(&output), previous);
    assert_eq!(fs::read(&f.source).unwrap(), original);
}

#[test]
fn unchanged_image_export_preserves_native_content_and_manifest() {
    let f = fixture();
    let output = f.temp.path().join("images");
    pdf_extract::extract_images(&f.source, &output).unwrap();
    let previous = contents(&output);
    pdf_extract::extract_images(&f.source, &output).unwrap();
    assert_eq!(contents(&output), previous);
    assert!(previous.contains_key(Path::new("images.json")));
}
