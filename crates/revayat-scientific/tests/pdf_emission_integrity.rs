#[path = "common/pdf.rs"]
mod common;
use revayat_scientific::pdf::{self, PdfBoundary};
use std::fs;

#[test]
fn replacing_serialized_bytes_before_readback_preserves_previous_pdf() {
    let fixture = common::Fixture::new();
    let mut doc = common::document(1);
    fixture.save(doc.clone());
    fixture.previous();
    let source = fs::read(&fixture.source).unwrap();
    let geometry = pdf::geometry(&doc).unwrap();
    let mut reached = false;
    let result = pdf::save_document_observed(
        &mut doc,
        &fixture.output,
        std::slice::from_ref(&fixture.source),
        &geometry,
        |_| Ok(()),
        |boundary, path| {
            if boundary == PdfBoundary::BytesWritten {
                let mut replacement = common::blank();
                replacement.change_page_content(
                    common::pages(&replacement)[0],
                    b"BT /F1 12 Tf 30 250 Td (Substituted result) Tj ET".to_vec(),
                )?;
                assert_eq!(pdf::geometry(&replacement)?, geometry);
                replacement.save(path)?;
                reached = true;
            }
            Ok(())
        },
    );
    assert!(reached, "the bytes-written substitution must execute");
    assert!(
        result.is_err(),
        "replacement became the expected serializer output"
    );
    fixture.preserved();
    assert_eq!(fs::read(&fixture.source).unwrap(), source);
    assert_eq!(fs::read_dir(fixture.temp.path()).unwrap().count(), 2);
}

#[test]
fn extraction_binds_the_parser_to_the_original_source_snapshot() {
    let fixture = common::Fixture::new();
    fixture.save(common::document(1));
    fixture.previous();
    let original = fs::read(&fixture.source).unwrap();
    let modified = fs::metadata(&fixture.source).unwrap().modified().unwrap();
    let mut foreign = common::document(1);
    foreign
        .change_page_content(
            common::pages(&foreign)[0],
            b"BT /F1 12 Tf 30 250 Td (Foreign scientific content) Tj ET".to_vec(),
        )
        .unwrap();
    let mut replacement = Vec::new();
    foreign.save_to(&mut replacement).unwrap();
    let mut captured = false;
    let mut restored = false;
    let result = pdf::extract_pages_observed(
        &fixture.source,
        &fixture.output,
        1,
        1,
        pdf::AdmissionLimits::default(),
        |boundary, _| {
            if boundary == PdfBoundary::SourceCaptured {
                fs::write(&fixture.source, &replacement)?;
                captured = true;
            }
            if boundary == PdfBoundary::StageWritten {
                fs::write(&fixture.source, &original)?;
                fs::File::options()
                    .write(true)
                    .open(&fixture.source)?
                    .set_times(fs::FileTimes::new().set_modified(modified))?;
                restored = true;
            }
            Ok(())
        },
    );
    assert!(captured, "the initial admission boundary must execute");
    assert!(
        result.is_err(),
        "independently admitted foreign PDF was published"
    );
    fixture.preserved();
    assert_eq!(
        fs::read(&fixture.source).unwrap(),
        if restored { original } else { replacement }
    );
    assert_eq!(fs::read_dir(fixture.temp.path()).unwrap().count(), 2);
}

#[test]
fn ocr_keeps_the_source_revision_admitted_before_tool_discovery() {
    let fixture = common::Fixture::new();
    fixture.save(common::document(1));
    fixture.previous();
    let mut foreign = None;
    let result = revayat_scientific::pdf_ocr::ocr_with_tools(
        &fixture.source,
        &fixture.output,
        "eng",
        300,
        120,
        || Ok(std::path::PathBuf::from("test-tesseract")),
        |spec| {
            assert_eq!(spec.args, [std::ffi::OsString::from("--list-langs")]);
            let mut replacement = common::document(1);
            replacement.change_page_content(
                common::pages(&replacement)[0],
                b"BT /F1 12 Tf 30 250 Td (Foreign already searchable source) Tj ET".to_vec(),
            )?;
            replacement.save(&fixture.source)?;
            foreign = Some(fs::read(&fixture.source)?);
            Ok(revayat_scientific::runtime::CommandOutput {
                code: 0,
                stdout: b"eng\n".to_vec(),
                stderr: Vec::new(),
            })
        },
    );
    let foreign = foreign.expect("actual language-query boundary must execute");
    assert!(
        result.is_err(),
        "OCR silently admitted a later source revision"
    );
    fixture.preserved();
    assert_eq!(fs::read(&fixture.source).unwrap(), foreign);
    assert_eq!(fs::read_dir(fixture.temp.path()).unwrap().count(), 2);
}
