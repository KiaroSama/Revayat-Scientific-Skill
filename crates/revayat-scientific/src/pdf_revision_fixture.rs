//! Small native fixtures for private renderer orchestration regressions.
use crate::identity::{Fingerprint, file_identity};
use anyhow::Result;
use lopdf::{Document, Object, Stream, dictionary};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub struct Fixture {
    pub temp: tempfile::TempDir,
    pub source: PathBuf,
    pub replacement: PathBuf,
}
impl Fixture {
    pub fn new(pages: usize) -> Self {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let source = temp.path().join("source.pdf");
        let replacement = temp.path().join("replacement.pdf");
        document(pages, "source-A").save(&source).unwrap();
        document(pages, "source-B").save(&replacement).unwrap();
        Self {
            temp,
            source,
            replacement,
        }
    }
    pub fn substitute(&self) -> Result<()> {
        fs::rename(&self.source, self.temp.path().join("held.pdf"))?;
        fs::copy(&self.replacement, &self.source)?;
        Ok(())
    }
    pub fn restore(&self) -> Result<()> {
        fs::remove_file(&self.source)?;
        fs::rename(self.temp.path().join("held.pdf"), &self.source)?;
        Ok(())
    }
}
fn document(count: usize, marker: &str) -> Document {
    let mut doc = Document::with_version("1.7");
    let pages = doc.new_object_id();
    let mut kids = Vec::new();
    for _ in 0..count {
        let stream = doc.add_object(Stream::new(
            dictionary! {},
            format!("q 0 0 0 rg 10 10 20 20 re f Q % {marker}\n").into_bytes(),
        ));
        let page = doc.add_object(dictionary! {"Type"=>"Page", "Parent"=>pages, "Contents"=>stream, "Resources"=>dictionary!{}, "MediaBox"=>vec![0.into(), 0.into(), 100.into(), 100.into()]});
        kids.push(Object::Reference(page));
    }
    doc.objects.insert(
        pages,
        Object::Dictionary(dictionary! {"Type"=>"Pages", "Kids"=>kids, "Count"=>count as i64}),
    );
    let catalog = doc.add_object(dictionary! {"Type"=>"Catalog", "Pages"=>pages});
    doc.trailer.set("Root", catalog);
    doc
}
pub fn png(path: &Path, color: u8) -> Result<Fingerprint> {
    image::RgbImage::from_pixel(8, 8, image::Rgb([color, 30, 80])).save(path)?;
    file_identity(path, Some(crate::pdf::MAX_PDF_BYTES))
}
