#![allow(dead_code)]
use revayat_scientific::images;
use serde_json::json;
use std::{fs, path::PathBuf};
pub struct F {
    pub _t: tempfile::TempDir,
    pub image: PathBuf,
    pub review: PathBuf,
}
impl F {
    pub fn new() -> Self {
        let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let image = t.path().join("figure.png");
        let review = t.path().join("figure.png.review.json");
        let mut pixels = image::RgbImage::from_pixel(100, 100, image::Rgb([0, 0, 0]));
        for i in (10..90).step_by(10) {
            pixels.put_pixel(i, i, image::Rgb([255, 255, 255]));
        }
        pixels.save(&image).unwrap();
        Self {
            _t: t,
            image,
            review,
        }
    }
    pub fn approve(&self) {
        let hash = revayat_scientific::identity::file_identity(&self.image, None)
            .unwrap()
            .sha256;
        fs::write(&self.review,serde_json::to_vec(&json!({"version":1,"sha256":hash,"decision":"preserve-dark-original","note":"Compared with source page; original dark background."})).unwrap()).unwrap();
    }
    pub fn check(&self) -> images::Inspection {
        images::inspect(&self.image).unwrap()
    }
}
