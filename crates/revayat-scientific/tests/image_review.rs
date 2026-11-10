#[path = "common/image.rs"]
mod common;
use common::*;
use revayat_scientific::images;
use serde_json::json;
use std::fs;
#[test]
fn test_unreviewed_dark_original_still_requires_review() {
    let f = F::new();
    let before = fs::read(&f.image).unwrap();
    assert_eq!(
        images::prepare(std::slice::from_ref(&f.image), false).unwrap(),
        0
    );
    assert!(f.check().requires_review);
    assert_eq!(fs::read(&f.image).unwrap(), before);
    assert!(!f.review.exists());
}
#[test]
fn test_valid_review_accepts_exact_original_without_mutation() {
    let f = F::new();
    f.approve();
    let before = (fs::read(&f.image).unwrap(), fs::read(&f.review).unwrap());
    assert!(!f.check().requires_review);
    assert!(f.check().reviewed);
    assert_eq!(
        (fs::read(&f.image).unwrap(), fs::read(&f.review).unwrap()),
        before
    );
    assert!(!f.image.with_file_name("figure.png.orig").exists());
}
#[test]
fn test_stale_review_is_rejected() {
    let f = F::new();
    f.approve();
    let mut image = image::open(&f.image).unwrap().to_rgb8();
    image.put_pixel(0, 0, image::Rgb([100, 100, 100]));
    image.save(&f.image).unwrap();
    let before = fs::read(&f.image).unwrap();
    assert!(
        images::inspect(&f.image)
            .unwrap_err()
            .to_string()
            .contains("stale")
    );
    assert_eq!(fs::read(&f.image).unwrap(), before);
}
#[test]
fn test_invalid_schema_duplicate_keys_and_oversized_review_fail() {
    let f = F::new();
    for bad in [
        json!({"version":true}),
        json!({"version":2}),
        json!({"sha256":"0".repeat(64)}),
        json!({"decision":"allow-all"}),
        json!({"note":""}),
        json!({"unexpected":true}),
    ] {
        f.approve();
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&f.review).unwrap()).unwrap();
        for (k, v) in bad.as_object().unwrap() {
            record[k] = v.clone();
        }
        fs::write(&f.review, record.to_string()).unwrap();
        assert!(images::inspect(&f.image).is_err());
    }
    for raw in [
        b"{\"version\":1,\"version\":1}".to_vec(),
        vec![255],
        vec![b' '; 16385],
        format!("{}{}", "[".repeat(2000), "]".repeat(2000)).into_bytes(),
    ] {
        fs::write(&f.review, raw).unwrap();
        assert!(images::inspect(&f.image).is_err());
    }
}
#[test]
fn test_review_cannot_waive_transparency_depth_or_frames() {
    let f = F::new();
    image::RgbaImage::from_pixel(100, 100, image::Rgba([0, 0, 0, 250]))
        .save(&f.image)
        .unwrap();
    f.approve();
    assert!(f.check().requires_review);
    let path = fs::File::create(&f.image).unwrap();
    {
        let mut encoder = png::Encoder::new(path, 20, 20);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Sixteen);
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&vec![0u8; 800])
            .unwrap();
    }
    f.approve();
    assert!(images::inspect(&f.image).is_err());
    let multi = f.image.with_extension("tiff");
    {
        let mut encoder =
            tiff::encoder::TiffEncoder::new(fs::File::create(&multi).unwrap()).unwrap();
        encoder
            .write_image::<tiff::encoder::colortype::RGB8>(20, 20, &[0; 1200])
            .unwrap();
        encoder
            .write_image::<tiff::encoder::colortype::RGB8>(20, 20, &[0; 1200])
            .unwrap();
    }
    let hash = revayat_scientific::identity::file_identity(&multi, None)
        .unwrap()
        .sha256;
    let review = multi.with_file_name("figure.tiff.review.json");
    fs::write(&review,serde_json::to_vec(&json!({"version":1,"sha256":hash,"decision":"preserve-dark-original","note":"Reviewed multiple frames"})).unwrap()).unwrap();
    let before = (fs::read(&multi).unwrap(), fs::read(&review).unwrap());
    assert!(images::inspect(&multi).is_err());
    assert_eq!(
        (fs::read(&multi).unwrap(), fs::read(&review).unwrap()),
        before
    );
    let animated = f.image.with_extension("gif");
    {
        let mut encoder = gif::Encoder::new(
            fs::File::create(&animated).unwrap(),
            20,
            20,
            &[0, 0, 0, 255, 255, 255],
        )
        .unwrap();
        let frame = gif::Frame {
            width: 20,
            height: 20,
            buffer: std::borrow::Cow::Owned(vec![0; 400]),
            ..Default::default()
        };
        encoder.write_frame(&frame).unwrap();
        encoder.write_frame(&frame).unwrap();
    }
    assert!(images::inspect(&animated).is_err());
}
#[test]
fn test_one_review_does_not_approve_another_asset() {
    let f = F::new();
    f.approve();
    let other = f.image.with_file_name("other.png");
    fs::copy(&f.image, &other).unwrap();
    assert!(!f.check().requires_review);
    assert!(images::inspect(&other).unwrap().requires_review);
    use revayat_scientific::runtime::{CommandSpec, run};
    let binary = env!("CARGO_BIN_EXE_revayat-scientific");
    let batch = run(&CommandSpec::new(binary).args([
        std::ffi::OsStr::new("figures"),
        f.image.as_os_str(),
        other.as_os_str(),
        std::ffi::OsStr::new("--check"),
    ]))
    .unwrap();
    assert_eq!(batch.code, 1);
    let reviewed = run(&CommandSpec::new(binary).args([
        std::ffi::OsStr::new("figures"),
        f.image.as_os_str(),
        std::ffi::OsStr::new("--check"),
    ]))
    .unwrap();
    assert_eq!(reviewed.code, 0);
}
#[test]
fn test_directory_or_linked_review_is_rejected() {
    let f = F::new();
    fs::create_dir(&f.review).unwrap();
    assert!(images::inspect(&f.image).is_err());
    fs::remove_dir(&f.review).unwrap();
    f.approve();
    let target = f.image.with_file_name("target.json");
    fs::rename(&f.review, &target).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, &f.review).unwrap();
        assert!(images::inspect(&f.image).is_err());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::symlink_file;
        symlink_file(&target, &f.review)
            .expect("required Windows linked-review fixture needs symlink capability");
        assert!(images::inspect(&f.image).is_err());
    }
}
#[test]
fn test_opaque_light_control_needs_no_review() {
    let f = F::new();
    image::RgbImage::from_pixel(100, 100, image::Rgb([255, 255, 255]))
        .save(&f.image)
        .unwrap();
    assert!(!f.check().requires_review);
    assert!(!f.review.exists());
}
#[test]
fn test_public_command_honors_review_and_preserves_inputs() {
    let f = F::new();
    f.approve();
    let before = (fs::read(&f.image).unwrap(), fs::read(&f.review).unwrap());
    let output = revayat_scientific::runtime::run(
        &revayat_scientific::runtime::CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific"))
            .args(["figures", f.image.to_str().unwrap(), "--check"]),
    )
    .unwrap();
    assert!(
        output.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("reviewed=true"));
    assert!(!text.contains("Compared with source"));
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("Compared with source")
    );
    assert_eq!(
        (fs::read(&f.image).unwrap(), fs::read(&f.review).unwrap()),
        before
    );
}
#[test]
fn alpha_preparation_retains_exact_backup_and_pixels() {
    let f = F::new();
    image::RgbaImage::from_pixel(10, 10, image::Rgba([30, 60, 90, 128]))
        .save(&f.image)
        .unwrap();
    let raw = fs::read(&f.image).unwrap();
    assert_eq!(
        images::prepare(std::slice::from_ref(&f.image), false).unwrap(),
        1
    );
    assert_eq!(
        fs::read(f.image.with_file_name("figure.png.orig")).unwrap(),
        raw
    );
    let im = image::open(&f.image).unwrap().to_rgb8();
    assert_eq!(im.get_pixel(0, 0).0, [142, 157, 172]);
}
#[test]
fn batch_destination_collision_refuses_before_conversion() {
    let f = F::new();
    let jpg = f.image.with_extension("jpg");
    image::RgbImage::from_pixel(10, 10, image::Rgb([50, 50, 50]))
        .save(&jpg)
        .unwrap();
    let raw = fs::read(&f.image).unwrap();
    assert!(images::prepare(&[f.image.clone(), jpg], true).is_err());
    assert_eq!(fs::read(&f.image).unwrap(), raw);
}
#[test]
fn duplicate_and_hardlinked_inputs_are_refused() {
    let f = F::new();
    assert!(images::iter_images(&[f.image.clone(), f.image.clone()]).is_err());
    let other = f.image.with_file_name("other.png");
    fs::hard_link(&f.image, &other).unwrap();
    assert!(images::iter_images(&[f.image.clone(), other]).is_err());
}
#[test]
fn png_color_metadata_is_never_silently_dropped() {
    let f = F::new();
    {
        let mut encoder = png::Encoder::new(fs::File::create(&f.image).unwrap(), 2, 2);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_source_gamma(png::ScaledFloat::new(0.45455));
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&[0; 12])
            .unwrap();
    }
    assert!(images::inspect(&f.image).is_err());
}
