#[path = "common/image.rs"]
mod common;
use common::*;
use image::ImageEncoder;
use revayat_scientific::images;
use std::fs;
fn snapshot(dir: &std::path::Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fs::read_dir(dir)
        .unwrap()
        .map(|p| p.unwrap().path())
        .filter(|p| p.is_file())
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into(),
                fs::read(p).unwrap(),
            )
        })
        .collect()
}
#[test]
fn test_collision_preserves_entire_batch() {
    let f = F::new();
    image::RgbaImage::from_pixel(12, 10, image::Rgba([0, 255, 0, 120]))
        .save(&f.image)
        .unwrap();
    image::RgbImage::from_pixel(12, 10, image::Rgb([255, 0, 0]))
        .save(f.image.with_extension("jpg"))
        .unwrap();
    let before = snapshot(f._t.path());
    assert!(images::prepare(&[f._t.path().to_owned()], false).is_err());
    assert_eq!(snapshot(f._t.path()), before);
}
#[test]
fn test_depth_frames_and_invalid_profile_refuse_without_mutation() {
    let f = F::new();
    {
        let mut info = png::Info::with_size(5, 5);
        info.color_type = png::ColorType::Rgba;
        info.bit_depth = png::BitDepth::Eight;
        info.icc_profile = Some(b"invalid".as_slice().into());
        png::Encoder::with_info(fs::File::create(&f.image).unwrap(), info)
            .unwrap()
            .write_header()
            .unwrap()
            .write_image_data(&[255; 100])
            .unwrap();
    }
    let before = snapshot(f._t.path());
    assert!(images::prepare(std::slice::from_ref(&f.image), false).is_err());
    assert_eq!(snapshot(f._t.path()), before);
    let tiff = f.image.with_extension("tiff");
    {
        let mut enc = tiff::encoder::TiffEncoder::new(fs::File::create(&tiff).unwrap()).unwrap();
        enc.write_image::<tiff::encoder::colortype::Gray16>(4, 1, &[256, 512, 1024, 65535])
            .unwrap();
    }
    assert!(images::inspect(&tiff).is_err());
    {
        let mut enc = tiff::encoder::TiffEncoder::new(fs::File::create(&tiff).unwrap()).unwrap();
        enc.write_image::<tiff::encoder::colortype::RGB8>(2, 2, &[0; 12])
            .unwrap();
        enc.write_image::<tiff::encoder::colortype::RGB8>(2, 2, &[255; 12])
            .unwrap();
    }
    assert!(images::inspect(&tiff).is_err());
}
#[test]
fn test_rgb16_png_is_refused_before_lazy_metadata_decodes_pixels() {
    let f = F::new();
    {
        let mut encoder = png::Encoder::new(fs::File::create(&f.image).unwrap(), 1, 1);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Sixteen);
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&[1, 0, 2, 0, 4, 0])
            .unwrap();
    }
    let original = fs::read(&f.image).unwrap();
    assert!(images::inspect(&f.image).is_err());
    assert!(images::prepare(std::slice::from_ref(&f.image), true).is_err());
    assert_eq!(fs::read(&f.image).unwrap(), original);
    assert!(!f.image.with_file_name("figure.png.orig").exists());
}
#[test]
fn test_transparency_forms_and_check_only() {
    for kind in 0..5 {
        let f = F::new();
        {
            let mut info = png::Info::with_size(8, 6);
            info.bit_depth = png::BitDepth::Eight;
            let data = match kind {
                0 => {
                    info.color_type = png::ColorType::Rgba;
                    [10, 20, 30, 0].repeat(48)
                }
                1 => {
                    info.color_type = png::ColorType::GrayscaleAlpha;
                    [10, 0].repeat(48)
                }
                2 => {
                    info.color_type = png::ColorType::Indexed;
                    info.palette = Some(vec![0, 0, 0].into());
                    info.trns = Some(vec![0].into());
                    vec![0; 48]
                }
                3 => {
                    info.color_type = png::ColorType::Grayscale;
                    info.trns = Some(vec![0, 0].into());
                    vec![0; 48]
                }
                _ => {
                    info.color_type = png::ColorType::Rgb;
                    info.trns = Some(vec![0, 10, 0, 20, 0, 30].into());
                    [10, 20, 30].repeat(48)
                }
            };
            png::Encoder::with_info(fs::File::create(&f.image).unwrap(), info)
                .unwrap()
                .write_header()
                .unwrap()
                .write_image_data(&data)
                .unwrap();
        }
        let before = fs::read(&f.image).unwrap();
        assert!(f.check().requires_review);
        assert_eq!(fs::read(&f.image).unwrap(), before);
        images::prepare(std::slice::from_ref(&f.image), false).unwrap();
        assert_eq!(
            fs::read(f.image.with_file_name("figure.png.orig")).unwrap(),
            before
        );
        assert_eq!(
            image::open(&f.image).unwrap().to_rgb8().get_pixel(0, 0).0,
            [255; 3]
        );
        assert!(!f.check().requires_review);
        assert_eq!(
            images::prepare(std::slice::from_ref(&f.image), false).unwrap(),
            0
        );
    }
}
fn exif_orientation() -> Vec<u8> {
    let mut data = vec![
        b'I', b'I', 42, 0, 8, 0, 0, 0, 2, 0, 0x12, 1, 3, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0x0e, 1, 2, 0,
        9, 0, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0,
    ];
    data.extend_from_slice(b"reviewed\0");
    data
}

#[test]
fn test_unsupported_color_and_orientation_metadata_preserve_original() {
    let f = F::new();
    {
        let mut info = png::Info::with_size(8, 4);
        info.color_type = png::ColorType::Rgba;
        info.bit_depth = png::BitDepth::Eight;
        info.exif_metadata = Some(exif_orientation().into());
        info.utf8_text.push(png::text_metadata::ITXtChunk::new(
            "XML:com.adobe.xmp",
            "<tiff:Orientation>6</tiff:Orientation>",
        ));
        png::Encoder::with_info(fs::File::create(&f.image).unwrap(), info)
            .unwrap()
            .write_header()
            .unwrap()
            .write_image_data(&[30; 128])
            .unwrap();
    }
    let before = fs::read(&f.image).unwrap();
    assert!(images::prepare(std::slice::from_ref(&f.image), false).is_err());
    assert_eq!(fs::read(&f.image).unwrap(), before);
    {
        let mut info = png::Info::with_size(8, 4);
        info.color_type = png::ColorType::Rgba;
        info.bit_depth = png::BitDepth::Eight;
        info.utf8_text.push(png::text_metadata::ITXtChunk::new(
            "XML:com.adobe.xmp",
            "<xmp:Label>Reviewed</xmp:Label>",
        ));
        png::Encoder::with_info(fs::File::create(&f.image).unwrap(), info)
            .unwrap()
            .write_header()
            .unwrap()
            .write_image_data(&[30; 128])
            .unwrap();
    }
    images::prepare(std::slice::from_ref(&f.image), false).unwrap();
    let reader = png::Decoder::new(std::io::Cursor::new(fs::read(&f.image).unwrap()))
        .read_info()
        .unwrap();
    assert_eq!(
        reader.info().utf8_text[0].get_text().unwrap(),
        "<xmp:Label>Reviewed</xmp:Label>"
    );
}
#[test]
fn test_metadata_orientation_and_source_preservation() {
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let source = t.path().join("portrait.jpg");
    let mut profile = vec![0u8; 132];
    profile[..4].copy_from_slice(&132u32.to_be_bytes());
    profile[16..20].copy_from_slice(b"RGB ");
    profile[36..40].copy_from_slice(b"acsp");
    let pixels = image::RgbImage::from_pixel(8, 4, image::Rgb([100, 150, 200]));
    {
        let mut encoder = image::codecs::jpeg::JpegEncoder::new(fs::File::create(&source).unwrap());
        encoder.set_pixel_density(image::codecs::jpeg::PixelDensity {
            density: (144, 288),
            unit: image::codecs::jpeg::PixelDensityUnit::Inches,
        });
        encoder.set_exif_metadata(exif_orientation()).unwrap();
        encoder.set_icc_profile(profile.clone()).unwrap();
        encoder.encode_image(&pixels).unwrap();
    }
    let before = fs::read(&source).unwrap();
    let mut expected = image::open(&source).unwrap();
    expected.apply_orientation(image::metadata::Orientation::Rotate90);
    images::prepare(std::slice::from_ref(&source), false).unwrap();
    let png = source.with_extension("png");
    assert_eq!(image::open(&png).unwrap().to_rgb8(), expected.to_rgb8());
    let reader = png::Decoder::new(std::io::Cursor::new(fs::read(png).unwrap()))
        .read_info()
        .unwrap();
    assert_eq!(
        reader.info().icc_profile.as_deref(),
        Some(profile.as_slice())
    );
    let tags = exif::Reader::new()
        .read_raw(reader.info().exif_metadata.as_ref().unwrap().to_vec())
        .unwrap();
    assert!(
        tags.get_field(exif::Tag::Orientation, exif::In::PRIMARY)
            .is_none()
    );
    let description = tags
        .get_field(exif::Tag::ImageDescription, exif::In::PRIMARY)
        .unwrap();
    assert!(matches!(&description.value,exif::Value::Ascii(v) if v[0]==b"reviewed"));
    let dpi = reader.info().pixel_dims.unwrap();
    assert!((dpi.xppu as f64 * 0.0254 - 288.).abs() < 0.02);
    assert!((dpi.yppu as f64 * 0.0254 - 144.).abs() < 0.02);
    assert_eq!(fs::read(source).unwrap(), before);
}
#[test]
fn test_repeated_arguments_existing_backup_and_unavailable_backend() {
    let f = F::new();
    image::RgbaImage::from_pixel(6, 6, image::Rgba([20, 30, 40, 20]))
        .save(&f.image)
        .unwrap();
    let before = snapshot(f._t.path());
    for paths in [
        vec![f.image.clone(), f.image.clone()],
        vec![f._t.path().to_owned(), f.image.clone()],
    ] {
        assert!(images::prepare(&paths, false).is_err());
        assert_eq!(snapshot(f._t.path()), before);
    }
    fs::write(
        f.image.with_file_name("figure.png.orig"),
        b"unrelated original",
    )
    .unwrap();
    let before = snapshot(f._t.path());
    assert!(images::prepare(std::slice::from_ref(&f.image), false).is_err());
    assert_eq!(snapshot(f._t.path()), before);
    let invalid = f._t.path().join("invalid.webp");
    fs::write(&invalid, b"not decodable").unwrap();
    assert!(images::inspect(&invalid).is_err());
}
#[test]
fn test_save_and_publication_failure_roll_back_full_batch() {
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let mut paths = Vec::new();
    for name in ["first.png", "second.png"] {
        let p = t.path().join(name);
        image::RgbaImage::from_pixel(6, 6, image::Rgba([20, 30, 40, 20]))
            .save(&p)
            .unwrap();
        paths.push(p);
    }
    let before = snapshot(t.path());
    assert!(
        images::prepare_observed(&paths, false, |b, p| {
            if b == images::Boundary::BeforeEncode && p.file_name().unwrap() == "second.png" {
                anyhow::bail!("injected encode failure");
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(snapshot(t.path()), before);
    assert!(
        images::prepare_observed(&paths, false, |b, p| {
            if b == images::Boundary::Publication(
                revayat_scientific::publication::Boundary::BeforeCommit,
            ) && p.file_name().unwrap() == "second.png"
            {
                anyhow::bail!("injected publish failure");
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(snapshot(t.path()), before);
    assert!(
        fs::read_dir(t.path())
            .unwrap()
            .all(|p| p.unwrap().path().is_file())
    );
}
