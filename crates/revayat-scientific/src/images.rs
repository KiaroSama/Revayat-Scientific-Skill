//! Bounded native raster preparation and asset-bound review of dark originals.
//! Review only waives darkness: alpha, frame, depth and color gates still apply.
use crate::identity;
use anyhow::{Context, Result, ensure};
use clap::Parser;
use image::metadata::Orientation;
use image::{DynamicImage, ImageDecoder, ImageFormat, ImageReader};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

pub const MAX_PIXELS: u64 = 50_000_000;
pub const MAX_IMAGE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_REVIEW_BYTES: u64 = 16 * 1024;
const EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "webp", "tif", "tiff"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DarkReview {
    version: u8,
    sha256: String,
    decision: String,
    note: String,
}

/// Reject all existing links, junctions and reparse components, including parents.
pub fn plain_path(path: &Path) -> Result<()> {
    let absolute = std::path::absolute(path)?;
    for part in absolute.ancestors() {
        ensure!(
            !identity::is_link(part)?,
            "path must not traverse a link or junction"
        );
    }
    Ok(())
}

pub fn reviewed_dark_original(source: &Path) -> Result<bool> {
    let review = source.with_file_name(format!(
        "{}.review.json",
        source
            .file_name()
            .context("image filename missing")?
            .to_string_lossy()
    ));
    plain_path(&review)?;
    if !review.exists() {
        return Ok(false);
    }
    let fingerprint = identity::file_identity(&review, Some(MAX_REVIEW_BYTES))?;
    let mut raw = Vec::new();
    fs::File::open(&review)?
        .take(MAX_REVIEW_BYTES + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= MAX_REVIEW_BYTES,
        "dark-image review exceeds 16 KiB"
    );
    let record: DarkReview =
        serde_json::from_slice(&raw).context("invalid dark-image review JSON or schema")?;
    ensure!(
        record.version == 1
            && record.decision == "preserve-dark-original"
            && record.sha256.len() == 64
            && record
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && (1..=4096).contains(&record.note.trim().chars().count()),
        "invalid dark-image review schema or decision"
    );
    ensure!(
        fingerprint == identity::file_identity(&review, Some(MAX_REVIEW_BYTES))?,
        "review changed during validation"
    );
    ensure!(
        record.sha256 == identity::file_identity(source, Some(MAX_IMAGE_BYTES))?.sha256,
        "dark-image review is stale; compare the current original again"
    );
    Ok(true)
}

#[derive(Clone, Debug, Serialize)]
pub struct Inspection {
    pub width: u32,
    pub height: u32,
    pub mode: String,
    pub alpha: bool,
    pub mean: f64,
    pub black_fraction: f64,
    pub dark: bool,
    pub reviewed: bool,
    pub requires_review: bool,
}
struct Raster {
    source: identity::Fingerprint,
    pixels: image::RgbImage,
    alpha: bool,
    mode: String,
    orientation: Orientation,
    icc: Option<Vec<u8>>,
    exif: Option<Vec<u8>>,
    xmp: Option<Vec<u8>>,
    density: Option<png::PixelDimensions>,
}

/// Delete IFD0 Orientation without relocating any referenced EXIF payload.
/// Offsets stay absolute within the TIFF block; only directory entries move.
fn remove_exif_orientation(data: &mut [u8]) -> Result<bool> {
    ensure!(data.len() >= 8, "truncated EXIF metadata");
    let little = match &data[..4] {
        b"II\x2a\0" => true,
        b"MM\0\x2a" => false,
        _ => anyhow::bail!("invalid EXIF byte order"),
    };
    let u16_at = |p: usize| -> Result<u16> {
        let raw: [u8; 2] = data
            .get(p..p + 2)
            .context("EXIF directory out of bounds")?
            .try_into()?;
        Ok(if little {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        })
    };
    let raw: [u8; 4] = data[4..8].try_into()?;
    let start = if little {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    } as usize;
    let count = usize::from(u16_at(start)?);
    let end = start
        .checked_add(2 + count * 12)
        .context("EXIF directory overflow")?;
    ensure!(end + 4 <= data.len(), "EXIF directory exceeds bounds");
    let mut orientation = None;
    for i in 0..count {
        if u16_at(start + 2 + i * 12)? == 274 {
            ensure!(orientation.is_none(), "duplicate EXIF orientation");
            orientation = Some(start + 2 + i * 12);
        }
    }
    let next: [u8; 4] = data[end..end + 4].try_into()?;
    let has_next = next != [0; 4];
    if let Some(position) = orientation {
        data.copy_within(position + 12..end, position);
        data[end - 12..end - 8].copy_from_slice(&next);
        let count = (count - 1) as u16;
        data[start..start + 2].copy_from_slice(&if little {
            count.to_le_bytes()
        } else {
            count.to_be_bytes()
        });
        Ok(count > 0 || has_next)
    } else {
        Ok(count > 0 || has_next)
    }
}
fn load(source: &Path) -> Result<Raster> {
    load_observed(source, |_| Ok(()))
}

#[derive(Clone, Copy)]
enum LoadBoundary {
    BeforeRead,
    AfterRead,
}

fn load_observed(
    source: &Path,
    mut observe: impl FnMut(LoadBoundary) -> Result<()>,
) -> Result<Raster> {
    plain_path(source)?;
    let before = identity::file_identity(source, Some(MAX_IMAGE_BYTES))?;
    let mut raw = Vec::new();
    observe(LoadBoundary::BeforeRead)?;
    fs::File::open(source)?
        .take(MAX_IMAGE_BYTES + 1)
        .read_to_end(&mut raw)?;
    observe(LoadBoundary::AfterRead)?;
    ensure!(
        raw.len() as u64 <= MAX_IMAGE_BYTES,
        "image exceeds bounded read limit"
    );
    ensure!(
        raw.len() as u64 == before.size && format!("{:x}", Sha256::digest(&raw)) == before.sha256,
        "decoded image bytes differ from the admitted source"
    );
    let format = image::guess_format(&raw)?;
    ensure!(
        matches!(
            format,
            ImageFormat::Png
                | ImageFormat::Jpeg
                | ImageFormat::Gif
                | ImageFormat::WebP
                | ImageFormat::Tiff
        ),
        "unsupported image format"
    );
    let mut density = None;
    if format == ImageFormat::Png {
        let reader = png::Decoder::new(Cursor::new(&raw)).read_info()?;
        let info = reader.info();
        ensure!(
            info.bit_depth as u8 <= 8,
            "unsupported PNG bit depth; preserve original intensities"
        );
        ensure!(
            info.gama_chunk.is_none()
                && info.chrm_chunk.is_none()
                && info.srgb.is_none()
                && info.coding_independent_code_points.is_none()
                && info.mastering_display_color_volume.is_none(),
            "PNG color metadata requires a reviewed color-preserving workflow"
        );
        ensure!(
            info.animation_control.is_none_or(|a| a.num_frames == 1),
            "multi-frame image requires reviewed extraction"
        );
        density = info.pixel_dims;
        if let Some(d) = density {
            ensure!(d.xppu > 0 && d.yppu > 0, "invalid image density metadata");
        }
    }
    if format == ImageFormat::Gif {
        let mut decoder = gif::DecodeOptions::new().read_info(Cursor::new(&raw))?;
        ensure!(
            decoder.read_next_frame()?.is_some() && decoder.read_next_frame()?.is_none(),
            "multi-frame image requires reviewed extraction"
        );
    }
    if format == ImageFormat::Tiff {
        let decoder = tiff::decoder::Decoder::new(Cursor::new(&raw))?;
        ensure!(
            !decoder.more_images(),
            "multi-frame image requires reviewed extraction"
        );
    }
    let mut reader = ImageReader::with_format(Cursor::new(&raw), format);
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(MAX_IMAGE_BYTES);
    limits.max_image_width = Some(MAX_PIXELS as u32);
    limits.max_image_height = Some(MAX_PIXELS as u32);
    reader.limits(limits);
    let mut decoder = reader.into_decoder()?;
    let (w, h) = decoder.dimensions();
    ensure!(
        w > 0 && h > 0 && u64::from(w) * u64::from(h) <= MAX_PIXELS,
        "image exceeds 50 million pixels"
    );
    let color = decoder.original_color_type();
    ensure!(
        matches!(
            color,
            image::ExtendedColorType::L1
                | image::ExtendedColorType::L2
                | image::ExtendedColorType::L4
                | image::ExtendedColorType::L8
                | image::ExtendedColorType::La8
                | image::ExtendedColorType::Rgb8
                | image::ExtendedColorType::Rgba8
        ),
        "unsupported image depth or mode; preserve original intensities"
    );
    let alpha = decoder.color_type().has_alpha();
    let mode = format!("{:?}", decoder.color_type());
    let orientation = decoder.orientation()?;
    let icc = decoder.icc_profile()?;
    if let Some(profile) = &icc {
        ensure!(
            profile.len() >= 132
                && &profile[16..20] == b"RGB "
                && &profile[36..40] == b"acsp"
                && u32::from_be_bytes(profile[..4].try_into()?) as usize == profile.len()
                && matches!(
                    color,
                    image::ExtendedColorType::Rgb8 | image::ExtendedColorType::Rgba8
                ),
            "unsupported color-profile conversion; retain original profile"
        );
    }
    let mut exif = decoder.exif_metadata()?;
    let xmp = decoder.xmp_metadata()?;
    ensure!(
        orientation == Orientation::NoTransforms || xmp.is_none(),
        "combined EXIF/XMP orientation requires reviewed normalization"
    );
    if density.is_none() && format == ImageFormat::Jpeg {
        let mut cursor = 2usize;
        while cursor + 4 <= raw.len() && raw[cursor] == 255 {
            let marker = raw[cursor + 1];
            if marker == 0xda || marker == 0xd9 {
                break;
            }
            let length = u16::from_be_bytes([raw[cursor + 2], raw[cursor + 3]]) as usize;
            ensure!(
                length >= 2 && cursor + 2 + length <= raw.len(),
                "invalid JPEG metadata bounds"
            );
            let payload = &raw[cursor + 4..cursor + 2 + length];
            if marker == 0xe0 && payload.len() >= 12 && payload.starts_with(b"JFIF\0") {
                let x = u16::from_be_bytes([payload[8], payload[9]]);
                let y = u16::from_be_bytes([payload[10], payload[11]]);
                ensure!(x > 0 && y > 0, "invalid image density metadata");
                let (scale, unit) = match payload[7] {
                    1 => (1. / 0.0254, png::Unit::Meter),
                    2 => (100., png::Unit::Meter),
                    0 => (1., png::Unit::Unspecified),
                    _ => anyhow::bail!("invalid JPEG density unit"),
                };
                density = Some(png::PixelDimensions {
                    xppu: (f64::from(x) * scale).round() as u32,
                    yppu: (f64::from(y) * scale).round() as u32,
                    unit,
                });
            }
            cursor += length + 2;
        }
    }
    if density.is_none()
        && let Some(ref data) = exif
        && let Ok(tags) = exif::Reader::new().read_raw(data.clone())
    {
        let value = |tag| {
            tags.get_field(tag, exif::In::PRIMARY)
                .and_then(|f| match &f.value {
                    exif::Value::Rational(v) => v.first().map(|r| r.to_f64()),
                    _ => None,
                })
        };
        if let (Some(x), Some(y)) = (value(exif::Tag::XResolution), value(exif::Tag::YResolution)) {
            ensure!(
                x.is_finite() && y.is_finite() && x > 0. && y > 0.,
                "invalid image density metadata"
            );
            let unit = tags
                .get_field(exif::Tag::ResolutionUnit, exif::In::PRIMARY)
                .and_then(|f| f.value.get_uint(0))
                .unwrap_or(2);
            let scale = if unit == 3 { 100. } else { 1. / 0.0254 };
            density = Some(png::PixelDimensions {
                xppu: (x * scale).round() as u32,
                yppu: (y * scale).round() as u32,
                unit: png::Unit::Meter,
            });
        }
    }
    if let Some(ref mut data) = exif
        && !remove_exif_orientation(data)?
    {
        exif = None;
    }
    if matches!(
        orientation,
        Orientation::Rotate90
            | Orientation::Rotate270
            | Orientation::Rotate90FlipH
            | Orientation::Rotate270FlipH
    ) && let Some(ref mut d) = density
    {
        std::mem::swap(&mut d.xppu, &mut d.yppu);
    }
    let mut decoded = DynamicImage::from_decoder(decoder)?;
    decoded.apply_orientation(orientation);
    let rgba = decoded.to_rgba8();
    let mut pixels = image::RgbImage::new(rgba.width(), rgba.height());
    for (out, input) in pixels.pixels_mut().zip(rgba.pixels()) {
        let a = u32::from(input[3]);
        for c in 0..3 {
            out[c] = ((u32::from(input[c]) * a + 255 * (255 - a) + 127) / 255) as u8;
        }
    }
    ensure!(
        before == identity::file_identity(source, Some(MAX_IMAGE_BYTES))?,
        "image changed while decoding"
    );
    Ok(Raster {
        source: before,
        pixels,
        alpha,
        mode,
        orientation,
        icc,
        exif,
        xmp,
        density,
    })
}

#[cfg(test)]
mod read_tests {
    use super::*;

    #[test]
    fn decoded_bytes_must_match_the_admitted_source_after_aba_replacement() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let source = temp.path().join("figure.jpg");
        let replacement = temp.path().join("replacement.jpg");
        for (path, color) in [(&source, [30, 80, 160]), (&replacement, [200, 210, 220])] {
            image::RgbImage::from_pixel(6, 6, image::Rgb(color))
                .save(path)
                .unwrap();
        }
        let admitted = fs::read(&source).unwrap();
        let foreign = fs::read(&replacement).unwrap();
        let modified = fs::metadata(&source).unwrap().modified().unwrap();
        let mut changed = false;
        let mut restored = false;
        let result = load_observed(&source, |boundary| {
            match boundary {
                LoadBoundary::BeforeRead => {
                    fs::write(&source, &foreign)?;
                    changed = true;
                }
                LoadBoundary::AfterRead => {
                    fs::write(&source, &admitted)?;
                    fs::File::options()
                        .write(true)
                        .open(&source)?
                        .set_times(fs::FileTimes::new().set_modified(modified))?;
                    restored = true;
                }
            }
            Ok(())
        });
        assert!(
            changed && restored,
            "both actual source mutation boundaries must execute"
        );
        assert_eq!(fs::read(&source).unwrap(), admitted);
        assert!(
            result.is_err(),
            "foreign pixels were paired with the restored source fingerprint"
        );
        assert!(
            load(&source).is_ok(),
            "unchanged admitted image must still decode"
        );
    }
}

fn stats(raster: &Raster) -> (f64, f64) {
    let scaled = image::imageops::thumbnail(&raster.pixels, 256, 256);
    let n = f64::from(scaled.width()) * f64::from(scaled.height());
    let sum: u64 = scaled.as_raw().iter().map(|v| u64::from(*v)).sum();
    let black = scaled
        .pixels()
        .filter(|p| p.0.iter().all(|v| *v < 18))
        .count();
    (sum as f64 / (3. * n), black as f64 / n)
}
pub fn inspect(source: &Path) -> Result<Inspection> {
    let raster = load(source)?;
    let (mean, black_fraction) = stats(&raster);
    let dark = mean < 120. && black_fraction >= 0.5;
    let reviewed = dark && reviewed_dark_original(source)?;
    Ok(Inspection {
        width: raster.pixels.width(),
        height: raster.pixels.height(),
        mode: raster.mode,
        alpha: raster.alpha,
        mean,
        black_fraction,
        dark,
        reviewed,
        requires_review: raster.alpha || (dark && !reviewed),
    })
}

struct EncodedPng {
    file: fs::File,
    digest: Sha256,
    size: u64,
}

impl Write for EncodedPng {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let available = MAX_IMAGE_BYTES.saturating_sub(self.size) as usize;
        if available == 0 && !bytes.is_empty() {
            return Err(std::io::Error::other("encoded PNG exceeds byte limit"));
        }
        let count = self.file.write(&bytes[..bytes.len().min(available)])?;
        self.digest.update(&bytes[..count]);
        self.size += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn write_png(raster: &Raster, destination: &Path, invert: bool) -> Result<identity::Fingerprint> {
    let mut pixels = raster.pixels.clone();
    if invert {
        image::imageops::invert(&mut pixels);
    }
    let mut info = png::Info::with_size(pixels.width(), pixels.height());
    info.color_type = png::ColorType::Rgb;
    info.bit_depth = png::BitDepth::Eight;
    info.pixel_dims = raster.density;
    info.icc_profile = raster.icc.clone().map(Into::into);
    info.exif_metadata = raster.exif.clone().map(Into::into);
    if let Some(xmp) = &raster.xmp {
        info.utf8_text.push(png::text_metadata::ITXtChunk::new(
            "XML:com.adobe.xmp",
            std::str::from_utf8(xmp)?,
        ));
    }
    let (encoded_size, encoded_digest) = {
        let mut output = EncodedPng {
            file: raster.source.create_file(destination)?,
            digest: Sha256::new(),
            size: 0,
        };
        let mut writer = png::Encoder::with_info(&mut output, info)?.write_header()?;
        writer.write_image_data(pixels.as_raw())?;
        writer.finish()?;
        #[cfg(unix)]
        raster.source.restore_mode(&output.file)?;
        output.file.sync_all()?;
        (output.size, format!("{:x}", output.digest.finalize()))
    };
    let check = image::open(destination)?.to_rgb8();
    ensure!(
        check == pixels,
        "staged PNG failed decoded-pixel validation"
    );
    let reader = png::Decoder::new(Cursor::new(fs::read(destination)?)).read_info()?;
    let info = reader.info();
    ensure!(
        info.icc_profile.as_deref() == raster.icc.as_deref()
            && info.pixel_dims.map(|p| (p.xppu, p.yppu, p.unit as u8))
                == raster.density.map(|p| (p.xppu, p.yppu, p.unit as u8))
            && info.exif_metadata.as_deref() == raster.exif.as_deref(),
        "staged PNG lost profile, density or EXIF metadata"
    );
    if let Some(xmp) = &raster.xmp {
        ensure!(
            info.utf8_text
                .iter()
                .any(|t| t.keyword == "XML:com.adobe.xmp"
                    && t.get_text().is_ok_and(|v| v.as_bytes() == xmp)),
            "staged PNG lost XMP metadata"
        );
    }
    let staged = identity::file_identity(destination, Some(MAX_IMAGE_BYTES))?;
    ensure!(
        staged.size == encoded_size && staged.sha256 == encoded_digest,
        "staged PNG differs from the encoded bytes"
    );
    #[cfg(unix)]
    ensure!(
        staged.mode == raster.source.mode,
        "staged PNG permissions differ from the admitted source"
    );
    Ok(staged)
}

#[path = "images_prepare.rs"]
mod preparation;
pub use preparation::{Boundary, iter_images, prepare, prepare_observed};

#[derive(Parser)]
#[command(name = "prepare-figures")]
struct Args {
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    #[arg(long)]
    check: bool,
    #[arg(long)]
    invert_dark: bool,
}
pub fn cli(args: &[String]) -> Result<i32> {
    let a = Args::try_parse_from(
        std::iter::once("prepare-figures".to_owned()).chain(args.iter().cloned()),
    )?;
    let files = iter_images(&a.paths)?;
    if a.check {
        let mut findings = 0;
        for source in &files {
            let r = inspect(source)?;
            findings += usize::from(r.requires_review);
            println!(
                "prepare-figures: {} mode={} alpha={} dark={} reviewed={}",
                if r.requires_review { "review" } else { "ok" },
                r.mode,
                r.alpha,
                r.dark,
                r.reviewed
            );
        }
        Ok(i32::from(findings > 0))
    } else {
        let n = prepare(&a.paths, a.invert_dark)?;
        println!(
            "prepare-figures: prepared={n} unchanged={}",
            files.len() - n
        );
        Ok(0)
    }
}
