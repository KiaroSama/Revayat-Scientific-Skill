use super::Fixture;
use anyhow::Result;
use revayat_scientific::build::{BuildGuard, DeliveryBoundary};
use std::{fs, io::Write};
pub(super) fn preview_admission() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    f.seal()?;
    for sample in &f.samples {
        fs::write(sample, b"previous preview")?;
    }
    let stages = f.stages()?;
    let bytes = fs::read(&stages[1])?;
    for (maximum, pixels, want) in [
        (bytes.len() - 1, 50_000_000, "bounded"),
        (128 * 1024 * 1024, 575, "oversized"),
    ] {
        let error = BuildGuard::publish_previews_with_limits(
            &f.record,
            &stages,
            maximum,
            pixels,
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains(want), "{error:#}");
        for sample in &f.samples {
            assert_eq!(fs::read(sample)?, b"previous preview");
        }
    }
    // Valid CRC/header, deliberately absent pixel data: dimensions must reject
    // before attempting the missing IDAT decode, without allocating that raster.
    let file = fs::File::create(&stages[1])?;
    let mut encoder = png::Encoder::new(file, 10_000, 10_000);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut header = encoder.write_header()?;
    header.write_chunk(png::chunk::IDAT, &[])?;
    drop(header);
    let error = BuildGuard::publish_previews(&f.record, &stages).unwrap_err();
    assert!(error.to_string().contains("oversized"), "{error:#}");
    for sample in &f.samples {
        assert_eq!(fs::read(sample)?, b"previous preview");
    }
    let stages = f.stages()?;
    BuildGuard::publish_previews(&f.record, &stages)?;
    for sample in &f.samples {
        assert_eq!(image::open(sample)?.width(), 24);
    }
    Ok(())
}
pub(super) fn growing_delivery() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    f.seal()?;
    let original = fs::read(&f.working)?;
    let mut reached = false;
    let error = BuildGuard::deliver_observed(&f.record, |phase, source, _| {
        if phase == DeliveryBoundary::BeforeCopy {
            reached = true;
            fs::OpenOptions::new()
                .append(true)
                .open(source)?
                .write_all(b"new unbounded revision")?;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(reached);
    assert!(error.to_string().contains("bounded delivery copy"));
    assert_eq!(
        fs::read(&f.working)?,
        [original, b"new unbounded revision".to_vec()].concat()
    );
    f.unchanged()?;
    assert!(!fs::read_dir(&f.root)?.any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-delivery-")
    }));
    Ok(())
}
