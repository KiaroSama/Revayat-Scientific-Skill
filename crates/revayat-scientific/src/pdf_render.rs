//! Bounded raster derivatives bound to their admitted PDF source snapshots.
use super::{SourceSnapshot, geometry, open_pdf, page_ids};
use crate::publication;
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

pub fn render_page(source: &Path, page: usize, dpi: u32, destination: &Path) -> Result<()> {
    let inputs = SourceSnapshot::capture(&[source.to_owned()])?;
    let d = open_pdf(source, false)?;
    let g = geometry(&d)?;
    ensure!(page > 0 && page <= g.len(), "render page exceeds document");
    render_region_bound(source, page, dpi, g[page - 1].rect, destination, &inputs)
}
pub fn render_region(
    source: &Path,
    page: usize,
    dpi: u32,
    clip: [f64; 4],
    destination: &Path,
) -> Result<()> {
    let inputs = SourceSnapshot::capture(&[source.to_owned()])?;
    render_region_bound(source, page, dpi, clip, destination, &inputs)
}
fn render_region_bound(
    source: &Path,
    page: usize,
    dpi: u32,
    clip: [f64; 4],
    destination: &Path,
    inputs: &SourceSnapshot,
) -> Result<()> {
    ensure!(dpi > 0, "render density must be positive");
    let d = open_pdf(source, false)?;
    let g = geometry(&d)?;
    ensure!(page > 0 && page <= g.len(), "render page exceeds document");
    let r = g[page - 1].rect;
    ensure!(
        clip.iter().all(|n| n.is_finite())
            && clip[0] >= r[0]
            && clip[1] >= r[1]
            && clip[2] <= r[2]
            && clip[3] <= r[3]
            && clip[0] < clip[2]
            && clip[1] < clip[3],
        "crop rectangle must be finite, nonempty and inside page"
    );
    let scale = f64::from(dpi) / 72.;
    let x = (clip[0] * scale).floor() as u64;
    let y = (clip[1] * scale).floor() as u64;
    let w = (clip[2] * scale).ceil() as u64 - x;
    let h = (clip[3] * scale).ceil() as u64 - y;
    ensure!(
        w.checked_mul(h).is_some_and(|n| n <= 50_000_000),
        "crop exceeds 50 million pixels; no downsampling performed"
    );
    let destination = publication::validate_destination(destination, &[source.to_owned()])?;
    let parent = destination
        .parent()
        .context("render destination parent missing")?;
    fs::create_dir_all(parent)?;
    let work = tempfile::Builder::new()
        .prefix(".revayat-raster-")
        .tempdir_in(parent)?;
    let prefix = work.path().join("page");
    let mut spec = crate::runtime::CommandSpec::new("pdftoppm");
    spec.timeout = Duration::from_secs(120);
    spec.args = vec![
        "-f".into(),
        page.to_string().into(),
        "-l".into(),
        page.to_string().into(),
        "-singlefile".into(),
        "-png".into(),
        "-cropbox".into(),
        "-r".into(),
        dpi.to_string().into(),
        "-x".into(),
        x.to_string().into(),
        "-y".into(),
        y.to_string().into(),
        "-W".into(),
        w.to_string().into(),
        "-H".into(),
        h.to_string().into(),
        source.as_os_str().to_owned(),
        prefix.as_os_str().to_owned(),
    ];
    let output = crate::runtime::run(&spec)?;
    ensure!(
        output.success(),
        "Poppler raster backend failed: {}",
        output.stderr_text()
    );
    let stage = prefix.with_extension("png");
    let image = image::open(&stage)?;
    ensure!(
        u64::from(image.width()) == w && u64::from(image.height()) == h,
        "raster backend changed requested crop dimensions"
    );
    inputs.publish(&[(stage, destination)], |_, _| Ok(()))
}
pub fn render_sample_set(source: &Path, output_prefix: &Path) -> Result<Vec<PathBuf>> {
    let protected = [source.to_owned()];
    let inputs = SourceSnapshot::capture(&protected)?;
    let d = open_pdf(source, false)?;
    let n = page_ids(&d)?.len();
    let mut pages = vec![1, n.div_ceil(2), n];
    pages.sort_unstable();
    pages.dedup();
    let parent = output_prefix
        .parent()
        .context("sample output parent missing")?;
    let mut outputs = Vec::new();
    for page in pages {
        let output = output_prefix.with_file_name(format!(
            "{}-{page}.png",
            output_prefix
                .file_name()
                .context("output prefix missing")?
                .to_string_lossy()
        ));
        publication::validate_destination(&output, &protected)?;
        outputs.push((page, output));
    }
    fs::create_dir_all(parent)?;
    let work = tempfile::Builder::new()
        .prefix(".revayat-samples-")
        .tempdir_in(parent)?;
    let mut entries = Vec::new();
    let mut result = Vec::new();
    for (page, destination) in outputs {
        let stage = work.path().join(format!("page-{page}.png"));
        render_page(source, page, 100, &stage)?;
        entries.push((stage, destination.clone()));
        result.push(destination);
    }
    inputs.publish(&entries, |_, _| Ok(()))?;
    Ok(result)
}
