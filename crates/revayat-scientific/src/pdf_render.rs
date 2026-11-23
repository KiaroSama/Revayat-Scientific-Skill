//! Bounded raster derivatives from one private, admitted PDF revision.
use super::{
    AdmissionLimits, MAX_PDF_BYTES, PageGeometry, SourceSnapshot, geometry, parse_pdf_bytes,
};
use crate::{
    identity::{self, Fingerprint},
    publication,
};
use anyhow::{Context, Result, ensure};
use lopdf::Document;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub(crate) struct FrozenPdf {
    _work: tempfile::TempDir,
    original: PathBuf,
    path: PathBuf,
    document: Document,
    geometry: Vec<PageGeometry>,
}
impl FrozenPdf {
    pub(crate) fn capture(
        source: &Path,
        inputs: &SourceSnapshot,
        limits: AdmissionLimits,
    ) -> Result<Self> {
        let limits = limits.validate()?;
        let bytes = inputs.verified_bytes(source)?;
        let work = tempfile::Builder::new()
            .prefix(".revayat-pdf-source-")
            .tempdir_in(std::env::temp_dir().canonicalize()?)?;
        let path = work.path().join("source.pdf");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(&bytes)?;
        drop(file);
        written_identity(&path, &bytes)?;
        let document = parse_pdf_bytes(&bytes, false, limits)?;
        let geometry = geometry(&document)?;
        Ok(Self {
            _work: work,
            original: source.to_owned(),
            path,
            document,
            geometry,
        })
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn document(&self) -> &Document {
        &self.document
    }
    pub(crate) fn geometry(&self) -> &[PageGeometry] {
        &self.geometry
    }
}
fn written_identity(path: &Path, bytes: &[u8]) -> Result<Fingerprint> {
    let fingerprint = identity::file_identity(path, Some(MAX_PDF_BYTES))?;
    ensure!(
        fingerprint.size == bytes.len() as u64
            && fingerprint.sha256 == format!("{:x}", Sha256::digest(bytes)),
        "staged raster bytes changed after production"
    );
    Ok(fingerprint)
}
pub fn render_page(source: &Path, page: usize, dpi: u32, destination: &Path) -> Result<()> {
    let inputs = SourceSnapshot::capture(&[source.to_owned()])?;
    let frozen = FrozenPdf::capture(source, &inputs, AdmissionLimits::default())?;
    ensure!(
        page > 0 && page <= frozen.geometry().len(),
        "render page exceeds document"
    );
    render_region_bound(
        &frozen,
        page,
        dpi,
        frozen.geometry()[page - 1].rect,
        destination,
        &inputs,
    )
}
pub fn render_region(
    source: &Path,
    page: usize,
    dpi: u32,
    clip: [f64; 4],
    destination: &Path,
) -> Result<()> {
    let inputs = SourceSnapshot::capture(&[source.to_owned()])?;
    let frozen = FrozenPdf::capture(source, &inputs, AdmissionLimits::default())?;
    render_region_bound(&frozen, page, dpi, clip, destination, &inputs)
}
fn render_region_bound(
    frozen: &FrozenPdf,
    page: usize,
    dpi: u32,
    clip: [f64; 4],
    destination: &Path,
    inputs: &SourceSnapshot,
) -> Result<()> {
    let destination =
        publication::validate_destination(destination, std::slice::from_ref(&frozen.original))?;
    let parent = destination
        .parent()
        .context("render destination parent missing")?;
    fs::create_dir_all(parent)?;
    let work = tempfile::Builder::new()
        .prefix(".revayat-raster-")
        .tempdir_in(parent)?;
    let stage = work.path().join("page.png");
    let expected = render_region_stage(frozen.path(), frozen.geometry(), page, dpi, clip, &stage)?;
    inputs.publish_expected(&[(stage, destination)], &[expected], |_, _| Ok(()))
}
/// Produce a private stage and return its verified content before another batch observer runs.
pub(crate) fn render_region_stage(
    source: &Path,
    geometry: &[PageGeometry],
    page: usize,
    dpi: u32,
    clip: [f64; 4],
    stage: &Path,
) -> Result<Fingerprint> {
    ensure!(dpi > 0, "render density must be positive");
    ensure!(
        page > 0 && page <= geometry.len(),
        "render page exceeds document"
    );
    let r = geometry[page - 1].rect;
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
    ensure!(w > 0 && h > 0, "crop rounds to zero pixels");
    ensure!(
        w.checked_mul(h).is_some_and(|n| n <= 50_000_000),
        "crop exceeds 50 million pixels; no downsampling performed"
    );
    crate::images::plain_path(source)?;
    let stage = publication::validate_destination(stage, &[source.to_owned()])?;
    ensure!(
        !stage.exists(),
        "raster producer requires a new private stage"
    );
    let prefix = stage.with_extension("");
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
    let mut raw = Vec::new();
    fs::File::open(&stage)?
        .take(MAX_PDF_BYTES + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= MAX_PDF_BYTES,
        "raster output exceeds byte limit"
    );
    let expected = written_identity(&stage, &raw)?;
    let dimensions =
        image::ImageReader::with_format(std::io::Cursor::new(&raw), image::ImageFormat::Png)
            .into_dimensions()?;
    ensure!(
        u64::from(dimensions.0) == w && u64::from(dimensions.1) == h,
        "raster backend changed requested crop dimensions"
    );
    image::load_from_memory(&raw)?;
    Ok(expected)
}
pub fn render_sample_set(source: &Path, output_prefix: &Path) -> Result<Vec<PathBuf>> {
    sample_set_with_renderer(source, output_prefix, render_region_stage)
}
fn sample_set_with_renderer(
    source: &Path,
    output_prefix: &Path,
    mut render: impl FnMut(&Path, &[PageGeometry], usize, u32, [f64; 4], &Path) -> Result<Fingerprint>,
) -> Result<Vec<PathBuf>> {
    let protected = [source.to_owned()];
    let inputs = SourceSnapshot::capture(&protected)?;
    let frozen = FrozenPdf::capture(source, &inputs, AdmissionLimits::default())?;
    let n = frozen.geometry().len();
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
    let mut expected = Vec::new();
    let mut result = Vec::new();
    for (page, destination) in outputs {
        let stage = work.path().join(format!("page-{page}.png"));
        expected.push(render(
            frozen.path(),
            frozen.geometry(),
            page,
            100,
            frozen.geometry()[page - 1].rect,
            &stage,
        )?);
        entries.push((stage, destination.clone()));
        result.push(destination);
    }
    inputs.publish_expected(&entries, &expected, |_, _| Ok(()))?;
    Ok(result)
}
#[cfg(test)]
#[path = "pdf_render_checks.rs"]
mod checks;
