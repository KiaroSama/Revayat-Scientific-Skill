//! Per-call PDF admission budgets and the real staged-publication boundary.
use super::{MAX_PDF_BYTES, MAX_PDF_OBJECTS, MAX_PDF_PAGES, PageGeometry, geometry, page_ids};
use crate::{identity, pdf_forms, publication};
use anyhow::{Context, Result, ensure};
use lopdf::Document;
use serde_json::Value;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug)]
pub struct AdmissionLimits {
    pub max_bytes: u64,
    pub max_pages: usize,
    pub max_objects: usize,
}
impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_PDF_BYTES,
            max_pages: MAX_PDF_PAGES,
            max_objects: MAX_PDF_OBJECTS,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PdfBoundary {
    TableDiscovery,
    TableCells,
    StageWritten,
    Publication(publication::Boundary),
}

pub(crate) struct SourceSnapshot {
    paths: Vec<PathBuf>,
    identities: Vec<identity::Fingerprint>,
}
impl SourceSnapshot {
    pub(crate) fn capture(paths: &[PathBuf]) -> Result<Self> {
        let identities = paths
            .iter()
            .map(|path| {
                crate::images::plain_path(path)?;
                identity::file_identity(path, Some(MAX_PDF_BYTES))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            paths: paths.to_vec(),
            identities,
        })
    }
    pub(crate) fn verify(&self) -> Result<()> {
        for (path, expected) in self.paths.iter().zip(&self.identities) {
            crate::images::plain_path(path)?;
            ensure!(
                identity::file_identity(path, Some(MAX_PDF_BYTES))? == *expected,
                "PDF input changed after its snapshot"
            );
        }
        Ok(())
    }
    pub(crate) fn publish(
        &self,
        entries: &[(PathBuf, PathBuf)],
        mut observer: impl FnMut(publication::Boundary, &Path) -> Result<()>,
    ) -> Result<()> {
        self.verify()?;
        let mut committed = 0;
        publication::publish_observed(
            entries,
            &self.paths,
            Some(MAX_PDF_BYTES),
            |boundary, path| {
                observer(boundary, path)?;
                if boundary == publication::Boundary::BeforeCommit && committed == 0 {
                    self.verify()?;
                }
                if boundary == publication::Boundary::AfterCommit {
                    committed += 1;
                    // A late source change rolls back the complete output batch,
                    // without rehashing a large source once per extracted image.
                    if committed == entries.len() {
                        self.verify()?;
                    }
                }
                Ok(())
            },
        )
    }
}
pub fn open_pdf(path: &Path, transform: bool) -> Result<Document> {
    open_pdf_with_limits(path, transform, AdmissionLimits::default())
}
pub fn open_pdf_with_limits(
    path: &Path,
    transform: bool,
    limits: AdmissionLimits,
) -> Result<Document> {
    ensure!(
        limits.max_bytes > 0
            && limits.max_bytes <= MAX_PDF_BYTES
            && limits.max_pages > 0
            && limits.max_pages <= MAX_PDF_PAGES
            && limits.max_objects > 0
            && limits.max_objects <= MAX_PDF_OBJECTS,
        "PDF admission limits must be positive and cannot exceed production budgets"
    );
    crate::images::plain_path(path)?;
    let before = identity::file_identity(path, Some(limits.max_bytes))?;
    let mut raw = Vec::new();
    fs::File::open(path)?
        .take(limits.max_bytes + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= limits.max_bytes,
        "PDF exceeds bounded read limit"
    );
    ensure!(
        raw.starts_with(b"%PDF-") && raw.trim_ascii_end().ends_with(b"%%EOF"),
        "PDF incomplete or requires parser repair"
    );
    let doc = Document::load_mem_with_options(
        &raw,
        lopdf::LoadOptions {
            strict: true,
            max_decompressed_size: Some(128 * 1024 * 1024),
            ..Default::default()
        },
    )
    .context("PDF parse failed; repaired sources must be validated separately")?;
    ensure!(
        !doc.trailer.has(b"Encrypt") && !doc.is_encrypted() && doc.encryption_state.is_none(),
        "encrypted PDF requires authorized decrypted copy"
    );
    ensure!(
        doc.objects.len() <= limits.max_objects && doc.max_id as usize <= limits.max_objects,
        "PDF exceeds object limit"
    );
    ensure!(
        page_ids(&doc)?.len() <= limits.max_pages,
        "PDF exceeds page limit"
    );
    let _ = geometry(&doc)?;
    if transform {
        pdf_forms::ensure_transformable(&doc)?;
    }
    ensure!(
        before == identity::file_identity(path, Some(limits.max_bytes))?,
        "PDF changed during admission"
    );
    Ok(doc)
}
pub fn write_report(value: &Value, destination: &Path, sources: &[PathBuf]) -> Result<()> {
    write_report_observed(value, destination, sources, |_, _| Ok(()))
}
fn publish_stage(
    inputs: &SourceSnapshot,
    stage: PathBuf,
    destination: PathBuf,
    expected: &identity::Fingerprint,
    mut observer: impl FnMut(PdfBoundary, &Path) -> Result<()>,
) -> Result<()> {
    inputs.publish(&[(stage.clone(), destination)], |boundary, path| {
        observer(PdfBoundary::Publication(boundary), path)?;
        let check = match boundary {
            publication::Boundary::BeforeCommit | publication::Boundary::BeforeReplace => {
                Some(stage.as_path())
            }
            publication::Boundary::AfterCommit => Some(path),
            _ => None,
        };
        if let Some(path) = check {
            ensure!(
                identity::file_identity(path, Some(MAX_PDF_BYTES))?.same_bytes(expected),
                "staged PDF output changed after writing"
            );
        }
        Ok(())
    })
}
pub fn write_report_observed(
    value: &Value,
    destination: &Path,
    sources: &[PathBuf],
    observer: impl FnMut(PdfBoundary, &Path) -> Result<()>,
) -> Result<()> {
    let inputs = SourceSnapshot::capture(sources)?;
    write_report_bound(value, destination, &inputs, observer)
}
pub(crate) fn write_report_bound(
    value: &Value,
    destination: &Path,
    inputs: &SourceSnapshot,
    mut observer: impl FnMut(PdfBoundary, &Path) -> Result<()>,
) -> Result<()> {
    let destination = publication::validate_destination(destination, &inputs.paths)?;
    let parent = destination.parent().context("report parent missing")?;
    fs::create_dir_all(parent)?;
    let stage = tempfile::Builder::new()
        .prefix(".revayat-pdf-")
        .tempdir_in(parent)?;
    let path = stage.path().join("report.json");
    let mut raw = serde_json::to_vec_pretty(value)?;
    raw.push(b'\n');
    let expected_bytes = (raw.len() as u64, crate::resource::sha256(&raw));
    fs::write(&path, raw)?;
    let expected = identity::file_identity(&path, Some(MAX_PDF_BYTES))?;
    ensure!(
        expected.size == expected_bytes.0 && expected.sha256 == expected_bytes.1,
        "staged report differs from emitted JSON"
    );
    observer(PdfBoundary::StageWritten, &path)?;
    publish_stage(inputs, path, destination, &expected, observer)
}
pub fn save_document(
    doc: &mut Document,
    destination: &Path,
    sources: &[PathBuf],
    expected: &[PageGeometry],
    validator: impl Fn(&Document) -> Result<()>,
) -> Result<()> {
    save_document_observed(
        doc,
        destination,
        sources,
        expected,
        validator,
        |_, _| Ok(()),
    )
}
pub fn save_document_observed(
    doc: &mut Document,
    destination: &Path,
    sources: &[PathBuf],
    expected: &[PageGeometry],
    validator: impl Fn(&Document) -> Result<()>,
    observer: impl FnMut(PdfBoundary, &Path) -> Result<()>,
) -> Result<()> {
    let inputs = SourceSnapshot::capture(sources)?;
    save_document_bound(doc, destination, &inputs, expected, validator, observer)
}
pub(crate) fn save_document_bound(
    doc: &mut Document,
    destination: &Path,
    inputs: &SourceSnapshot,
    expected: &[PageGeometry],
    validator: impl Fn(&Document) -> Result<()>,
    mut observer: impl FnMut(PdfBoundary, &Path) -> Result<()>,
) -> Result<()> {
    let destination = publication::validate_destination(destination, &inputs.paths)?;
    let parent = destination.parent().context("PDF output parent missing")?;
    fs::create_dir_all(parent)?;
    let stage = tempfile::Builder::new()
        .prefix(".revayat-pdf-")
        .tempdir_in(parent)?;
    let path = stage.path().join("result.pdf");
    doc.save(&path)?;
    let expected_content = identity::file_identity(&path, Some(MAX_PDF_BYTES))?;
    observer(PdfBoundary::StageWritten, &path)?;
    let reopened = open_pdf(&path, false)?;
    ensure!(
        geometry(&reopened)? == expected,
        "staged PDF changed page count or geometry"
    );
    validator(&reopened)?;
    publish_stage(inputs, path, destination, &expected_content, observer)
}
