//! Per-call PDF admission budgets and the real staged-publication boundary.
#[path = "pdf_emission.rs"]
mod emission;
use super::{MAX_PDF_BYTES, MAX_PDF_OBJECTS, MAX_PDF_PAGES, PageGeometry, geometry, page_ids};
use crate::{identity, pdf_forms, publication};
use anyhow::{Context, Result, ensure};
use lopdf::Document;
use serde_json::Value;
use std::{
    collections::BTreeMap,
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
impl AdmissionLimits {
    pub(crate) fn validate(self) -> Result<Self> {
        ensure!(
            self.max_bytes > 0
                && self.max_bytes <= MAX_PDF_BYTES
                && self.max_pages > 0
                && self.max_pages <= MAX_PDF_PAGES
                && self.max_objects > 0
                && self.max_objects <= MAX_PDF_OBJECTS,
            "PDF admission limits must be positive and cannot exceed production budgets"
        );
        Ok(self)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PdfBoundary {
    /// Original source admitted, before its document bytes are parsed.
    SourceCaptured,
    TableDiscovery,
    TableCells,
    /// Producer closed, before its output is admitted by readback.
    BytesWritten,
    StageWritten,
    Publication(publication::Boundary),
}

pub(crate) struct SourceSnapshot {
    paths: Vec<PathBuf>,
    identities: Vec<identity::Fingerprint>,
    maximums: Vec<u64>,
    by_path: BTreeMap<PathBuf, usize>,
}
impl SourceSnapshot {
    pub(crate) fn capture(paths: &[PathBuf]) -> Result<Self> {
        Self::capture_with_limits(paths, &vec![MAX_PDF_BYTES; paths.len()])
    }
    pub(crate) fn capture_with_limits(paths: &[PathBuf], maximums: &[u64]) -> Result<Self> {
        ensure!(
            paths.len() == maximums.len() && maximums.iter().all(|n| *n > 0 && *n <= MAX_PDF_BYTES),
            "source snapshots require one valid byte limit per input"
        );
        let identities = paths
            .iter()
            .zip(maximums)
            .map(|(path, maximum)| {
                crate::images::plain_path(path)?;
                identity::file_identity(path, Some(*maximum))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            paths: paths.to_vec(),
            identities,
            maximums: maximums.to_vec(),
            by_path: paths
                .iter()
                .enumerate()
                .map(|(index, path)| (path.clone(), index))
                .collect(),
        })
    }
    pub(crate) fn verified_bytes(&self, path: &Path) -> Result<Vec<u8>> {
        let index = *self
            .by_path
            .get(path)
            .context("read path is not an admitted source")?;
        let expected = &self.identities[index];
        crate::images::plain_path(path)?;
        let mut raw = Vec::new();
        fs::File::open(path)?
            .take(expected.size.saturating_add(1))
            .read_to_end(&mut raw)?;
        ensure!(
            raw.len() as u64 == expected.size && crate::resource::sha256(&raw) == expected.sha256,
            "read bytes differ from the admitted source"
        );
        self.verify_one(index)?;
        Ok(raw)
    }
    pub(crate) fn open_pdf(
        &self,
        path: &Path,
        transform: bool,
        limits: AdmissionLimits,
    ) -> Result<Document> {
        let limits = limits.validate()?;
        let index = *self
            .by_path
            .get(path)
            .context("PDF path is not an admitted source")?;
        ensure!(
            self.identities[index].size <= limits.max_bytes,
            "PDF exceeds caller byte limit"
        );
        let raw = self.verified_bytes(path)?;
        let document = parse_pdf_bytes(&raw, transform, limits)?;
        self.verify_one(index)?;
        Ok(document)
    }
    fn verify_one(&self, index: usize) -> Result<()> {
        let path = &self.paths[index];
        crate::images::plain_path(path)?;
        ensure!(
            identity::file_identity(path, Some(self.maximums[index]))? == self.identities[index],
            "PDF input changed after its snapshot"
        );
        Ok(())
    }
    pub(crate) fn verify(&self) -> Result<()> {
        for index in 0..self.paths.len() {
            self.verify_one(index)?;
        }
        Ok(())
    }
    pub(crate) fn publish_expected(
        &self,
        entries: &[(PathBuf, PathBuf)],
        expected: &[identity::Fingerprint],
        mut observer: impl FnMut(publication::Boundary, &Path) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            entries.len() == expected.len(),
            "missing producer output identity"
        );
        self.verify()?;
        let expected = entries
            .iter()
            .zip(expected)
            .map(|((stage, _), identity)| Ok((publication::absolute(stage)?, identity)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut committed = 0;
        publication::publish_with_identity(
            entries,
            &self.paths,
            Some(MAX_PDF_BYTES),
            |boundary, path| {
                observer(boundary, path)?;
                if boundary == publication::Boundary::BeforeCommit && committed == 0 {
                    self.verify()?;
                }
                if boundary == publication::Boundary::BeforeFinalize {
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
            |path, maximum| {
                let current = identity::file_identity(path, maximum)?;
                if let Some(produced) = expected.get(path) {
                    ensure!(
                        current.same_bytes(produced),
                        "staged output differs from producer content"
                    );
                }
                Ok(current)
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
    let limits = limits.validate()?;
    let inputs = SourceSnapshot::capture_with_limits(&[path.to_owned()], &[limits.max_bytes])?;
    inputs.open_pdf(path, transform, limits)
}
pub(crate) fn parse_pdf_bytes(
    raw: &[u8],
    transform: bool,
    limits: AdmissionLimits,
) -> Result<Document> {
    let limits = limits.validate()?;
    ensure!(
        raw.len() as u64 <= limits.max_bytes,
        "PDF exceeds bounded read limit"
    );
    ensure!(
        raw.starts_with(b"%PDF-") && raw.trim_ascii_end().ends_with(b"%%EOF"),
        "PDF incomplete or requires parser repair"
    );
    let doc = Document::load_mem_with_options(
        raw,
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
    inputs.publish_expected(
        &[(stage.clone(), destination)],
        std::slice::from_ref(expected),
        |boundary, path| {
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
        },
    )
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
    let (size, sha256) = emission::save_document(doc, &path, MAX_PDF_BYTES)?;
    observer(PdfBoundary::BytesWritten, &path)?;
    let expected_content = identity::file_identity(&path, Some(MAX_PDF_BYTES))?;
    ensure!(
        expected_content.size == size && expected_content.sha256 == sha256,
        "staged PDF differs from emitted serializer bytes"
    );
    observer(PdfBoundary::StageWritten, &path)?;
    let reopened = open_pdf(&path, false)?;
    ensure!(
        geometry(&reopened)? == expected,
        "staged PDF changed page count or geometry"
    );
    validator(&reopened)?;
    publish_stage(inputs, path, destination, &expected_content, observer)
}
