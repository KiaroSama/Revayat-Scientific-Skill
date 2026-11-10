//! Tesseract text-only grafting. Every accepted painting instruction is invisible.
use crate::{
    pdf, pdf_content, pdf_forms, pdf_navigation as nav,
    runtime::{CommandOutput, CommandSpec, run},
};
use anyhow::{Context, Result, bail, ensure};
use lopdf::{
    Document, Object, Stream,
    content::{Content, Operation},
    dictionary,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

/// Refuse paths, shadings, images, external graphics states and nested Forms;
/// accepting Tr=3 alone would still let an attacker paint over source evidence.
pub fn validate_text_layer(layer: &Document, width: f64, height: f64) -> Result<bool> {
    let ids = pdf::page_ids(layer)?;
    ensure!(
        ids.len() == 1,
        "OCR backend must produce one text-only page"
    );
    let g = pdf::geometry(layer)?;
    ensure!(
        (g[0].rect[2] - width).abs() <= 1. && (g[0].rect[3] - height).abs() <= 1.,
        "OCR text layer dimensions differ from source"
    );
    for o in layer.objects.values() {
        if let Object::Stream(s) = o {
            ensure!(
                s.dict.get(b"Subtype").and_then(Object::as_name).ok() != Some(b"Image"),
                "OCR text layer contains image"
            );
        }
    }
    let content = Content::decode(&pdf_content::page_stream(layer, ids[0])?)?;
    let mut mode = 0i64;
    let mut in_text = false;
    let mut states = Vec::new();
    for op in content.operations {
        match op.operator.as_str() {
            "q" => {
                ensure!(states.len() < 128, "OCR state nesting exceeds limit");
                states.push(mode);
            }
            "Q" => mode = states.pop().context("unbalanced OCR state")?,
            "BT" => {
                ensure!(!in_text, "nested OCR text object");
                in_text = true;
            }
            "ET" => {
                ensure!(in_text, "unbalanced OCR text object");
                in_text = false;
            }
            "Tr" => {
                mode = op
                    .operands
                    .first()
                    .context("missing OCR rendering mode")?
                    .as_i64()?;
                ensure!(
                    mode == 3,
                    "OCR text layer contains visible text rendering mode"
                );
            }
            "Tj" | "TJ" | "'" | "\"" => {
                ensure!(in_text && mode == 3, "OCR text layer contains visible text")
            }
            "cm" | "Tc" | "Tw" | "Tz" | "TL" | "Tf" | "Ts" | "Td" | "TD" | "Tm" | "T*" => {}
            _ => bail!(
                "OCR text layer contains visible or unsupported painting operation {}",
                op.operator
            ),
        }
    }
    ensure!(
        !in_text && states.is_empty(),
        "unbalanced OCR text layer state"
    );
    Ok(!pdf_content::page_text(layer, ids[0])?.trim().is_empty())
}
fn tesseract() -> Result<PathBuf> {
    if let Some(value) = std::env::var_os("TESSERACT_CMD") {
        let p = PathBuf::from(value);
        ensure!(
            p.is_absolute() && p.is_file(),
            "TESSERACT_CMD must name an existing absolute executable path"
        );
        return Ok(p);
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&paths) {
            let candidate = directory.join(if cfg!(windows) {
                "tesseract.exe"
            } else {
                "tesseract"
            });
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    #[cfg(windows)]
    for (variable, suffix) in [
        ("ProgramFiles", "Tesseract-OCR/tesseract.exe"),
        ("ProgramFiles(x86)", "Tesseract-OCR/tesseract.exe"),
        ("LOCALAPPDATA", "Programs/Tesseract-OCR/tesseract.exe"),
    ] {
        if let Some(base) = std::env::var_os(variable) {
            let candidate = PathBuf::from(base).join(suffix);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    anyhow::bail!(
        "Tesseract unavailable; configure TESSERACT_CMD or PATH and install requested language data"
    )
}
pub fn ocr_pdf(
    source: &Path,
    destination: &Path,
    language: &str,
    dpi: u32,
    timeout: u64,
) -> Result<()> {
    ocr_with_tools(source, destination, language, dpi, timeout, tesseract, run)
}
/// The real tool-discovery and bounded command boundaries, without global overrides.
pub fn ocr_with_tools(
    source: &Path,
    destination: &Path,
    language: &str,
    dpi: u32,
    timeout: u64,
    find: impl FnOnce() -> Result<PathBuf>,
    mut execute: impl FnMut(&CommandSpec) -> Result<CommandOutput>,
) -> Result<()> {
    ensure!(
        language.len() <= 256
            && regex::Regex::new(r"^[A-Za-z][A-Za-z0-9_]*(?:\+[A-Za-z][A-Za-z0-9_]*)*$")?
                .is_match(language),
        "OCR language must be installed names joined with +"
    );
    ensure!(
        (72..=600).contains(&dpi) && (1..=600).contains(&timeout),
        "OCR DPI must be 72..600 and timeout 1..600 seconds"
    );
    let destination = crate::publication::validate_destination(destination, &[source.to_owned()])?;
    let _ = pdf::open_pdf(source, true)?;
    let program = find()?;
    let mut spec = CommandSpec::new(program.as_os_str());
    spec.args = vec!["--list-langs".into()];
    spec.timeout = Duration::from_secs(timeout.min(30));
    let result = execute(&spec)?;
    ensure!(result.success(), "Tesseract language query failed");
    let stdout = result.stdout_text();
    let installed: std::collections::HashSet<_> = stdout.lines().map(str::trim).collect();
    ensure!(
        language.split('+').all(|l| installed.contains(l)),
        "one or more requested OCR languages not installed"
    );
    let parent = destination.parent().context("OCR output parent missing")?;
    fs::create_dir_all(parent)?;
    let work = tempfile::Builder::new()
        .prefix(".revayat-ocr-")
        .tempdir_in(parent)?;
    ocr_with_backend(source, &destination, |index, admitted| {
        let id = pdf::page_ids(admitted)?[index];
        let mut unrotated = admitted.clone();
        unrotated
            .get_object_mut(id)?
            .as_dict_mut()?
            .set("Rotate", 0);
        let input = work.path().join("unrotated.pdf");
        unrotated.save(&input)?;
        let image = work.path().join("page.png");
        pdf::render_page(&input, index + 1, dpi, &image)?;
        let prefix = work.path().join("recognized");
        let layer_path = prefix.with_extension("pdf");
        if layer_path.exists() {
            fs::remove_file(&layer_path)?;
        }
        let mut spec = CommandSpec::new(program.as_os_str());
        spec.timeout = Duration::from_secs(timeout);
        spec.args = vec![
            image.as_os_str().to_owned(),
            prefix.as_os_str().to_owned(),
            "-l".into(),
            language.into(),
            "--dpi".into(),
            dpi.to_string().into(),
            "-c".into(),
            "textonly_pdf=1".into(),
            "pdf".into(),
        ];
        let result = execute(&spec)?;
        ensure!(
            result.success() && layer_path.is_file(),
            "Tesseract did not produce fresh text-only PDF"
        );
        pdf::open_pdf(&layer_path, false)
    })
}
/// The backend seam is used by production and by adversarial-layer regressions;
/// every layer is verified and the entire derivative is published exactly once.
pub fn ocr_with_backend(
    source: &Path,
    destination: &Path,
    mut backend: impl FnMut(usize, &Document) -> Result<Document>,
) -> Result<()> {
    let destination = crate::publication::validate_destination(destination, &[source.to_owned()])?;
    let source_identity = crate::identity::file_identity(source, Some(pdf::MAX_PDF_BYTES))?;
    let mut doc = pdf::open_pdf(source, true)?;
    let expected = pdf::geometry(&doc)?;
    let mut planned = 0;
    let mut recognized = 0;
    for (index, geometry) in expected.iter().enumerate() {
        if !pdf::page_text(&doc, index + 1)?.trim().is_empty() {
            continue;
        }
        planned += 1;
        let layer = backend(index, &doc)?;
        let crop = geometry.cropbox;
        if !validate_text_layer(&layer, crop[2] - crop[0], crop[3] - crop[1])? {
            continue;
        }
        graft_text_layer(&mut doc, index, layer)?;
        recognized += 1;
    }
    ensure!(
        planned == 0 || recognized > 0,
        "OCR recognized no text; no derivative published"
    );
    ensure!(
        source_identity == crate::identity::file_identity(source, Some(pdf::MAX_PDF_BYTES))?,
        "OCR source changed during backend processing"
    );
    pdf::save_document(
        &mut doc,
        &destination,
        &[source.to_owned()],
        &expected,
        |_| Ok(()),
    )
}

/// Graft an already validated invisible layer without altering original streams.
pub fn graft_text_layer(doc: &mut Document, index: usize, mut layer: Document) -> Result<()> {
    let ids = pdf::page_ids(doc)?;
    let id = *ids.get(index).context("OCR page exceeds source")?;
    let crop = pdf::geometry(doc)?[index].cropbox;
    let w = crop[2] - crop[0];
    let h = crop[3] - crop[1];
    ensure!(validate_text_layer(&layer, w, h)?, "OCR recognized no text");
    layer.renumber_objects_with(doc.max_id + 1);
    doc.max_id = layer.max_id;
    let page = pdf::page_ids(&layer)?[0];
    let media = pdf::geometry(&layer)?[0].mediabox;
    let resources = pdf_forms::inherited(&layer, page, b"Resources")?
        .cloned()
        .unwrap_or(Object::Dictionary(Default::default()));
    let content = pdf_content::page_stream(&layer, page)?;
    doc.objects.extend(layer.objects);
    let form=doc.add_object(Stream::new(dictionary!{"Type"=>"XObject","Subtype"=>"Form","BBox"=>media.iter().map(|n|Object::Real(*n as f32)).collect::<Vec<_>>(),"Resources"=>resources},content));
    let mut resources = pdf_forms::inherited(doc, id, b"Resources")?
        .map(Object::as_dict)
        .transpose()?
        .cloned()
        .unwrap_or_default();
    let mut xobjects = resources
        .get(b"XObject")
        .ok()
        .map(|o| nav::resolved(doc, o).and_then(|v| Ok(v.as_dict()?.clone())))
        .transpose()?
        .unwrap_or_default();
    let name = format!("RvOCR{index}");
    ensure!(
        !xobjects.has(name.as_bytes()),
        "OCR resource name collision"
    );
    xobjects.set(name.as_bytes(), form);
    resources.set("XObject", xobjects);
    doc.get_object_mut(id)?
        .as_dict_mut()?
        .set("Resources", resources);
    let sx = w / (media[2] - media[0]);
    let sy = h / (media[3] - media[1]);
    let content = Content {
        operations: vec![
            Operation::new("q", vec![]),
            Operation::new(
                "cm",
                vec![
                    (sx as f32).into(),
                    0.into(),
                    0.into(),
                    (sy as f32).into(),
                    ((crop[0] - media[0] * sx) as f32).into(),
                    ((crop[1] - media[1] * sy) as f32).into(),
                ],
            ),
            Operation::new("Do", vec![Object::Name(name.into_bytes())]),
            Operation::new("Q", vec![]),
        ],
    };
    doc.add_to_page_content(id, content)?;
    Ok(())
}
