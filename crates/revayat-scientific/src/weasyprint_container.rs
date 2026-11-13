//! Optional external WeasyPrint inside the same finite native container boundary.
use crate::{
    build::{BuildGuard, MAX_FILE_BYTES, file_hash},
    publication::{publish_files, validate_destination},
    resource::ResourcePolicy,
    tex_container::{self, RuntimeConfig},
};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

fn stage(parent: &Path) -> Result<tempfile::TempDir> {
    let stage = tempfile::Builder::new()
        .prefix(".revayat-tex-")
        .tempdir_in(parent)?;
    fs::create_dir(stage.path().join("input"))?;
    fs::create_dir(stage.path().join("output"))?;
    Ok(stage)
}

/// Only the native entry's clean optional-renderer refusal is absence. Docker
/// errors, wrapper deadlines, capture failures and uncertain cleanup propagate.
pub fn is_unavailable_probe(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<crate::runtime::CleanupFailure>()
        .is_none()
        && error
            .downcast_ref::<crate::runtime::DeadlineExceeded>()
            .is_none()
        && error
            .downcast_ref::<tex_container::IsolatedRendererFailure>()
            .is_some_and(|failure| failure.code == 2)
}

/// Readiness is a real bounded isolated invocation, with the same owned holder,
/// synchronous exec and final cleanup as rendering. It never borrows Chromium.
pub fn available(config: RuntimeConfig) -> Result<Option<RuntimeConfig>> {
    let parent = std::env::temp_dir().canonicalize()?;
    let prepared = stage(&parent)?;
    match tex_container::execute_prepared_job(&config, prepared, &["--engine-info", "weasyprint"]) {
        Ok(prepared) => {
            prepared
                .close()
                .context("WeasyPrint readiness stage cleanup failed")?;
            Ok(Some(config))
        }
        Err(error) if is_unavailable_probe(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn render_html(
    source: &Path,
    output: &Path,
    config: RuntimeConfig,
    guard: Option<&Path>,
) -> Result<()> {
    let source = source.canonicalize()?;
    let output = validate_destination(output, std::slice::from_ref(&source))?;
    let mut policy = ResourcePolicy::new(&source)?;
    if let Some(path) = guard {
        let record = BuildGuard::check(path, Some(&policy.resources))?;
        ensure!(
            record.outputs[0] == output,
            "HTML guard belongs to another output"
        );
    }
    fs::create_dir_all(output.parent().context("HTML output parent missing")?)?;
    let prepared = stage(output.parent().unwrap())?;
    policy.stage_for_container(&prepared.path().join("input"))?;
    let prepared = tex_container::execute_prepared_job(&config, prepared, &["--weasyprint"])?;
    let rendered = prepared.path().join("output/document.pdf");
    crate::render::validate_pdf(&rendered)?;
    ensure!(!policy.denied, "render resource access denied");
    for (path, digest) in &policy.resources {
        ensure!(
            file_hash(path)? == *digest,
            "document resource changed before publication"
        );
    }
    let mut protected: Vec<_> = policy.resources.keys().cloned().collect();
    if let Some(path) = guard {
        protected.extend(BuildGuard::check(path, Some(&policy.resources))?.protected(path));
    }
    let digest = file_hash(&rendered)?;
    publish_files(
        &[(rendered, output.clone())],
        &protected,
        Some(MAX_FILE_BYTES),
    )?;
    if let Some(path) = guard {
        BuildGuard::seal(path, &output, &digest)?;
    }
    prepared
        .close()
        .context("WeasyPrint render stage cleanup failed")?;
    Ok(())
}
