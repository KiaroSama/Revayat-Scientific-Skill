//! Checked copies, real backend invocation and owned finalization for XeTeX.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TexBoundary {
    BeforeCopy,
    AfterCopy,
    BeforeBackend,
    AfterBackend,
}
pub fn compile_document(
    source: &Path,
    output: &Path,
    config: Option<RuntimeConfig>,
    guard: Option<&Path>,
) -> Result<()> {
    let config = if let Some(config) = config {
        config
    } else {
        runtime_config()?
    };
    compile_document_observed(source, output, config, guard, &mut call, |_, _, _| Ok(()))
}
pub fn compile_document_observed(
    source: &Path,
    output: &Path,
    config: RuntimeConfig,
    guard: Option<&Path>,
    execute: &mut impl FnMut(&[String], u64) -> Result<(i32, String)>,
    boundary: impl FnMut(TexBoundary, &Path, &Path) -> Result<()>,
) -> Result<()> {
    compile_document_with_recovery(
        source,
        output,
        config,
        guard,
        execute,
        boundary,
        finalize::recovery,
    )
}
pub fn compile_document_with_recovery(
    source: &Path,
    output: &Path,
    config: RuntimeConfig,
    guard: Option<&Path>,
    execute: &mut impl FnMut(&[String], u64) -> Result<(i32, String)>,
    boundary: impl FnMut(TexBoundary, &Path, &Path) -> Result<()>,
    report: impl FnOnce(&Path, &str) -> Result<()>,
) -> Result<()> {
    compile_document_with_lifecycle(
        source,
        output,
        config,
        guard,
        execute,
        boundary,
        (
            crate::tex_supervisor::register,
            crate::tex_supervisor::acknowledge,
            report,
        ),
    )
}
/// Per-call external ownership/report adapters; production wrappers always use
/// the real supervisor. Synthetic backends must not register fake daemon receipts.
pub fn compile_document_with_lifecycle(
    source: &Path,
    output: &Path,
    config: RuntimeConfig,
    guard: Option<&Path>,
    execute: &mut impl FnMut(&[String], u64) -> Result<(i32, String)>,
    mut boundary: impl FnMut(TexBoundary, &Path, &Path) -> Result<()>,
    finalization: (
        impl FnOnce(&RuntimeConfig, &Path, &str) -> Result<Option<PathBuf>>,
        impl FnOnce(Option<&Path>) -> Result<()>,
        impl FnOnce(&Path, &str) -> Result<()>,
    ),
) -> Result<()> {
    let (register, acknowledge, report) = finalization;
    let source = source.canonicalize()?;
    let inputs = approved_files(&source)?;
    let protected = inputs.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>();
    let output = validate_destination(output, &protected)?;
    if let Some(path) = guard {
        ensure!(
            BuildGuard::check(path, None)?.outputs[0] == output,
            "TeX guard belongs to another renderer output"
        );
    }
    fs::create_dir_all(output.parent().context("output parent missing")?)?;
    let stage = tempfile::Builder::new()
        .prefix(".revayat-tex-")
        .tempdir_in(output.parent().unwrap())?;
    let directory = stage.path().to_owned();
    let run_id = crate::tex_supervisor::new_token();
    let incoming = directory.join("input");
    let outgoing = directory.join("output");
    fs::create_dir(&incoming)?;
    fs::create_dir(&outgoing)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&outgoing, fs::Permissions::from_mode(0o777))?;
    }
    let identities = inputs
        .iter()
        .map(|(original, _)| {
            Ok((
                original.clone(),
                crate::identity::file_identity(original, Some(MAX_INPUT_BYTES))?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let snapshots = identities
        .iter()
        .map(|(path, identity)| (path.clone(), identity.sha256.clone()))
        .collect::<BTreeMap<_, _>>();
    for (original, relative) in &inputs {
        let digest = &snapshots[original];
        let target = incoming.join(relative);
        fs::create_dir_all(target.parent().unwrap())?;
        boundary(TexBoundary::BeforeCopy, original, &target)?;
        let mut reader =
            fs::File::open(original)?.take(identities[original].size.saturating_add(1));
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        ensure!(
            std::io::copy(&mut reader, &mut writer)? == identities[original].size,
            "TeX input changed during bounded checked copy"
        );
        writer.sync_all()?;
        drop(writer);
        drop(reader);
        boundary(TexBoundary::AfterCopy, original, &target)?;
        ensure!(
            file_hash(&target)? == *digest,
            "TeX input changed preparing checked copy"
        );
    }
    for (original, digest) in &snapshots {
        ensure!(
            file_hash(original)? == *digest,
            "TeX input changed preparing checked copy"
        );
    }
    let main = incoming.join(STAGED_MAIN);
    let checked_main = incoming.join(source.file_name().context("source basename missing")?);
    ensure!(
        !main.try_exists()? || main == checked_main,
        "approved input collides with reserved renderer filename"
    );
    if main != checked_main {
        let mut reader =
            fs::File::open(&checked_main)?.take(identities[&source].size.saturating_add(1));
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&main)?;
        ensure!(
            std::io::copy(&mut reader, &mut writer)? == identities[&source].size,
            "renderer main changed during bounded checked copy"
        );
        writer.sync_all()?;
    }
    ensure!(
        file_hash(&main)? == snapshots[&source],
        "renderer main copy differs from checked source"
    );
    if let Some(path) = guard {
        BuildGuard::check(path, Some(&snapshots))?;
    }
    boundary(TexBoundary::BeforeBackend, &source, &directory)?;
    let arguments = run_arguments(&config, &directory, STAGED_MAIN, &run_id)?;
    let receipt = register(&config, &directory, &run_id)?;
    let rendered = execute(&arguments, INNER_TIMEOUT + 30);
    let after = boundary(TexBoundary::AfterBackend, &source, &directory);
    let rendered = rendered.and_then(|(code, text)| {
        if code != 0 {
            let evidence = std::env::var_os("SCIENTIFIC_EVIDENCE_DIR").map(PathBuf::from);
            let _ = retain_fixture_console(
                &source,
                &outgoing,
                &run_id,
                evidence.as_deref(),
                std::env::var("SCIENTIFIC_RENDER").as_deref() == Ok("1"),
            );
        }
        ensure!(
            code == 0,
            "isolated XeLaTeX failed or exceeded its deadline (exit_code={code}, category={})",
            failure_class(&outgoing)?
        );
        Ok((code, text))
    });
    let operation = runtime::with_cleanup(rendered, after);
    let cleanup = cleanup_with(&config, &directory, &run_id, false, execute);
    let (_stage, _) = finalize::finish_stage(
        stage,
        &run_id,
        operation,
        cleanup,
        || acknowledge(receipt.as_deref()),
        report,
    )?;
    let pdf = outgoing.join("document.pdf");
    crate::render::validate_pdf(&pdf)?;
    for (original, relative) in &inputs {
        ensure!(
            file_hash(original)? == snapshots[original]
                && file_hash(&incoming.join(relative))? == snapshots[original],
            "TeX input or staged copy changed during rendering"
        );
    }
    ensure!(
        file_hash(&main)? == snapshots[&source],
        "renderer main copy changed during compilation"
    );
    let mut protected = protected;
    if let Some(path) = guard {
        protected.extend(BuildGuard::check(path, None)?.protected(path));
    }
    let digest = file_hash(&pdf)?;
    publish_files(&[(pdf, output.clone())], &protected, Some(MAX_INPUT_BYTES))?;
    if let Some(path) = guard {
        BuildGuard::seal(path, &output, &digest)?;
    }
    Ok(())
}
