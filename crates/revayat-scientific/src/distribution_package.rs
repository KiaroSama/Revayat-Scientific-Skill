//! Complete native skill archives with protected source/Git publication.
use crate::distribution::{MAX_PAYLOAD_BYTES, NAME, Payload, repository_root};
use crate::distribution_paths::protected_location;
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageBoundary {
    Staged,
    BeforePublish,
}
pub fn package(
    source: &Path,
    repository: &Path,
    output: &Path,
    binary: Option<&Path>,
) -> Result<()> {
    package_observed(source, repository, output, binary, |_, _| Ok(()))
}
pub fn package_observed(
    source: &Path,
    repository: &Path,
    output: &Path,
    binary: Option<&Path>,
    mut observe: impl FnMut(PackageBoundary, &Path) -> Result<()>,
) -> Result<()> {
    let payload = Payload::collect(source, binary)?;
    let output = protected_location(output, repository, source, false)?;
    let mut protected: Vec<_> = payload.files.iter().map(|f| f.source.clone()).collect();
    let administration = crate::distribution_paths::git_paths(repository)?;
    let is_repository = !administration.is_empty();
    protected.extend(administration);
    // Protect hardlinked tracked source too, even when it is outside the payload.
    let listing = crate::distribution_paths::git_result(repository, &["ls-files", "-z"])?;
    ensure!(
        listing.success() || !is_repository,
        "cannot enumerate tracked source files; packaging refused"
    );
    if listing.success() {
        for name in listing.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()) {
            protected.push(repository.join(std::str::from_utf8(name)?));
        }
    }
    crate::publication::validate_destination(&output, &protected)?;
    let parent = output.parent().context("archive lacks parent")?;
    fs::create_dir_all(parent)?;
    let mut stage = tempfile::Builder::new()
        .prefix(".revayat-package-")
        .tempfile_in(parent)?;
    {
        let mut archive = zip::ZipWriter::new(stage.as_file_mut());
        for row in &payload.files {
            let executable = row.relative.starts_with("bin");
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(if executable { 0o755 } else { 0o644 });
            archive.start_file(
                format!(
                    "{NAME}/{}",
                    row.relative.to_string_lossy().replace('\\', "/")
                ),
                options,
            )?;
            let mut handle = File::open(&row.source)?;
            let copied = std::io::copy(&mut handle, &mut archive)?;
            ensure!(
                copied == row.fingerprint.size,
                "payload changed during archive write"
            );
        }
        archive.finish()?;
    }
    stage.as_file_mut().flush()?;
    stage.as_file().sync_all()?;
    observe(PackageBoundary::Staged, stage.path())?;
    payload.verify()?;
    {
        let mut archive = zip::ZipArchive::new(File::open(stage.path())?)?;
        ensure!(
            archive.len() == payload.files.len(),
            "archive payload entry count changed"
        );
        let expected: std::collections::BTreeMap<_, _> = payload
            .files
            .iter()
            .map(|f| {
                (
                    format!("{NAME}/{}", f.relative.to_string_lossy().replace('\\', "/")),
                    &f.fingerprint,
                )
            })
            .collect();
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let name = file.name()?;
            let row = expected
                .get(name.as_ref())
                .context("unexpected archive payload entry")?;
            ensure!(
                file.size() == row.size,
                "archive payload size differs from source"
            );
            let mut bytes = Vec::new();
            file.by_ref()
                .take(MAX_PAYLOAD_BYTES + 1)
                .read_to_end(&mut bytes)?;
            use sha2::{Digest, Sha256};
            ensure!(
                bytes.len() as u64 == row.size
                    && format!("{:x}", Sha256::digest(&bytes)) == row.sha256,
                "archive payload bytes differ from source"
            );
        }
    }
    observe(PackageBoundary::BeforePublish, &output)?;
    protected_location(&output, repository, source, false)?;
    crate::publication::publish_files(
        &[(stage.path().to_owned(), output)],
        &protected,
        Some(MAX_PAYLOAD_BYTES),
    )?;
    Ok(())
}
pub fn cli_package(args: &[String]) -> Result<i32> {
    use clap::Parser;
    #[derive(Parser)]
    struct Options {
        #[arg(long, default_value = "dist/revayat-scientific.skill")]
        output: PathBuf,
    }
    let opts =
        Options::try_parse_from(std::iter::once("package".to_owned()).chain(args.iter().cloned()))?;
    let root = repository_root()?;
    package(
        &root.join("skills").join(NAME),
        &root,
        &opts.output,
        Some(&std::env::current_exe()?),
    )?;
    println!("Packaged {}", opts.output.display());
    Ok(0)
}
