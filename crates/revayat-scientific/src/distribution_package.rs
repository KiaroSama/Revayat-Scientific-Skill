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
    BeforeArchiveEntry(usize),
    Staged,
    BeforePublish,
    Publication(crate::publication::Boundary),
}
pub fn package(
    source: &Path,
    repository: &Path,
    output: &Path,
    binary: Option<&Path>,
) -> Result<()> {
    package_observed(source, repository, output, binary, |_, _| Ok(()))
}
pub fn package_for_target(
    source: &Path,
    repository: &Path,
    output: &Path,
    binary: &Path,
    target_triple: &str,
) -> Result<()> {
    let payload = Payload::collect_for_target(source, binary, target_triple)?;
    package_payload(source, repository, output, payload, |_, _| Ok(()))
}
pub fn package_observed(
    source: &Path,
    repository: &Path,
    output: &Path,
    binary: Option<&Path>,
    observe: impl FnMut(PackageBoundary, &Path) -> Result<()>,
) -> Result<()> {
    let payload = Payload::collect(source, binary)?;
    package_payload(source, repository, output, payload, observe)
}
fn package_payload(
    source: &Path,
    repository: &Path,
    output: &Path,
    payload: Payload,
    mut observe: impl FnMut(PackageBoundary, &Path) -> Result<()>,
) -> Result<()> {
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
        for (index, row) in payload.files.iter().enumerate() {
            let executable = row.relative.starts_with("bin");
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .system(zip::System::Unix)
                .unix_permissions(if executable { 0o755 } else { 0o644 });
            archive.start_file(
                format!(
                    "{NAME}/{}",
                    row.relative.to_string_lossy().replace('\\', "/")
                ),
                options,
            )?;
            observe(PackageBoundary::BeforeArchiveEntry(index), &row.source)?;
            let handle = File::open(&row.source)?;
            let metadata = handle.metadata()?;
            ensure!(
                metadata.is_file()
                    && crate::identity::object_id(&handle)? == row.fingerprint.identity
                    && metadata.len() == row.fingerprint.size
                    && metadata.modified()? == row.fingerprint.modified,
                "payload changed before archive write"
            );
            let copied = std::io::copy(
                &mut handle.take(row.fingerprint.size.saturating_add(1)),
                &mut archive,
            )?;
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
    publish_archive(
        stage.path(),
        &output,
        &protected,
        &payload,
        |boundary, path| {
            observe(boundary, path)?;
            if matches!(
                boundary,
                PackageBoundary::BeforePublish
                    | PackageBoundary::Publication(crate::publication::Boundary::BeforeReplace)
            ) {
                protected_location(path, repository, source, false)?;
            }
            Ok(())
        },
    )
}
fn publish_archive(
    stage: &Path,
    output: &Path,
    protected: &[PathBuf],
    payload: &Payload,
    mut observe: impl FnMut(PackageBoundary, &Path) -> Result<()>,
) -> Result<()> {
    let verified = crate::identity::file_identity(stage, Some(MAX_PAYLOAD_BYTES))?;
    verify_archive(stage, payload)?;
    ensure!(
        crate::identity::file_identity(stage, Some(MAX_PAYLOAD_BYTES))? == verified,
        "archive changed during payload verification"
    );
    observe(PackageBoundary::BeforePublish, output)?;
    crate::publication::publish_observed(
        &[(stage.to_owned(), output.to_owned())],
        protected,
        Some(MAX_PAYLOAD_BYTES),
        |boundary, path| {
            observe(PackageBoundary::Publication(boundary), path)?;
            if boundary == crate::publication::Boundary::BeforeReplace {
                ensure!(
                    crate::identity::file_identity(stage, Some(MAX_PAYLOAD_BYTES))?
                        .same_bytes(&verified),
                    "verified archive changed before publication"
                );
            }
            Ok(())
        },
    )?;
    Ok(())
}
fn verify_archive(path: &Path, payload: &Payload) -> Result<()> {
    let mut archive = zip::ZipArchive::new(File::open(path)?)?;
    archive
        .validate_header_consistency()
        .context("archive payload headers are inconsistent")?;
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
                (
                    &f.fingerprint,
                    if f.relative.starts_with("bin") {
                        0o100755
                    } else {
                        0o100644
                    },
                ),
            )
        })
        .collect();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name()?;
        let (row, mode) = expected
            .get(name.as_ref())
            .context("unexpected archive payload entry")?;
        ensure!(
            file.system() == zip::System::Unix && file.unix_mode() == Some(*mode),
            "archive payload type or permissions differ from the collected member"
        );
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
            bytes.len() as u64 == row.size && format!("{:x}", Sha256::digest(&bytes)) == row.sha256,
            "archive payload bytes differ from source"
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};

    fn fixture(target: &str) -> Result<(tempfile::TempDir, PathBuf, Payload)> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        let source = root.join("source");
        fs::create_dir(&source)?;
        fs::write(
            source.join("SKILL.md"),
            b"---\nname: revayat-scientific\n---\n",
        )?;
        fs::write(source.join("LICENSE"), b"GPL-3.0-or-later")?;
        let binary = root.join("native-binary");
        fs::write(&binary, b"synthetic native executable")?;
        fs::write(
            root.join(if target.contains("windows") {
                "revayat-quota-worker.exe"
            } else {
                "revayat-process-owner"
            }),
            b"synthetic native companion",
        )?;
        let payload = Payload::collect_for_target(&source, &binary, target)?;
        let path = root.join("bundle.skill");
        let mut archive = zip::ZipWriter::new(File::create(&path)?);
        for row in &payload.files {
            archive.start_file(
                format!(
                    "{NAME}/{}",
                    row.relative.to_string_lossy().replace('\\', "/")
                ),
                zip::write::SimpleFileOptions::default()
                    .system(zip::System::Unix)
                    .unix_permissions(if row.relative.starts_with("bin") {
                        0o755
                    } else {
                        0o644
                    }),
            )?;
            archive.write_all(&fs::read(&row.source)?)?;
        }
        archive.finish()?;
        Ok((temp, path, payload))
    }

    #[test]
    fn staged_archive_accepts_complete_native_payloads_for_every_target() -> Result<()> {
        for target in crate::release_bundle::REQUIRED_TARGETS {
            let (_temp, path, payload) = fixture(target)?;
            verify_archive(&path, &payload)?;
        }
        Ok(())
    }

    #[test]
    fn late_verified_archive_mutations_preserve_the_previous_delivery() -> Result<()> {
        let mut accepted = Vec::new();
        for mutation in [
            PackageBoundary::BeforePublish,
            PackageBoundary::Publication(crate::publication::Boundary::BeforeReplace),
        ] {
            let (_temp, path, payload) = fixture("x86_64-unknown-linux-gnu")?;
            let output = path.with_file_name("approved.skill");
            fs::write(&output, b"approved previous archive")?;
            let mut changed = false;
            let result = publish_archive(&path, &output, &[], &payload, |at, _| {
                if at == mutation {
                    fs::write(&path, b"different unvalidated bytes")?;
                    changed = true;
                }
                Ok(())
            });
            assert!(changed, "the actual publication mutation must execute");
            if result.is_ok() || fs::read(&output)? != b"approved previous archive" {
                accepted.push(mutation);
            }
        }
        assert!(
            accepted.is_empty(),
            "verified archive mutations replaced the previous delivery: {accepted:?}"
        );
        Ok(())
    }

    #[test]
    fn staged_archive_rejects_inconsistent_local_filenames() -> Result<()> {
        let (_temp, path, payload) = fixture("x86_64-unknown-linux-gnu")?;
        let mut archive = zip::ZipArchive::new(File::open(&path)?)?;
        let offset = archive.by_name(&format!("{NAME}/SKILL.md"))?.header_start();
        drop(archive);
        let mut file = fs::OpenOptions::new().write(true).open(&path)?;
        file.seek(SeekFrom::Start(offset + 30 + NAME.len() as u64 + 1))?;
        file.write_all(b"X")?;
        drop(file);
        assert!(
            verify_archive(&path, &payload).is_err(),
            "local-header filename differs from the collected member"
        );
        Ok(())
    }

    #[test]
    fn staged_archive_rejects_changed_member_types_and_permissions() -> Result<()> {
        let mut accepted = Vec::new();
        for (label, name, mode) in [
            ("symlink", "SKILL.md", 0o120644_u32),
            ("data-permissions", "SKILL.md", 0o100777_u32),
            (
                "nonexecutable-binary",
                "bin/revayat-scientific",
                0o100644_u32,
            ),
        ] {
            let (_temp, path, payload) = fixture("x86_64-unknown-linux-gnu")?;
            let mut archive = zip::ZipArchive::new(File::open(&path)?)?;
            let offset = archive
                .by_name(&format!("{NAME}/{name}"))?
                .central_header_start();
            drop(archive);
            let mut file = fs::OpenOptions::new().write(true).open(&path)?;
            file.seek(SeekFrom::Start(offset + 38))?;
            file.write_all(&(mode << 16).to_le_bytes())?;
            drop(file);
            if verify_archive(&path, &payload).is_ok() {
                accepted.push(label);
            }
        }
        assert!(
            accepted.is_empty(),
            "invalid archive member metadata accepted: {accepted:?}"
        );
        Ok(())
    }

    #[test]
    fn staged_archive_rejects_duplicate_central_directory_entries() -> Result<()> {
        let (_temp, path, payload) = fixture("x86_64-unknown-linux-gnu")?;
        let mut archive = zip::ZipArchive::new(File::open(&path)?)?;
        let offset = archive
            .by_name(&format!("{NAME}/SKILL.md"))?
            .central_header_start() as usize;
        drop(archive);
        let mut bytes = fs::read(&path)?;
        let end = bytes
            .windows(4)
            .rposition(|value| value == b"PK\x05\x06")
            .unwrap();
        let count = u16::from_le_bytes(bytes[end + 10..end + 12].try_into()?);
        let size = u32::from_le_bytes(bytes[end + 12..end + 16].try_into()?);
        let length = 46
            + [28, 30, 32]
                .into_iter()
                .map(|field| {
                    u16::from_le_bytes(
                        bytes[offset + field..offset + field + 2]
                            .try_into()
                            .unwrap(),
                    ) as usize
                })
                .sum::<usize>();
        let duplicate = bytes[offset..offset + length].to_vec();
        bytes[end + 8..end + 10].copy_from_slice(&(count + 1).to_le_bytes());
        bytes[end + 10..end + 12].copy_from_slice(&(count + 1).to_le_bytes());
        bytes[end + 12..end + 16].copy_from_slice(&(size + length as u32).to_le_bytes());
        bytes.splice(end..end, duplicate);
        fs::write(&path, bytes)?;
        assert!(
            verify_archive(&path, &payload).is_err(),
            "duplicate central directory member was accepted"
        );
        Ok(())
    }
}
