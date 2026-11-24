//! Figure-batch admission, original backups and checked publication.
use super::{EXTENSIONS, MAX_IMAGE_BYTES, load, plain_path, stats, write_png};
use crate::{identity, publication};
use anyhow::{Context, Result, ensure};
use image::metadata::Orientation;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub fn iter_images(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in paths {
        plain_path(path)?;
        if path.is_dir() {
            let mut entries: Vec<PathBuf> = fs::read_dir(path)?
                .map(|r| r.map(|e| e.path()))
                .collect::<std::io::Result<_>>()?;
            entries.sort();
            files.extend(entries.into_iter().filter(|p| {
                p.extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| EXTENSIONS.contains(&s.to_lowercase().as_str()))
            }));
        } else {
            ensure!(
                path.is_file()
                    && path
                        .extension()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| EXTENSIONS.contains(&s.to_lowercase().as_str())),
                "input must be an image file or directory"
            );
            files.push(path.clone());
        }
    }
    let mut keys = HashSet::new();
    let mut objects = Vec::new();
    for file in &files {
        plain_path(file)?;
        ensure!(
            keys.insert(fs::canonicalize(file)?.to_string_lossy().to_lowercase()),
            "duplicate image input"
        );
        let id = identity::path_object_id(file)?;
        ensure!(!objects.contains(&id), "aliased image input");
        objects.push(id);
    }
    ensure!(!files.is_empty(), "no images");
    Ok(files)
}

/// Validate the complete batch before staging any conversion or original backup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    BeforeEncode,
    BeforeInputCheck,
    Publication(publication::Boundary),
}
type Observations = BTreeMap<PathBuf, Option<identity::Fingerprint>>;

fn verify_path(
    path: &Path,
    expected: &Option<identity::Fingerprint>,
    observe: &mut impl FnMut(Boundary, &Path) -> Result<()>,
) -> Result<()> {
    if let Some(expected) = expected {
        observe(Boundary::BeforeInputCheck, path)?;
        plain_path(path)?;
        ensure!(
            identity::file_identity(path, Some(MAX_IMAGE_BYTES))? == *expected,
            "image input changed after decoding"
        );
    } else {
        plain_path(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => anyhow::bail!("image destination appeared after planning"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn verify_inputs(
    inputs: &Observations,
    observe: &mut impl FnMut(Boundary, &Path) -> Result<()>,
) -> Result<()> {
    for (path, expected) in inputs {
        verify_path(path, expected, observe)?;
    }
    Ok(())
}
fn verify_original(
    path: &Path,
    expected: &identity::Fingerprint,
    observe: &mut impl FnMut(Boundary, &Path) -> Result<()>,
) -> Result<()> {
    observe(Boundary::BeforeInputCheck, path)?;
    plain_path(path)?;
    ensure!(
        identity::file_identity(path, Some(MAX_IMAGE_BYTES))?.same_bytes_and_mode(expected),
        "original image backup changed before source replacement"
    );
    Ok(())
}

fn verify_final_batch(
    inputs: &Observations,
    originals: &BTreeMap<PathBuf, (PathBuf, identity::Fingerprint)>,
    observe: &mut impl FnMut(Boundary, &Path) -> Result<()>,
) -> Result<()> {
    // Finish every observer before validating the final batch. A later observer
    // must not invalidate a source or original that was already checked.
    for (path, expected) in inputs {
        if expected.is_some() {
            observe(Boundary::BeforeInputCheck, path)?;
        }
    }
    for (backup, _) in originals.values() {
        observe(Boundary::BeforeInputCheck, backup)?;
    }
    let mut silent = |_: Boundary, _: &Path| Ok(());
    verify_inputs(inputs, &mut silent)?;
    for (backup, expected) in originals.values() {
        verify_original(backup, expected, &mut silent)?;
    }
    Ok(())
}

pub fn prepare(paths: &[PathBuf], invert_dark: bool) -> Result<usize> {
    prepare_observed(paths, invert_dark, |_, _| Ok(()))
}
pub fn prepare_observed(
    paths: &[PathBuf],
    invert_dark: bool,
    mut observe: impl FnMut(Boundary, &Path) -> Result<()>,
) -> Result<usize> {
    let files = iter_images(paths)?
        .into_iter()
        .map(|path| publication::absolute(&path))
        .collect::<Result<Vec<_>>>()?;
    let mut names = HashSet::new();
    let mut plan = Vec::new();
    let mut inputs = Observations::new();
    let mut originals = BTreeMap::new();
    for source in &files {
        let in_place = source
            .extension()
            .is_some_and(|s| s.eq_ignore_ascii_case("png"));
        let raster = load(source)?;
        inputs.insert(source.clone(), Some(raster.source.clone()));
        let (mean, black) = stats(&raster);
        let invert = invert_dark && mean < 120. && black >= 0.5;
        if in_place
            && !invert
            && !raster.alpha
            && raster.mode == "Rgb8"
            && raster.orientation == Orientation::NoTransforms
        {
            continue;
        }
        let destination = if in_place {
            source.clone()
        } else {
            source.with_extension("png")
        };
        ensure!(
            names.insert(destination.to_string_lossy().to_lowercase()),
            "image destination collision"
        );
        for sibling in fs::read_dir(
            destination
                .parent()
                .context("image destination parent missing")?,
        )? {
            let p = sibling?.path();
            ensure!(
                p == destination
                    || p.file_name().unwrap().to_string_lossy().to_lowercase()
                        != destination
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .to_lowercase(),
                "case-insensitive image destination collision"
            );
        }
        let destination = publication::validate_destination(
            &destination,
            &files
                .iter()
                .filter(|p| *p != source)
                .cloned()
                .collect::<Vec<_>>(),
        )?;
        ensure!(
            in_place || !destination.exists(),
            "converted PNG destination already exists"
        );
        if !in_place {
            inputs.insert(destination.clone(), None);
        }
        let backup = if in_place {
            let backup = source.with_file_name(format!(
                "{}.orig",
                source.file_name().unwrap().to_string_lossy()
            ));
            let backup = publication::validate_destination(&backup, &files)?;
            let original = if backup.exists() {
                let original = identity::file_identity(&backup, Some(MAX_IMAGE_BYTES))?;
                ensure!(
                    original.same_bytes(&raster.source),
                    "existing original differs from current input"
                );
                Some(original)
            } else {
                None
            };
            let expected = original.as_ref().unwrap_or(&raster.source).clone();
            inputs.insert(backup.clone(), original);
            originals.insert(source.clone(), (backup.clone(), expected));
            Some(backup)
        } else {
            None
        };
        plan.push((source.clone(), destination, backup, raster, invert));
    }
    let mut dirs = Vec::new();
    let mut entries = Vec::new();
    let mut stages = BTreeMap::new();
    let mut protected = files.clone();
    for (source, dest, backup, raster, invert) in &plan {
        let mut builder = tempfile::Builder::new();
        #[cfg(unix)]
        let private = {
            use std::os::unix::fs::PermissionsExt;
            let private = fs::Permissions::from_mode(0o700);
            builder.permissions(private.clone());
            private
        };
        let dir = builder
            .prefix(".revayat-images-")
            .tempdir_in(source.parent().unwrap())?;
        #[cfg(unix)]
        fs::set_permissions(dir.path(), private)?;
        let stage = dir.path().join("figure.png");
        observe(Boundary::BeforeEncode, source)?;
        stages.insert(stage.clone(), write_png(raster, &stage, *invert)?);
        if let Some(backup) = backup {
            protected.retain(|p| p != source);
            if inputs
                .get(backup)
                .context("missing original backup admission")?
                .is_some()
            {
                protected.push(backup.clone());
            } else {
                let original = dir.path().join("original");
                let mut output = raster.source.create_file(&original)?;
                let count = std::io::copy(
                    &mut fs::File::open(source)?.take(raster.source.size.saturating_add(1)),
                    &mut output,
                )?;
                #[cfg(unix)]
                raster.source.restore_mode(&output)?;
                drop(output);
                let copied = identity::file_identity(&original, Some(MAX_IMAGE_BYTES))?;
                ensure!(
                    count == raster.source.size && copied.same_bytes_and_mode(&raster.source),
                    "source changed during original backup"
                );
                stages.insert(original.clone(), copied);
                entries.push((original, backup.clone()));
            }
        }
        entries.push((stage, dest.clone()));
        dirs.push(dir);
    }
    if entries.is_empty() {
        verify_final_batch(&inputs, &originals, &mut observe)?;
    } else {
        verify_inputs(&inputs, &mut observe)?;
        let mut committed = 0;
        publication::publish_with_identity(
            &entries,
            &protected,
            Some(MAX_IMAGE_BYTES),
            |boundary, path| {
                observe(Boundary::Publication(boundary), path)?;
                if boundary == publication::Boundary::BeforeCommit && committed == 0 {
                    verify_inputs(&inputs, &mut observe)?;
                }
                if boundary == publication::Boundary::BeforeReplace {
                    if let Some(expected) = inputs.get(path) {
                        verify_path(path, expected, &mut observe)?;
                    }
                    if let Some((backup, expected)) = originals.get(path) {
                        verify_original(backup, expected, &mut observe)?;
                    }
                }
                if boundary == publication::Boundary::AfterCommit {
                    inputs.remove(path);
                    committed += 1;
                    if committed == entries.len() {
                        verify_inputs(&inputs, &mut observe)?;
                        for (backup, expected) in originals.values() {
                            verify_original(backup, expected, &mut observe)?;
                        }
                    }
                }
                if boundary == publication::Boundary::BeforeFinalize {
                    verify_final_batch(&inputs, &originals, &mut observe)?;
                }
                Ok(())
            },
            |path, max_bytes| {
                let current = identity::file_identity(path, max_bytes)?;
                if let Some(expected) = stages.get(path) {
                    ensure!(
                        current.same_bytes_and_mode(expected),
                        "image stage differs from its producer's bytes or permissions"
                    );
                }
                Ok(current)
            },
        )?;
    }
    Ok(plan.len())
}
