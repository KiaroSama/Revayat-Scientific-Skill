//! Exact Cargo harness layouts and adjacent final binaries, without ancestor searches.
use anyhow::{Context, Result, ensure};
use std::{ffi::OsStr, path::Path};

fn profile(path: &Path) -> bool {
    ["debug", "release"]
        .iter()
        .any(|name| path.file_name() == Some(OsStr::new(name)))
}

/// The old deps/examples layout and Cargo 1.100's package/hash/out layout only.
pub(crate) fn test_profile_directory(executable: &Path) -> Option<&Path> {
    let parent = executable.parent()?;
    if ["deps", "examples"]
        .iter()
        .any(|name| parent.file_name() == Some(OsStr::new(name)))
    {
        return parent.parent().filter(|directory| profile(directory));
    }
    if parent.file_name()? != "out" {
        return None;
    }
    let hash = parent.parent()?;
    let value = hash.file_name()?.to_str()?;
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let package = hash.parent()?;
    let name = package.file_name()?.to_str()?;
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    let build = package.parent()?;
    if build.file_name()? != "build" {
        return None;
    }
    build.parent().filter(|directory| profile(directory))
}

/// Final installed binaries stay adjacent; recognized test harnesses use their own profile.
/// Callers retain their existing fixed-name, no-link and held-image admission checks.
pub fn binary_directory(executable: &Path) -> Result<&Path> {
    ensure!(executable.is_absolute(), "executable path must be absolute");
    let parent = executable
        .parent()
        .context("executable parent directory missing")?;
    // An installed final binary can live in a directory that happens to look
    // like Cargo's cache. Only hashed harness filenames authorize that layout.
    let hash = executable
        .file_stem()
        .and_then(OsStr::to_str)
        .and_then(|name| name.rsplit_once('-'))
        .filter(|(name, hash)| {
            !name.is_empty()
                && hash.len() == 16
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .map(|(_, hash)| hash);
    if hash.is_none()
        || (parent.file_name() == Some(OsStr::new("out"))
            && parent
                .parent()
                .and_then(Path::file_name)
                .and_then(OsStr::to_str)
                != hash)
    {
        return Ok(parent);
    }
    Ok(test_profile_directory(executable).unwrap_or(parent))
}
