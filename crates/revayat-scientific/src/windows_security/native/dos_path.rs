//! Existing local DOS object spelling without relaxing the caller's lexical grammar.
use crate::{identity::path_object_id, windows_security::plain_path};
use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};

pub(super) fn existing(path: &Path) -> Result<PathBuf> {
    plain_path(path)?;
    let text = path.to_str().context("fixed DOS object is not Unicode")?;
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    let bytes = text.as_bytes();
    ensure!(
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":\\",
        "fixed context requires a local DOS object"
    );
    let candidate = PathBuf::from(text);
    plain_path(&candidate)?;
    ensure!(
        path_object_id(path)? == path_object_id(&candidate)?,
        "DOS namespace spelling changed object identity"
    );
    Ok(candidate)
}
