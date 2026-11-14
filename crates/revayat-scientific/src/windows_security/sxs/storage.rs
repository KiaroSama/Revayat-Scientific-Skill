//! Exact private SxS storage predicates and fixed synchronous creation result.
use anyhow::{Result, ensure};
#[path = "storage_creation.rs"]
pub mod creation;
pub use creation::check_validation;

/// Four final rules; the original first failing predicate is retained.
pub fn require_policy(bytes: &[u8], directory: bool, owner: &[u8], package: &[u8]) -> Result<()> {
    super::storage_policy::require(bytes, directory, owner, package)
}
pub(crate) fn validate_folder(folder: &str) -> Result<()> {
    let bytes = folder.as_bytes();
    ensure!(
        bytes.len() == 45
            && (b'D'..=b'Z').contains(&bytes[0])
            && &bytes[1..13] == b":\\sxs-trace-"
            && bytes[13..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
        "invalid fixed SxS storage folder"
    );
    Ok(())
}
/// No drive aliases, alternate mappings, system volume or arbitrary path components are accepted.
pub fn native_path(folder: &str, mapping: &[u16]) -> Result<String> {
    validate_folder(folder)?;
    ensure!(
        (3..=512).contains(&mapping.len())
            && mapping.ends_with(&[0, 0])
            && !mapping[..mapping.len() - 2].contains(&0),
        "invalid fixed SxS device mapping"
    );
    let device = String::from_utf16(&mapping[..mapping.len() - 2])?;
    let suffix = device
        .strip_prefix("\\Device\\HarddiskVolume")
        .ok_or_else(|| anyhow::anyhow!("unsupported fixed SxS device family"))?;
    ensure!(
        !suffix.is_empty() && suffix.len() <= 20 && suffix.bytes().all(|b| b.is_ascii_digit()),
        "invalid fixed SxS device identity"
    );
    let path = format!("{device}\\{}", &folder[3..]);
    ensure!(
        path.encode_utf16().count() * 2 <= 512,
        "fixed SxS native path exceeds bound"
    );
    Ok(path)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    Created,
    Pending,
}
pub fn creation_completion(
    returned: i32,
    completed: i32,
    information: u64,
    handle: usize,
) -> Result<Completion> {
    if returned == 0x103 || completed == 0x103 {
        return Ok(Completion::Pending);
    }
    ensure!(
        returned == 0,
        "fixed SxS native creation failed ntstatus={:08X}",
        returned as u32
    );
    ensure!(
        completed == 0 && information == 2 && handle != 0 && handle != usize::MAX,
        "fixed SxS native creation output differs"
    );
    Ok(Completion::Created)
}
