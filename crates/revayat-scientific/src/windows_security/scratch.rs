//! Fixed scratch observation and lifecycle operations. Models do not prove kernel access.
use anyhow::{Result, ensure};
use std::{error::Error, fmt, sync::Arc};

#[path = "scratch_private.rs"]
pub mod private;
#[path = "scratch_private_checks.rs"]
mod private_checks;
pub use private_checks::check_private_creator_validation;
#[path = "scratch_cleanup.rs"]
pub mod cleanup;
pub use cleanup::check_cleanup_validation;
#[path = "scratch_policy.rs"]
pub mod policy;
#[path = "scratch_policy_checks.rs"]
mod policy_checks;
pub use policy_checks::{check_attachment_validation, check_volume_policy_validation};

pub(super) fn truth(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

pub type SharedError = Arc<dyn Error + Send + Sync>;
pub type OperationResult<T> = std::result::Result<T, SharedError>;

#[derive(Debug)]
pub struct Failures {
    pub errors: Vec<SharedError>,
}
impl fmt::Display for Failures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fixed scratch observation/cleanup failed")
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.errors.first().map(|error| error.as_ref() as _)
    }
}
pub fn failure(message: &'static str) -> SharedError {
    Arc::new(std::io::Error::other(message))
}
pub fn need(value: bool) -> OperationResult<()> {
    if value {
        Ok(())
    } else {
        Err(failure("fixed scratch control is unqualified"))
    }
}
pub fn finish<T>(result: OperationResult<T>, mut cleanup: Vec<SharedError>) -> OperationResult<T> {
    if cleanup.is_empty() {
        return result;
    }
    if let Err(error) = &result {
        cleanup.insert(0, error.clone());
    }
    Err(Arc::new(Failures { errors: cleanup }))
}
pub fn attempt(errors: &mut Vec<SharedError>, operation: impl FnOnce() -> OperationResult<()>) {
    if let Err(error) = operation() {
        errors.push(error);
    }
}
pub fn valid_handle(value: usize) -> bool {
    value != 0 && value != usize::MAX
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileIdentity {
    pub volume: u64,
    pub high: u64,
    pub low: u64,
}
pub fn same_identity(expected: FileIdentity, actual: FileIdentity) -> Result<()> {
    ensure!(expected == actual, "fixed scratch object identity differs");
    Ok(())
}

/// Strict binary SID construction for fixed policy principals, including diagnostic short SIDs.
pub fn sid(text: &str) -> Result<Vec<u8>> {
    let parts = text.split('-').collect::<Vec<_>>();
    ensure!(
        parts.len() >= 4 && parts[0] == "S" && parts[1] == "1" && parts.len() <= 18,
        "invalid scratch SID"
    );
    ensure!(
        parts[2..].iter().all(|part| !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_digit())
            && (part.len() == 1 || !part.starts_with('0'))),
        "invalid scratch SID"
    );
    let authority: u64 = parts[2].parse()?;
    ensure!(
        authority <= 0xffff_ffff_ffff,
        "scratch SID authority exceeds bound"
    );
    let mut bytes = vec![1, (parts.len() - 3) as u8];
    bytes.extend(&authority.to_be_bytes()[2..]);
    for part in &parts[3..] {
        bytes.extend(part.parse::<u32>()?.to_le_bytes());
    }
    Ok(bytes)
}
pub(super) fn ace(kind: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind, flags];
    bytes.extend(((8 + sid.len()) as u16).to_le_bytes());
    bytes.extend(mask.to_le_bytes());
    bytes.extend(sid);
    bytes
}
pub(super) fn acl(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![2, 0];
    bytes.extend((8 + entries.iter().map(Vec::len).sum::<usize>() as u16).to_le_bytes());
    bytes.extend((entries.len() as u16).to_le_bytes());
    bytes.extend([0, 0]);
    for entry in entries {
        bytes.extend(entry);
    }
    bytes
}
pub(super) fn descriptor(
    control: u16,
    owner: &[u8],
    group: &[u8],
    dacl: &[u8],
    sacl: Option<&[u8]>,
) -> Vec<u8> {
    let mut bytes = vec![1, 0];
    bytes.extend((control | 0x8000).to_le_bytes());
    bytes.resize(20, 0);
    for (field, value) in [
        (4, Some(owner)),
        (8, Some(group)),
        (12, sacl),
        (16, Some(dacl)),
    ] {
        if let Some(value) = value {
            let offset = bytes.len() as u32;
            bytes[field..field + 4].copy_from_slice(&offset.to_le_bytes());
            bytes.extend(value);
        }
    }
    bytes
}
