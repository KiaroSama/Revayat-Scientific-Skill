//! Safe diagnostics shared by the two native creation boundaries.
use anyhow::{Result, ensure};
use std::{ffi::OsStr, fmt, os::windows::ffi::OsStrExt, path::Path};

/// An explicit Unicode allowlist, never a copy of the host environment.
/// AppContainer initialization requires LOCALAPPDATA as well as SystemRoot;
/// Windows reroutes the former to the package profile. Baseline Sandbox.cs also
/// supplied it from its private home. Keep its input in our protected scratch.
/// https://learn.microsoft.com/windows/win32/secauthz/implementing-an-appcontainer
/// https://github.com/microsoft/mxc/pull/1158
pub(super) fn authority_environment(
    system_root: &OsStr,
    scratch: &Path,
    fixture: &str,
    foreign: &Path,
    network: &str,
) -> Result<Vec<u16>> {
    let entries = [
        ("LOCALAPPDATA", scratch.as_os_str()),
        ("REVAYAT_AUTHORITY_FIXTURE", OsStr::new(fixture)),
        ("REVAYAT_AUTHORITY_FOREIGN", foreign.as_os_str()),
        ("REVAYAT_AUTHORITY_NETWORK", OsStr::new(network)),
        ("SystemRoot", system_root),
        ("TEMP", scratch.as_os_str()),
        ("TMP", scratch.as_os_str()),
        ("WINDIR", system_root),
    ];
    let mut block = Vec::new();
    for (name, value) in entries {
        let value = value.encode_wide().collect::<Vec<_>>();
        ensure!(
            !value.is_empty() && !value.contains(&0),
            "invalid authority environment value"
        );
        block.extend(name.encode_utf16());
        block.push(b'=' as u16);
        block.extend(value);
        block.push(0);
        ensure!(block.len() < 32767, "authority environment exceeds bound");
    }
    block.push(0);
    Ok(block)
}

#[derive(Debug)]
pub(super) struct CreationFailure {
    pub(super) operation: &'static str,
    pub(super) code: Option<u32>,
}

impl fmt::Display for CreationFailure {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(code) => write!(
                output,
                "native authority creation failed operation={} winerror={code} winerror_hex={code:08X}",
                self.operation
            ),
            None => write!(
                output,
                "native authority creation returned invalid handles operation={}",
                self.operation
            ),
        }
    }
}

impl std::error::Error for CreationFailure {}

pub(super) fn creation_result(
    success: i32,
    valid_outputs: bool,
    operation: &'static str,
    last_error: impl FnOnce() -> u32,
) -> Result<()> {
    let code = if success == 0 {
        Some(last_error())
    } else {
        None
    };
    if code.is_some() || !valid_outputs {
        return Err(CreationFailure { operation, code }.into());
    }
    Ok(())
}

pub(super) fn retain_cleanup<T>(result: Result<T>, failures: usize) -> Result<T> {
    if failures == 0 {
        return result;
    }
    match result {
        Err(primary) => {
            let cleanup = format!("authority cleanup also failed in {failures} owned operations");
            // Only this fixed operation/code type may enter the outer diagnostic.
            let context = match primary.downcast_ref::<CreationFailure>() {
                Some(creation) => format!("{creation}; {cleanup}"),
                None => cleanup,
            };
            Err(primary.context(context))
        }
        Ok(_) => anyhow::bail!("authority cleanup failed in {failures} owned operations"),
    }
}
