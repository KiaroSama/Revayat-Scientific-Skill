//! Fixed activation and stopped-thread contracts. Model checks are not kernel attestation.
use anyhow::{Result, ensure};
use std::collections::BTreeSet;
use std::fmt;

#[cfg(windows)]
#[path = "activation/native.rs"]
pub mod native;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ActCtx {
    pub size: u32,
    pub flags: u32,
    pub source: usize,
    pub architecture: u16,
    pub language: u16,
    pub directory: usize,
    pub resource: usize,
    pub application: usize,
    pub module: usize,
}
#[derive(Clone, Copy, Debug)]
pub enum CallRole {
    Executable,
    DllResource,
    HostDll,
    StandaloneManifest,
}
impl ActCtx {
    pub fn fixed(role: CallRole, source: usize, directory: usize, language: u16) -> Self {
        let (flags, resource) = match role {
            CallRole::Executable => (0x2e, 1),
            CallRole::DllResource => (0x2e, 2),
            CallRole::HostDll => (8, 2),
            CallRole::StandaloneManifest => (0, 0),
        };
        Self {
            size: 56,
            flags,
            source,
            architecture: 0,
            language: if flags & 2 != 0 { language } else { 0 },
            directory: if flags & 4 != 0 { directory } else { 0 },
            resource,
            application: if flags & 0x20 != 0 { source } else { 0 },
            module: 0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivationOutcome {
    pub created: bool,
    pub error: u32,
}
pub fn require_absent_thread_token(opened: bool, error: u32, token: usize) -> Result<()> {
    ensure!(
        !opened && error == 1008 && token == 0,
        "activation host thread identity is not unimpersonated"
    );
    Ok(())
}
pub mod assembly;
pub mod capture;
pub mod control;
pub mod dispatch;
pub mod dll;
pub mod dll_request;
pub mod sweep;
pub use dll::check_fixed_dll_validation;
pub use sweep::check_manual_activation_validation;
pub mod loader;
pub mod self_result;
pub mod threads;
pub use self_result::check_policy_result_validation;
#[path = "activation/validation.rs"]
mod validation;
pub use validation::{
    FixedPathCall, check_startup_activation_validation, finalize_checked, report, startup_outcome,
};

pub fn creation_outcome(
    handle: usize,
    last_error: impl FnOnce() -> u32,
) -> Result<ActivationOutcome> {
    let error = if handle == usize::MAX {
        last_error()
    } else {
        0
    };
    ensure!(handle != 0, "activation returned a null success handle");
    Ok(ActivationOutcome {
        created: handle != usize::MAX,
        error,
    })
}

/// Ordered causes remain available to owners; public formatting never expands private errors.
pub struct Failures {
    pub errors: Vec<anyhow::Error>,
}
impl fmt::Debug for Failures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Failures")
            .field("count", &self.errors.len())
            .finish()
    }
}
impl fmt::Display for Failures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "fixed activation operation/cleanup failed count={}",
            self.errors.len()
        )
    }
}
impl std::error::Error for Failures {}
fn finish(mut errors: Vec<anyhow::Error>) -> Result<()> {
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.remove(0)),
        _ => Err(Failures { errors }.into()),
    }
}
pub fn finalize_comparison<'a>(
    primary: Option<anyhow::Error>,
    impersonating: bool,
    revert: impl FnOnce() -> Result<()>,
    fatal: impl FnOnce(),
    cleanup: Vec<Box<dyn FnMut() -> Result<()> + 'a>>,
    emit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    finalize_checked(
        primary,
        impersonating,
        || revert().map(|()| true),
        || {
            fatal();
            Ok(())
        },
        cleanup,
        emit,
    )
}

pub fn bounded_report(lines: &[String], newline: &str) -> Result<String> {
    ensure!(
        matches!(newline, "\n" | "\r\n") && lines.len() <= 15,
        "activation report line bound exceeded"
    );
    let mut bytes = 0usize;
    for line in lines {
        bytes = bytes
            .checked_add(line.len())
            .and_then(|n| n.checked_add(newline.len()))
            .ok_or_else(|| anyhow::anyhow!("activation report length overflow"))?;
        ensure!(bytes <= 12288, "activation report byte bound exceeded");
    }
    Ok(lines
        .iter()
        .map(|line| format!("{line}{newline}"))
        .collect())
}
pub fn activation_event<'a>(
    operation: impl FnOnce() -> Result<()>,
    mut restore: impl FnMut() -> Result<()>,
    releases: Vec<Box<dyn FnMut() -> Result<()> + 'a>>,
    continuation: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut errors = Vec::new();
    if let Err(error) = operation() {
        errors.push(error);
    }
    let restored = !errors.is_empty();
    if restored && let Err(error) = restore() {
        errors.push(error);
    }
    for mut release in releases {
        if let Err(error) = release() {
            errors.push(error);
        }
    }
    if !restored
        && !errors.is_empty()
        && let Err(error) = restore()
    {
        errors.push(error);
    }
    if let Err(error) = continuation() {
        errors.push(error);
    }
    finish(errors)
}

pub const CONTEXT_SIZE: usize = 1232;
fn context(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() == CONTEXT_SIZE, "x64 context size differs");
    Ok(())
}
pub fn unchanged_control_integer(before: &[u8], after: &[u8]) -> Result<bool> {
    context(before)?;
    context(after)?;
    Ok(before[56..58] == after[56..58]
        && before[66..72] == after[66..72]
        && before[120..256] == after[120..256])
}
pub fn raw_debug_equal(before: &[u8], after: &[u8]) -> Result<bool> {
    context(before)?;
    context(after)?;
    Ok(before[72..120] == after[72..120])
}
pub fn owned_trap_status(status: u64, control: u64, expected: u64, slot: u32) -> bool {
    slot <= 1
        && expected & !0x405 == 0
        && expected & (1 << (slot * 2)) != 0
        && (control ^ expected) & !0x400 == 0
        && status & 0xe00f == 1 << slot
        && status & !(0x10000 | 3) == 0xfffe0ff0
}
pub fn owned_trap_site(
    thread: u32,
    creator: u32,
    first: bool,
    enabled: bool,
    instruction: u64,
    configured: u64,
) -> bool {
    thread == creator && first && enabled && configured != 0 && instruction == configured
}
pub fn trap_qualifiers(status: u64) -> String {
    format!(
        "raw_dr6=0x{status:016X} rtm_bit_set={} bld_bit_set={} transaction_context=unknown",
        if status & 0x10000 != 0 {
            "True"
        } else {
            "False"
        },
        if status & 0x800 != 0 { "True" } else { "False" }
    )
}
#[derive(Default)]
pub struct EventCleanup {
    unresolved: BTreeSet<usize>,
    failed: bool,
    overflowed: bool,
}
impl EventCleanup {
    pub fn unresolved(&self) -> usize {
        self.unresolved.len()
    }
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }
    pub fn close(
        &mut self,
        handle: &mut usize,
        close: impl FnOnce(usize) -> Result<()>,
    ) -> Result<()> {
        let value = *handle;
        if value == 0 || value == usize::MAX {
            *handle = 0;
            return Ok(());
        }
        if self.unresolved.contains(&value) {
            self.failed = true;
            *handle = 0;
            anyhow::bail!("uncertain event handle cannot be closed twice");
        }
        if self.unresolved.len() >= 260 {
            self.failed = true;
            self.overflowed = true;
            anyhow::bail!("callback event cleanup ownership exceeded its bound");
        }
        self.unresolved.insert(value);
        *handle = 0;
        match close(value) {
            Ok(()) => {
                self.unresolved.remove(&value);
                Ok(())
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
    pub fn require_clean(&self) -> Result<()> {
        ensure!(
            !self.failed && !self.overflowed && self.unresolved.is_empty(),
            "callback event cleanup remains unqualified"
        );
        Ok(())
    }
}
