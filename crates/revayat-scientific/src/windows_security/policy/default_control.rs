//! Shared default-security object contracts; native observations remain separate.
use super::*;
use crate::windows_security::activation::{Failures, finalize_checked};
use anyhow::Context;

#[path = "default_comparison.rs"]
pub mod comparison;
#[path = "default_validation.rs"]
mod validation;
pub use validation::{check_child_validation, check_control_validation};

#[derive(Debug)]
pub struct ContractFailure {
    pub component: &'static str,
    pub source: u32,
    pub status: Option<u32>,
}
impl std::fmt::Display for ContractFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "child default-DACL contract failed component={} source_check={}",
            self.component, self.source
        )?;
        if let Some(status) = self.status {
            write!(out, " native_status=0x{status:08X}")?;
        }
        Ok(())
    }
}
impl std::error::Error for ContractFailure {}
#[track_caller]
pub(super) fn need(value: bool, component: &'static str, status: Option<u32>) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(ContractFailure {
            component,
            source: std::panic::Location::caller().line(),
            status,
        }
        .into())
    }
}
fn valid(handle: usize) -> bool {
    handle != 0 && handle != usize::MAX
}

pub const EVENT_LEAF: &str = "DefaultDaclEvent";
#[repr(C)]
#[derive(Debug)]
pub struct EventAttributes {
    pub length: u32,
    pub root: usize,
    pub name: usize,
    pub flags: u32,
    pub descriptor: usize,
    pub qos: usize,
}
pub fn event_attributes(directory: usize, name: usize) -> Result<EventAttributes> {
    need(valid(directory) && name != 0, "control", None)?;
    Ok(EventAttributes {
        length: 48,
        root: directory,
        name,
        flags: 0,
        descriptor: 0,
        qos: 0,
    })
}
#[derive(Debug)]
pub struct PreparationFailure {
    pub phase: &'static str,
    pub error: anyhow::Error,
}
impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "child default-security preparation failed phase={}",
            self.phase
        )
    }
}
impl std::error::Error for PreparationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}
pub fn preparation_failure(phase: &'static str, error: anyhow::Error) -> PreparationFailure {
    PreparationFailure { phase, error }
}
/// A successful fresh open must have its own handle. Denial never owns an output.
pub fn opened(status: u32, opened: usize, created: usize, directory: usize) -> Result<bool> {
    need(valid(created) && created != directory, "control", None)?;
    need(
        if status == 0 {
            valid(opened) && opened != created && opened != directory
        } else {
            status == 0xc0000022 && opened == 0
        },
        "control",
        Some(status),
    )?;
    Ok(status == 0)
}
pub fn decode_path(buffer: &[u8], returned: u32) -> Result<String> {
    need(
        buffer.len() == 4096 && (1..=2048).contains(&returned),
        "control",
        None,
    )?;
    let units = buffer
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    need(end > 1 && end < units.len(), "control", None)?;
    String::from_utf16(&units[..end]).map_err(|_| {
        ContractFailure {
            component: "control",
            source: line!(),
            status: None,
        }
        .into()
    })
}
fn package(value: &str) -> bool {
    let Some(tail) = value.strip_prefix("S-1-15-2-") else {
        return false;
    };
    let parts = tail.split('-').collect::<Vec<_>>();
    !parts.is_empty()
        && parts.len() <= 14
        && parts.iter().all(|part| {
            part.parse::<u32>()
                .is_ok_and(|number| number.to_string() == *part)
        })
}
pub fn object_name(
    path: &str,
    returned: u32,
    suffix: &str,
    sid: &str,
    session: u32,
) -> Result<String> {
    need(
        (2..2048).contains(&path.encode_utf16().count())
            && (1..=2048).contains(&returned)
            && package(sid)
            && suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "control",
        None,
    )?;
    let relative = format!("AppContainerNamedObjects\\{sid}");
    let qualified = format!("Sessions\\{session}\\{relative}");
    need(
        path == relative || path == qualified || path == format!("\\{qualified}"),
        "control",
        None,
    )?;
    Ok(format!("\\{qualified}\\ScientificDefaultDacl-{suffix}"))
}
pub fn directory_acl(user: &[u8], sid: &[u8]) -> Result<Vec<u8>> {
    valid_sid(user)?;
    valid_sid(sid)?;
    need(user != sid, "control", None)?;
    encode_acl(2, &[allow_ace(user, 0x20006)?, allow_ace(sid, 0x20006)?])
}
pub fn directory_descriptor(user: &[u8], sid: &[u8]) -> Result<Vec<u8>> {
    let acl = directory_acl(user, sid)?;
    let mut bytes = vec![1, 0, 4, 0x90];
    for offset in [20, 20, 0, 20 + user.len() as u32] {
        bytes.extend(offset.to_le_bytes());
    }
    bytes.extend(user);
    bytes.extend(acl);
    need((20..=512).contains(&bytes.len()), "control", None)?;
    Ok(bytes)
}
pub fn require_directory_policy(bytes: &[u8], user: &[u8], sid: &[u8]) -> Result<()> {
    let descriptor = Descriptor::parse(bytes)?;
    need(
        descriptor.control & 0x9004 == 0x9004
            && descriptor.owner == Some(user)
            && descriptor.dacl == Some(directory_acl(user, sid)?.as_slice()),
        "control",
        None,
    )
}
pub fn require_object_policy(bytes: &[u8], user: &[u8], prepared: &[u8]) -> Result<()> {
    let descriptor = Descriptor::parse(bytes)?;
    need(
        descriptor.control & 0x8004 == 0x8004 && descriptor.owner == Some(user),
        "control",
        None,
    )?;
    let actual = descriptor.dacl.context("default object DACL absent")?;
    need(
        child_acl_equal(&child_event_policy(prepared)?, actual)?,
        "control",
        None,
    )
}
/// Every distinct valid object is closed once, even when an earlier close fails.
pub fn finish_objects(
    primary: Option<anyhow::Error>,
    handles: [usize; 3],
    mut close: impl FnMut(usize) -> Result<()>,
    actions: Vec<Box<dyn FnMut() -> Result<()> + '_>>,
) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    let mut errors = primary.into_iter().collect::<Vec<_>>();
    for handle in handles {
        if valid(handle)
            && seen.insert(handle)
            && let Err(error) = close(handle)
        {
            errors.push(error);
        }
    }
    for mut action in actions {
        if let Err(error) = action() {
            errors.push(error);
        }
    }
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.remove(0)),
        _ => Err(Failures { errors }.into()),
    }
}
pub fn finish_context(
    primary: Option<anyhow::Error>,
    impersonating: bool,
    revert: impl FnOnce() -> Result<bool>,
    fatal: impl FnOnce() -> Result<()>,
    actions: Vec<Box<dyn FnMut() -> Result<()> + '_>>,
) -> Result<()> {
    finalize_checked(primary, impersonating, revert, fatal, actions, || Ok(()))
}
