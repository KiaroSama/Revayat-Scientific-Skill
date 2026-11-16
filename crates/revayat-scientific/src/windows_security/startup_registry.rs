//! Fixed read-open and child finalization seams shared by native startup observation and validation.
use super::activation::{Failures, finalize_checked};
use anyhow::{Result, ensure};
use std::{cell::RefCell, ffi::c_void, rc::Rc};
pub const KEY_PATH: &str =
    r"\Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide";
pub const ACCESS: u32 = 0x20019;
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum: u16,
    pub buffer: *const u16,
}
#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root: *mut c_void,
    pub name: *const UnicodeString,
    pub flags: u32,
    pub descriptor: *mut c_void,
    pub qos: *mut c_void,
}
pub fn fixed_name(text: *const u16) -> UnicodeString {
    UnicodeString {
        length: 140,
        maximum: 142,
        buffer: text,
    }
}
pub fn fixed_attributes(name: *const UnicodeString) -> ObjectAttributes {
    ObjectAttributes {
        length: 48,
        root: std::ptr::null_mut(),
        name,
        flags: 0x40,
        descriptor: std::ptr::null_mut(),
        qos: std::ptr::null_mut(),
    }
}
pub fn valid(handle: usize) -> bool {
    handle != 0 && handle != usize::MAX
}
pub fn outcome(label: &str, status: i32, key: usize) -> Result<String> {
    ensure!(
        matches!(label, "host" | "lpac") && if status >= 0 { valid(key) } else { key == 0 },
        "fixed registry-access contract is invalid"
    );
    Ok(format!(
        "WINDOWS_STARTUP_REGISTRY context={label} label=sxs-policy desired_access=0x00020019 status=0x{:08X} opened={} child_equivalence_claimed=False cause_claimed=False",
        status as u32,
        if status >= 0 { "True" } else { "False" }
    ))
}
pub fn closed(status: i32) -> Result<()> {
    ensure!(status >= 0, "close fixed registry read handle failed");
    Ok(())
}
fn aggregate(
    primary: Option<anyhow::Error>,
    mut errors: Vec<anyhow::Error>,
) -> Result<Option<anyhow::Error>> {
    if errors.is_empty() {
        return Ok(primary);
    }
    if let Some(primary) = primary {
        errors.insert(0, primary);
    }
    Err(Failures { errors }.into())
}
/// On clean finalization the caller still owns its primary, matching the original outer rethrow.
pub fn cleanup(
    primary: Option<anyhow::Error>,
    actions: Vec<Box<dyn FnMut() -> Result<()> + '_>>,
) -> Result<Option<anyhow::Error>> {
    aggregate(
        primary,
        actions
            .into_iter()
            .filter_map(|mut action| action().err())
            .collect(),
    )
}
pub fn finish<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    let (value, primary) = match result {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error)),
    };
    match aggregate(primary, cleanup.err().into_iter().collect())? {
        Some(error) => Err(error),
        None => Ok(value.unwrap()),
    }
}
pub fn observe_one(
    label: &str,
    record: impl FnOnce(String) -> Result<()>,
    deadline: &dyn Fn() -> Result<()>,
    qualify: &dyn Fn() -> Result<()>,
    open: impl FnOnce(&mut usize) -> Result<i32>,
    close: impl FnOnce(usize) -> Result<()>,
) -> Result<i32> {
    let mut key = 0;
    let result = (|| {
        deadline()?;
        qualify()?;
        let status = open(&mut key)?;
        qualify()?;
        deadline()?;
        record(outcome(label, status, key)?)?;
        ensure!(
            label != "host" || status >= 0,
            "host fixed registry positive control failed"
        );
        Ok(status)
    })();
    let owned = std::mem::replace(&mut key, 0);
    finish(result, if valid(owned) { close(owned) } else { Ok(()) })
}
/// Reversion/fail-fast ordering comes from the shared production finalizer; cleanup retains
/// the original registry AggregateException shape even for a single secondary error.
pub fn finalize_child<'a>(
    primary: Option<anyhow::Error>,
    impersonating: bool,
    revert: impl FnOnce() -> Result<bool>,
    fatal: impl FnOnce() -> Result<()>,
    close: Vec<Box<dyn FnMut() -> Result<()> + 'a>>,
    emit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let errors = Rc::new(RefCell::new(Vec::new()));
    let actions = close
        .into_iter()
        .map(|mut action| {
            let errors = errors.clone();
            Box::new(move || {
                if let Err(error) = action() {
                    errors.borrow_mut().push(error);
                }
                Ok(())
            }) as Box<dyn FnMut() -> Result<()> + 'a>
        })
        .collect();
    let emitted = errors.clone();
    finalize_checked(None, impersonating, revert, fatal, actions, move || {
        if let Err(error) = emit() {
            emitted.borrow_mut().push(error);
        }
        Ok(())
    })?;
    let failures = errors.borrow_mut().drain(..).collect();
    match aggregate(primary, failures)? {
        None => Ok(()),
        Some(primary) => Err(primary),
    }
}
#[path = "startup_registry_checks.rs"]
mod checks;
pub use checks::check_validation;
