//! Original StartupImageAccess read-section contracts. No section is mapped here.
use super::*;
use crate::windows_security::scratch::{self, OperationResult, SharedError};
use std::{
    cell::{Cell, RefCell},
    mem::size_of,
    sync::Arc,
};

pub const RUNTIME_FILES: [&str; 3] = ["python.exe", "python311.dll", "vcruntime140.dll"];
pub const SYSTEM_FILES: [&str; 8] = [
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "ucrtbase.dll",
    "advapi32.dll",
    "version.dll",
    "ws2_32.dll",
    "bcrypt.dll",
];
#[repr(C)]
pub struct ImageUnicode {
    pub length: u16,
    pub maximum: u16,
    pub buffer: usize,
}
#[repr(C)]
pub struct ImageAttributes {
    pub length: u32,
    pub root: usize,
    pub name: usize,
    pub attributes: u32,
    pub descriptor: usize,
    pub qos: usize,
}
pub fn require_section_result(status: i32, handle: usize) -> Result<()> {
    ensure!(
        handle != usize::MAX && (status >= 0) == (handle != 0),
        "native section status/handle are inconsistent"
    );
    Ok(())
}
pub fn section_status(status: Option<i32>) -> String {
    status.map_or_else(
        || "not-attempted".into(),
        |status| format!("0x{:08X}", status as u32),
    )
}
/// A finally-block cleanup: attempt every action; successful cleanup leaves the caller's primary intact.
pub fn release_image<'a>(
    primary: Option<SharedError>,
    actions: Vec<Box<dyn FnMut() -> OperationResult<()> + 'a>>,
) -> OperationResult<()> {
    let mut errors = Vec::new();
    for mut action in actions {
        scratch::attempt(&mut errors, action.as_mut());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        scratch::finish(primary.map_or(Ok(()), Err), errors)
    }
}
pub fn report_image(
    lines: &[String],
    newline: &str,
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    ensure!(
        matches!(newline, "\n" | "\r\n") && lines.len() <= 41,
        "image differential line bound exceeded"
    );
    let mut bytes = 0usize;
    for line in lines {
        bytes = bytes
            .checked_add(line.len())
            .and_then(|n| n.checked_add(newline.len()))
            .ok_or_else(|| anyhow::anyhow!("image differential output length overflow"))?;
    }
    ensure!(bytes <= 12288, "image differential output bound exceeded");
    for line in lines {
        emit(line)?;
    }
    Ok(())
}
#[derive(Debug)]
struct Identity(SharedError);
impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fixed image validation error")
    }
}
impl std::error::Error for Identity {}
fn identified(error: &SharedError) -> anyhow::Error {
    anyhow::Error::new(Identity(error.clone()))
}
fn same(error: &anyhow::Error, expected: &SharedError) -> bool {
    error
        .downcast_ref::<Identity>()
        .is_some_and(|value| Arc::ptr_eq(&value.0, expected))
}
fn check_finalization() -> Result<()> {
    let operation = scratch::failure("fixed image operation");
    let first = scratch::failure("fixed section close");
    let second = scratch::failure("fixed file close");
    let reporting = scratch::failure("fixed image reporting");
    let order = RefCell::new(Vec::new());
    let error = release_image(
        Some(operation.clone()),
        vec![
            Box::new(|| {
                order.borrow_mut().push("section");
                Err(first.clone())
            }),
            Box::new(|| {
                order.borrow_mut().push("file");
                Err(second.clone())
            }),
        ],
    )
    .unwrap_err();
    let group = error
        .downcast_ref::<scratch::Failures>()
        .ok_or_else(|| anyhow::anyhow!("image releases lost aggregate failure"))?;
    ensure!(
        group.errors.len() == 3
            && Arc::ptr_eq(&group.errors[0], &operation)
            && Arc::ptr_eq(&group.errors[1], &first)
            && Arc::ptr_eq(&group.errors[2], &second)
            && *order.borrow() == ["section", "file"],
        "image releases lost ordered failure identity"
    );
    order.borrow_mut().clear();
    let error = activation::finalize_comparison(
        Some(identified(&operation)),
        true,
        || {
            order.borrow_mut().push("revert");
            Ok(())
        },
        || panic!("unexpected image finalization fail-fast"),
        vec![
            Box::new(|| {
                order.borrow_mut().push("close");
                Err(identified(&first))
            }),
            Box::new(|| {
                order.borrow_mut().push("held");
                Ok(())
            }),
        ],
        || {
            order.borrow_mut().push("report");
            Err(identified(&reporting))
        },
    )
    .unwrap_err();
    let group = error
        .downcast_ref::<activation::Failures>()
        .ok_or_else(|| anyhow::anyhow!("image finalization lost aggregate failure"))?;
    ensure!(
        group.errors.len() == 3
            && same(&group.errors[0], &operation)
            && same(&group.errors[1], &first)
            && same(&group.errors[2], &reporting)
            && *order.borrow() == ["revert", "close", "held", "report"],
        "image finalization lost ordered failure identity"
    );
    let emitted = Cell::new(0);
    let newline = "\r\n";
    report_image(&["x".repeat(12288 - newline.len())], newline, |_| {
        emitted.set(emitted.get() + 1);
        Ok(())
    })?;
    ensure!(
        emitted.get() == 1,
        "image output boundary was not exercised"
    );
    for lines in [
        vec!["x".repeat(12289 - newline.len())],
        vec![String::new(); 42],
    ] {
        ensure!(
            report_image(&lines, newline, |_| {
                emitted.set(emitted.get() + 1);
                Ok(())
            })
            .is_err()
                && emitted.get() == 1,
            "image output exceeded its bound or emitted before admission"
        );
    }
    Ok(())
}
pub fn check_startup_image_access_validation() -> Result<()> {
    check_finalization()?;
    ensure!(
        size_of::<usize>() == 8
            && size_of::<ImageUnicode>() == 16
            && size_of::<ImageAttributes>() == 48
            && RUNTIME_FILES.len() == 3
            && SYSTEM_FILES.len() == 8
            && section_status(Some(0xc0000022u32 as i32)) == "0xC0000022"
            && section_status(None) == "not-attempted",
        "fixed image differential ABI/format differs"
    );
    require_section_result(0, 1)?;
    require_section_result(0xc0000022u32 as i32, 0)?;
    for (status, handle) in [(0, 0), (0xc0000022u32 as i32, 1)] {
        ensure!(
            require_section_result(status, handle).is_err(),
            "inconsistent section status/handle was accepted"
        );
    }
    Ok(())
}
