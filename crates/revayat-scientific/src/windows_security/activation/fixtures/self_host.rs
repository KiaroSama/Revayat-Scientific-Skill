//! Closed original/manual/explicit-ID2 own-module fixtures and positive-latch sequencing.
pub use crate::windows_security::activation::self_result::{
    SelfRole, complete_host, condition, require_host, result,
};
use anyhow::{Result, ensure};
use std::path::Path;
#[path = "self_host_checks.rs"]
mod checks;
#[path = "self_wire_checks.rs"]
mod wire_checks;
pub use checks::{check_entry_host_validation, check_self_validation};
pub fn require_role(preflight: bool, others: &[bool]) -> Result<()> {
    ensure!(
        preflight && others.len() == 9 && !others.contains(&true),
        "self activation is a separate fixed undebugged trusted diagnostic"
    );
    Ok(())
}
pub fn require_positive(positive: bool) -> Result<()> {
    ensure!(positive, "fixed self activation contract failed");
    Ok(())
}
pub fn stem(role: i32) -> Result<&'static str> {
    Ok(SelfRole::try_from(role)?.stem())
}
pub fn label(role: i32) -> Result<&'static str> {
    Ok(SelfRole::try_from(role)?.label())
}
pub fn image_name(role: i32) -> Result<String> {
    Ok(SelfRole::try_from(role)?.image_name())
}
pub fn source_bytes(text: &str, role: i32) -> Result<String> {
    super::source::self_source(text, SelfRole::try_from(role)?)
}
pub fn result_for_role(
    exit: u32,
    text: Option<&str>,
    errors: Option<&str>,
    role: i32,
    emit: impl FnMut(&str) -> Result<()>,
) -> Result<String> {
    result(exit, text, errors, SelfRole::try_from(role)?, emit)
}
pub fn complete_entry_host(
    run: impl FnOnce(&mut dyn FnMut(&str) -> Result<()>) -> Result<String>,
    close: impl FnOnce() -> Result<()>,
    mut emit: impl FnMut(&str) -> Result<()>,
    accept: impl FnOnce() -> Result<()>,
    resource: bool,
) -> Result<()> {
    let metadata = std::cell::RefCell::new(None);
    complete_host(
        SelfRole::ExplicitId2,
        || {
            run(&mut |line| {
                ensure!(
                    metadata.borrow().is_none(),
                    "fixed entry metadata was retained twice"
                );
                *metadata.borrow_mut() = Some(line.to_owned());
                Ok(())
            })
        },
        close,
        || {
            let retained = metadata.borrow();
            let metadata = retained
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("fixed entry metadata was not retained"))?;
            emit(metadata)?;
            emit(if resource {
                "WINDOWS_AUTOMATIC_RESOURCE_HOST positive=True cleanup_complete=True cause_claimed=False"
            } else {
                "WINDOWS_EXPLICIT_ENTRY_HOST positive=True cleanup_complete=True cause_claimed=False"
            })?;
            accept()
        },
    )
}
pub fn check_rejected_entry(observation: impl FnOnce() -> Result<()>) -> Result<()> {
    use std::cell::Cell;
    let latched = Cell::new(false);
    let closed = Cell::new(false);
    let result = complete_entry_host(
        |retain| {
            observation()?;
            retain("fixed-metadata")?;
            Ok(SelfRole::ExplicitId2.success())
        },
        || {
            closed.set(true);
            Ok(())
        },
        |_| Ok(()),
        || {
            latched.set(true);
            Ok(())
        },
        false,
    );
    ensure!(
        result.is_err() && closed.get() && !latched.get(),
        "rejected entry observation latched positive or skipped close"
    );
    Ok(())
}
