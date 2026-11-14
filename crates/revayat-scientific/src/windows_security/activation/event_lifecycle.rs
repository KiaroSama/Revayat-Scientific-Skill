//! Source-derived debug-event finalization and finite destruction qualification.
//! The callbacks belong to an actual process/event owner; these seams create no observation.
use super::activation_event;
use crate::windows_security::scratch::{OperationResult, SharedError};
use anyhow::{Result, ensure};
use std::{cell::RefCell, error::Error, fmt};
#[path = "event_lifecycle_checks.rs"]
mod checks;
pub use checks::{check_activation_destruction_validation, check_activation_event_validation};

#[derive(Default)]
pub struct ResourceContinuation {
    failure: Option<SharedError>,
}
impl ResourceContinuation {
    /// Retain the first uncertain continuation, while propagating each actual
    /// callback failure by identity. A later successful retry never qualifies it.
    pub fn run(
        &mut self,
        continuation: impl FnOnce() -> OperationResult<()>,
    ) -> OperationResult<()> {
        let result = continuation();
        if let Err(error) = &result
            && self.failure.is_none()
        {
            self.failure = Some(error.clone());
        }
        result
    }
    pub fn require_clean(&self) -> Result<()> {
        if let Some(original) = &self.failure {
            return Err(UncertainContinuation {
                original: original.clone(),
            }
            .into());
        }
        Ok(())
    }
}
pub struct UncertainContinuation {
    pub original: SharedError,
}
impl fmt::Display for UncertainContinuation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("resource continuation remains unqualified")
    }
}
impl fmt::Debug for UncertainContinuation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Error for UncertainContinuation {}

pub fn finalize_resource_cleanup<'a>(
    invalidate: impl FnOnce() -> Result<()>,
    restore: impl FnMut() -> Result<()>,
    exit: impl FnOnce() -> Result<()>,
    process_exit: bool,
    releases: Vec<Box<dyn FnMut() -> Result<()> + 'a>>,
    continuation: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let restore = RefCell::new(restore);
    activation_event(
        || {
            invalidate()?;
            if process_exit {
                exit()?;
            }
            (restore.borrow_mut())()
        },
        || (restore.borrow_mut())(),
        releases,
        continuation,
    )
}
pub fn remaining_activation_cleanup(elapsed: i64) -> Result<u32> {
    ensure!(elapsed >= 0, "activation cleanup clock is invalid");
    Ok(if elapsed >= 5000 {
        0
    } else {
        (5000 - elapsed) as u32
    })
}
#[derive(Clone, Copy, Debug)]
pub struct WaitOutcome {
    pub result: u32,
    pub error: u32,
}
pub fn confirm_activation_destruction(
    exit_received: bool,
    event_pending: bool,
    handle_present: bool,
    elapsed: i64,
    wait: impl FnOnce(u32) -> Result<WaitOutcome>,
    destroyed: impl FnOnce() -> Result<()>,
) -> Result<()> {
    ensure!(
        exit_received && !event_pending && handle_present,
        "activation destruction lacks continued EXIT or retained handle"
    );
    let outcome = wait(remaining_activation_cleanup(elapsed)?)?;
    ensure!(
        outcome.result == 0,
        "activation destruction wait did not signal wait_result=0x{:08X} native_error={}",
        outcome.result,
        if outcome.result == u32::MAX {
            outcome.error
        } else {
            0
        }
    );
    destroyed()
}
pub fn await_activation_job_zero(
    mut active: impl FnMut() -> Result<u32>,
    mut remaining: impl FnMut() -> Result<u32>,
    mut pause: impl FnMut(u32) -> Result<()>,
) -> Result<()> {
    while active()? != 0 {
        let remaining = remaining()?;
        ensure!(remaining != 0, "activation Job-zero deadline elapsed");
        pause(remaining.min(20))?;
    }
    Ok(())
}
pub fn require_callback_event_process(actual: u32, expected: u32) -> Result<()> {
    ensure!(
        actual == expected,
        "callback cleanup event is not from the fixed owned child"
    );
    Ok(())
}
pub fn drain_callback_events(
    mut has_exited: impl FnMut() -> bool,
    mut has_pending: impl FnMut() -> bool,
    mut remaining: impl FnMut() -> Result<u32>,
    mut receive: impl FnMut(u32) -> Result<bool>,
    mut finish: impl FnMut() -> Result<()>,
) -> Result<()> {
    if has_pending() {
        finish()?;
    }
    let mut count = 0;
    while !has_exited() && remaining()? != 0 && count < 128 {
        ensure!(!has_pending(), "callback cleanup event was not continued");
        if !receive(remaining()?.min(100))? {
            continue;
        }
        count += 1;
        finish()?;
    }
    ensure!(
        has_exited() && !has_pending(),
        "owned callback EXIT drain exceeded finite cleanup ceiling"
    );
    Ok(())
}
/// Source ActivationEvent permits an absent continuation after failed CREATE.
pub fn activation_event_optional<'a>(
    operation: impl FnOnce() -> Result<()>,
    restore: impl FnMut() -> Result<()>,
    releases: Vec<Box<dyn FnMut() -> Result<()> + 'a>>,
    continuation: Option<Box<dyn FnOnce() -> Result<()> + 'a>>,
) -> Result<()> {
    activation_event(operation, restore, releases, || {
        continuation.map_or(Ok(()), |next| next())
    })
}
