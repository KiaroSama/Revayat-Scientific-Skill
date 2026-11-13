//! Original SandboxCompletion ordering, bounded receipt retention, and exact cleanup qualification.
use super::wire;
use crate::windows_security::{
    activation::{Failures, dispatch},
    scratch::cleanup::QualifiedModuleCallbackFailure,
};
use anyhow::{Result, ensure};
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, Default)]
pub struct Flags {
    pub authority: bool,
    pub trace: bool,
    pub observed: bool,
    pub callback: bool,
    pub undebugged: bool,
    pub started: bool,
    pub signaled: bool,
}
pub type ReceiptRetainer<'a> = Option<&'a mut dyn FnMut(&[u8], bool)>;
pub trait CompletionIo {
    fn terminate(&mut self) -> Result<()>;
    fn reap(&mut self) -> Result<()>;
    fn confirm_destroyed(&mut self) -> Option<Result<()>>;
    fn query_exit(&mut self) -> Result<Option<u32>>;
    fn close_output(&mut self) -> Result<()>;
    fn close_error(&mut self, retain: ReceiptRetainer<'_>) -> Result<()>;
    fn release_count(&self) -> usize;
    fn release(&mut self, index: usize) -> Result<()>;
    fn metadata(&mut self) -> Result<String>;
    fn emit(&mut self, line: &str) -> Result<()>;
}
/// An ordinary completion has no replacement error in the legacy finally block.
/// Rust must also return its still-owned primary to the outer operation instead of dropping it.
pub struct Completion {
    pub primary: Option<anyhow::Error>,
    pub failure: Option<anyhow::Error>,
    pub reaped: bool,
    pub destroyed: bool,
}
impl Completion {
    pub fn cleanup_qualified(&self) -> bool {
        self.failure.as_ref().is_none_or(|error| {
            error.is::<dispatch::QualifiedFailure>()
                || error.is::<QualifiedModuleCallbackFailure<anyhow::Error>>()
        })
    }
    pub fn into_error(self) -> Option<anyhow::Error> {
        self.failure.or(self.primary)
    }
}
pub fn actual_exit(
    started: bool,
    signal: impl FnOnce() -> Result<u32>,
    query: impl FnOnce() -> Result<u32>,
) -> Result<Option<u32>> {
    if !started {
        return Ok(None);
    }
    let observed = signal()?;
    if observed == 0x102 {
        return Ok(None);
    }
    ensure!(
        observed == 0,
        "authority failure process signal is unqualified"
    );
    query().map(Some)
}
pub fn finish_undebugged(
    primary: Option<anyhow::Error>,
    cleanup: Vec<anyhow::Error>,
    started: bool,
    signaled: bool,
    reaped: bool,
) -> Option<anyhow::Error> {
    dispatch::finish_trace(
        primary,
        cleanup,
        started,
        signaled && reaped,
        || Ok(String::new()),
        |_| Ok(()),
    )
    .err()
}
/// Keep the ordinary primary in its caller-owned slot. Qualification cannot absorb
/// cleanup errors, and takes the original only after a completed callback destruction.
pub fn completion_failure(
    primary: &mut Option<anyhow::Error>,
    cleanup: Vec<anyhow::Error>,
    callback: bool,
    destroyed: bool,
) -> Option<anyhow::Error> {
    if !cleanup.is_empty() {
        let mut errors = primary.take().into_iter().collect::<Vec<_>>();
        errors.extend(cleanup);
        Some(Failures { errors }.into())
    } else if callback && destroyed {
        primary
            .take()
            .map(|original| QualifiedModuleCallbackFailure { original }.into())
    } else {
        None
    }
}
fn attempt(failures: &mut Vec<anyhow::Error>, operation: Result<()>) -> bool {
    match operation {
        Ok(()) => true,
        Err(error) => {
            failures.push(error);
            false
        }
    }
}
fn zero(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: the slice is uniquely borrowed and initialized; the write keeps
        // receipt retirement observable even when its allocation is immediately dropped.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}
pub fn complete_run(
    mut primary: Option<anyhow::Error>,
    flags: Flags,
    io: &mut impl CompletionIo,
) -> Completion {
    let mut failures = Vec::new();
    attempt(&mut failures, io.terminate());
    let reaped = attempt(&mut failures, io.reap());
    let mut destroyed = false;
    if reaped && let Some(result) = io.confirm_destroyed() {
        destroyed = attempt(&mut failures, result);
    }
    let mut exit = None;
    if flags.authority && primary.is_some() {
        match io.query_exit() {
            Ok(value) => exit = value,
            Err(error) => failures.push(error),
        }
    }
    attempt(&mut failures, io.close_output());
    let mut receipt: Option<(Vec<u8>, bool)> = None;
    let mut retain = |bytes: &[u8], truncated| {
        if wire::from_prefix(bytes, truncated).is_none() {
            return;
        }
        if let Some((old, _)) = receipt.as_mut() {
            zero(old);
        }
        receipt = Some((bytes.into(), truncated));
    };
    let retain: ReceiptRetainer<'_> = if flags.authority && primary.is_some() {
        Some(&mut retain)
    } else {
        None
    };
    attempt(&mut failures, io.close_error(retain));
    if let Some((mut bytes, truncated)) = receipt {
        if !primary
            .as_ref()
            .is_some_and(|error| error.is::<wire::ReceiptFailure>())
        {
            primary = wire::preserve(primary, exit, &bytes, truncated);
        }
        zero(&mut bytes);
    }
    for index in 0..io.release_count() {
        attempt(&mut failures, io.release(index));
    }
    let failure = if flags.trace {
        let io = RefCell::new(io);
        dispatch::finish_trace(
            primary.take(),
            failures,
            flags.observed,
            destroyed,
            || io.borrow_mut().metadata(),
            |line| io.borrow_mut().emit(line),
        )
        .err()
    } else if flags.undebugged {
        finish_undebugged(
            primary.take(),
            failures,
            flags.started,
            flags.signaled,
            reaped,
        )
    } else {
        completion_failure(&mut primary, failures, flags.callback, destroyed)
    };
    let failure = if flags.authority {
        failure.map(wire::sanitize)
    } else {
        failure
    };
    Completion {
        primary,
        failure,
        reaped,
        destroyed,
    }
}
/// Actual operation callers retain the value only after completion, and never lose an ordinary primary.
pub fn complete_operation<T>(
    operation: Result<T>,
    flags: Flags,
    io: &mut impl CompletionIo,
) -> Result<T> {
    let (value, primary) = match operation {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error)),
    };
    if let Some(error) = complete_run(primary, flags, io).into_error() {
        return Err(error);
    }
    value.ok_or_else(|| anyhow::anyhow!("Windows operation lost its original failure"))
}

pub use crate::windows_security::activation::capture::{
    StrictCaptureIo, check_strict_cleanup as check_capture_validation, dispose_strict,
};
pub fn complete_policies(
    primary: Option<anyhow::Error>,
    mut clean: bool,
    actions: &mut [&mut dyn FnMut(bool) -> Result<()>],
) -> Result<()> {
    let mut errors = primary.into_iter().collect::<Vec<_>>();
    let original = errors.len();
    for action in actions {
        if let Err(error) = action(clean) {
            clean = false;
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else if original == 1 && errors.len() == 1 {
        Err(errors.remove(0))
    } else {
        Err(Failures { errors }.into())
    }
}

#[path = "registry_completion_checks.rs"]
mod checks;
pub use checks::{check_callback_completion, check_validation};
