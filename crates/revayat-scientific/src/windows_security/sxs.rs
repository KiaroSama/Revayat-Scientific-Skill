//! Fixed SxS evidence contracts. Parsed text never proves producer identity or target admission.
use anyhow::{Result, ensure};
use std::fmt;

#[path = "sxs/event_collector.rs"]
pub mod event_collector;
#[path = "sxs/events.rs"]
mod events;
pub use event_collector::check_startup_events_validation;
#[cfg(windows)]
#[path = "sxs/native_events.rs"]
pub mod native_events;
#[path = "sxs/ordinal.rs"]
mod ordinal;
pub use ordinal::ordinal_path_equal;
#[cfg(windows)]
#[path = "sxs/native.rs"]
pub mod native;
#[cfg(windows)]
#[path = "sxs/native_identity.rs"]
mod native_identity;
#[cfg(windows)]
pub(crate) use native_identity::{current_user_sid, observe_startup_token, with_authority};
#[cfg(windows)]
#[path = "sxs/native_session.rs"]
mod native_session;
#[cfg(windows)]
pub(crate) use native_session::recover_owned_session;
#[cfg(windows)]
#[path = "sxs/native_storage.rs"]
mod native_storage;
#[path = "sxs/recovery.rs"]
mod recovery;
#[path = "sxs/session.rs"]
mod session;
#[path = "sxs/storage.rs"]
pub mod storage;
pub use recovery::{bound_text, decode_bound, intent_text, intent_volume, stop_owned};
#[path = "sxs/text.rs"]
mod text;
pub use events::classify_event;
pub use session::{
    SESSION_CAPACITY, SESSION_NAME, SessionSnapshot, require_enumeration, select_session,
};
pub use text::{
    EvidenceRead, LengthPhase, check_evidence_validation, check_reporting_validation,
    check_success_validation, decode_lines, failure_evidence, known_dependency, read_owned,
    require_length, success_evidence,
};

/// The raw cause remains private and is deliberately not an Error::source or Debug field.
pub struct PrivateFailure {
    stage: std::borrow::Cow<'static, str>,
    original: anyhow::Error,
}
impl PrivateFailure {
    pub fn stage(&self) -> &str {
        &self.stage
    }
    pub fn original(&self) -> &anyhow::Error {
        &self.original
    }
}
impl fmt::Display for PrivateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "fixed SxS trace failed stage={} raw_error_withheld=True",
            self.stage
        )
    }
}
impl fmt::Debug for PrivateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}
impl std::error::Error for PrivateFailure {}
pub(crate) fn safe(error: anyhow::Error, stage: &'static str) -> anyhow::Error {
    safe_stage(error, stage)
}
pub(crate) fn safe_stage(
    error: anyhow::Error,
    stage: impl Into<std::borrow::Cow<'static, str>>,
) -> anyhow::Error {
    if error.is::<PrivateFailure>() {
        error
    } else {
        PrivateFailure {
            stage: stage.into(),
            original: error,
        }
        .into()
    }
}
fn combine(first: anyhow::Error, second: anyhow::Error) -> anyhow::Error {
    super::activation::Failures {
        errors: vec![first, second],
    }
    .into()
}
/// The finite production ordering seam: a failed operation still stops and parses failed-consumer
/// evidence, but failed control qualification or failed stop forbids successful-consumer parsing.
pub fn execute_capture(
    operation: impl FnOnce() -> Result<()>,
    control: impl FnOnce() -> Result<()>,
    stop: impl FnOnce() -> Result<()>,
    parse: impl FnOnce(bool) -> Result<()>,
) -> Result<()> {
    let mut primary = operation().err();
    let completed = primary.is_none();
    let qualified = if completed {
        match control() {
            Ok(()) => true,
            Err(error) => {
                primary = Some(safe(error, "collector-control"));
                false
            }
        }
    } else {
        false
    };
    let stopped = match stop() {
        Ok(()) => true,
        Err(error) => {
            let error = safe(error, "stop");
            primary = Some(match primary {
                Some(first) => combine(first, error),
                None => error,
            });
            false
        }
    };
    if stopped
        && (!completed || qualified)
        && let Err(error) = parse(qualified)
    {
        let error = safe(error, "parse");
        primary = Some(match primary {
            Some(first) => combine(first, error),
            None => error,
        });
    }
    match primary {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
#[derive(Default)]
pub struct StorageLifecycle {
    attempted: bool,
    ready: bool,
    seal_attempted: bool,
    sealed: bool,
    entered: bool,
}
impl StorageLifecycle {
    pub fn prepare(&mut self, action: impl FnOnce() -> Result<()>) -> Result<()> {
        ensure!(!self.attempted, "SxS storage preparation already attempted");
        self.attempted = true;
        action()?;
        self.ready = true;
        Ok(())
    }
    pub fn seal(&mut self, action: impl FnOnce() -> Result<()>) -> Result<()> {
        ensure!(
            self.ready && !self.seal_attempted && !self.entered,
            "SxS storage seal is unavailable"
        );
        self.seal_attempted = true;
        action()?;
        self.sealed = true;
        Ok(())
    }
    pub fn enter(&mut self, action: impl FnOnce() -> Result<()>) -> Result<()> {
        ensure!(
            self.ready && self.sealed && !self.entered,
            "SxS storage entry is unavailable"
        );
        self.entered = true;
        action()
    }
}

#[path = "sxs/canary.rs"]
pub mod canary;
#[path = "sxs/capture.rs"]
pub mod capture;
#[path = "sxs/seed.rs"]
pub mod seed;
#[path = "sxs/storage_policy.rs"]
pub mod storage_policy;
pub use capture::check_capture_validation;

#[cfg(windows)]
#[path = "sxs/native_file_abi.rs"]
pub(crate) mod native_file_abi;
