//! Explicit application cancellation, distinct from retryable interrupted I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cancellation {
    Signal,
    Requested,
}
impl std::fmt::Display for Cancellation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Signal => "application cancellation: signal",
            Self::Requested => "application cancellation: requested",
        })
    }
}
impl std::error::Error for Cancellation {}

/// A recovery cancellation keeps the primary operation available for inspection.
#[derive(Debug)]
pub struct RetainedPrimary(pub anyhow::Error);
impl std::fmt::Display for RetainedPrimary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("primary operation failure retained")
    }
}

pub fn cancelled(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Cancellation>().is_some()
}
pub fn retain_cancellation(
    primary: Option<anyhow::Error>,
    cancellation: anyhow::Error,
) -> anyhow::Error {
    retain_cancellation_after(primary, cancellation, Vec::new())
}
pub(crate) fn retain_cancellation_after(
    primary: Option<anyhow::Error>,
    cancellation: anyhow::Error,
    mut secondary: Vec<anyhow::Error>,
) -> anyhow::Error {
    let reason = *cancellation
        .downcast_ref::<Cancellation>()
        .expect("retain_cancellation requires an explicit cancellation");
    secondary.push(cancellation);
    let retained = anyhow::Error::new(reason).context(RecoveryFailures(secondary));
    match primary {
        Some(primary) => retained.context(RetainedPrimary(primary)),
        None => retained,
    }
}

#[derive(Debug)]
pub struct RecoveryFailures(pub Vec<anyhow::Error>);
impl std::fmt::Display for RecoveryFailures {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("secondary recovery failures retained")
    }
}
pub fn retain_recovery(
    primary: Option<anyhow::Error>,
    secondary: Vec<anyhow::Error>,
) -> anyhow::Error {
    let cancellation = primary
        .as_ref()
        .and_then(|error| error.downcast_ref::<Cancellation>())
        .copied();
    let error = match cancellation {
        Some(reason) => anyhow::Error::new(reason),
        None => anyhow::anyhow!("recovery operation failed"),
    }
    .context(RecoveryFailures(secondary));
    match primary {
        Some(primary) => error.context(RetainedPrimary(primary)),
        None => error,
    }
}
