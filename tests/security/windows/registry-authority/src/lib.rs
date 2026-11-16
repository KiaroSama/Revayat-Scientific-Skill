//! Authoritative Windows registry controls and portable wire validation.
#[cfg(windows)]
pub mod native;
pub mod oracle;
#[cfg(test)]
mod oracle_events;
#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod process;
pub mod protocol;
#[cfg(windows)]
pub mod registry;
#[cfg(windows)]
pub mod token;
