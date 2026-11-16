//! Completed child diagnostics stay inspectable when independent cleanup/recovery fails.
use super::{CleanupFailure, CommandOutput, Result};
use std::fmt;
struct Retained(CommandOutput);
impl fmt::Display for Retained {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("completed command diagnostics retained after cleanup failure")
    }
}
impl fmt::Debug for Retained {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Drop for Retained {
    fn drop(&mut self) {
        self.0.stdout.fill(0);
        self.0.stderr.fill(0);
    }
}
/// Inspect bytes explicitly; neither error formatting nor this value certifies cleanup.
pub fn retained_command_output(error: &anyhow::Error) -> Option<&CommandOutput> {
    error.downcast_ref::<Retained>().map(|value| &value.0)
}
/// Retain the completed value separately from its failed cleanup; errors keep their typed cause.
pub fn with_command_cleanup(
    result: Result<CommandOutput>,
    cleanup: Result<()>,
) -> Result<CommandOutput> {
    match (result, cleanup) {
        (Ok(output), Err(cleanup)) => {
            Err(anyhow::Error::new(CleanupFailure(cleanup)).context(Retained(output)))
        }
        (result, cleanup) => super::with_cleanup(result, cleanup),
    }
}
