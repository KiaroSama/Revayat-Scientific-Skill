//! Safe diagnostics shared by the two native creation boundaries.
use anyhow::Result;
use std::fmt;

#[derive(Debug)]
pub(super) struct CreationFailure {
    pub(super) operation: &'static str,
    pub(super) code: Option<u32>,
}

impl fmt::Display for CreationFailure {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(code) => write!(
                output,
                "native authority creation failed operation={} winerror={code} winerror_hex={code:08X}",
                self.operation
            ),
            None => write!(
                output,
                "native authority creation returned invalid handles operation={}",
                self.operation
            ),
        }
    }
}

impl std::error::Error for CreationFailure {}

pub(super) fn creation_result(
    success: i32,
    valid_outputs: bool,
    operation: &'static str,
    last_error: impl FnOnce() -> u32,
) -> Result<()> {
    let code = if success == 0 {
        Some(last_error())
    } else {
        None
    };
    if code.is_some() || !valid_outputs {
        return Err(CreationFailure { operation, code }.into());
    }
    Ok(())
}

pub(super) fn retain_cleanup<T>(result: Result<T>, failures: usize) -> Result<T> {
    if failures == 0 {
        return result;
    }
    match result {
        Err(primary) => {
            let cleanup = format!("authority cleanup also failed in {failures} owned operations");
            // Only this fixed operation/code type may enter the outer diagnostic.
            let context = match primary.downcast_ref::<CreationFailure>() {
                Some(creation) => format!("{creation}; {cleanup}"),
                None => cleanup,
            };
            Err(primary.context(context))
        }
        Ok(_) => anyhow::bail!("authority cleanup failed in {failures} owned operations"),
    }
}
