//! Fixed Python loader observations under original, temporary and restored policy.
//! Exit differences describe this owned clone and never establish target admission.
use super::{activation::Failures, policy::registry_comparison::Trial};
use anyhow::{Result, ensure};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    Original,
    Modified,
    Restored,
}
impl Condition {
    pub fn from_index(index: i32) -> Result<Self> {
        match index {
            0 => Ok(Self::Original),
            1 => Ok(Self::Modified),
            2 => Ok(Self::Restored),
            _ => anyhow::bail!("unsupported fixed Python loader condition"),
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Modified => "modified",
            Self::Restored => "restored",
        }
    }
    pub fn expected(self) -> i32 {
        if self == Self::Modified {
            0
        } else {
            0xC0000022u32 as i32
        }
    }
}
pub fn require_exit(text: Option<&str>) -> Result<u32> {
    let digits = text.and_then(|text| text.strip_prefix("LOADER_TRACE_EXIT=0x"));
    ensure!(
        digits.is_some_and(|value| value.len() == 8
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))),
        "fixed Python loader comparison contract failed"
    );
    Ok(u32::from_str_radix(digits.unwrap(), 16)?)
}
pub fn begin(condition: Condition) -> String {
    format!(
        "WINDOWS_PYTHON_LOADER_CONDITION condition={} phase=begin clone_only=True target_admitted=False cause_claimed=False",
        condition.label()
    )
}
pub fn complete(condition: Condition, exit: u32) -> String {
    format!(
        "WINDOWS_PYTHON_LOADER_CONDITION condition={} phase=complete exit=0x{exit:08X} process_job_handle_cleanup=True ifeo_absent=True clone_only=True target_admitted=False cause_claimed=False",
        condition.label()
    )
}
fn finish<T>(operation: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(Failures {
            errors: vec![primary, cleanup],
        }
        .into()),
    }
}
/// Cleanup owns the held fixture and always runs after successful acquisition.
/// Its error contains cleanup failures only; this owner retains the primary first.
pub fn observe_leg<H>(
    index: i32,
    hold: impl FnOnce() -> Result<H>,
    enable: impl FnOnce() -> Result<()>,
    observe: impl FnOnce(Condition) -> Result<String>,
    cleanup: impl FnOnce(H) -> Result<()>,
    require_clean: impl FnOnce() -> Result<()>,
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<u32> {
    let condition = Condition::from_index(index)?;
    let held = hold()?;
    let operation = (|| {
        enable()?;
        emit(&begin(condition))?;
        require_exit(Some(&observe(condition)?))
    })();
    let exit = finish(operation, cleanup(held))?;
    require_clean()?;
    emit(&complete(condition, exit))?;
    Ok(exit)
}
/// A failed modified observation always defers policy recovery, even if its
/// error happens to carry another experiment's qualified-cleanup marker.
pub fn execute<'a>(
    mut observe: impl FnMut(Condition) -> Result<u32>,
    begin_trial: impl FnOnce() -> Result<Trial<'a>>,
) -> Result<()> {
    observe(Condition::Original)?;
    let mut trial = begin_trial()?;
    let operation = observe(Condition::Modified);
    let cleanup = if operation.is_ok() {
        (trial.restore)()
    } else {
        (trial.defer)()
    };
    finish(operation, cleanup)?;
    observe(Condition::Restored)?;
    Ok(())
}

#[path = "loader_comparison_checks.rs"]
mod checks;
pub use checks::check_validation;
