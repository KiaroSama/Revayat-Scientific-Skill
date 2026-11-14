//! Original/modified/restored activation observation with explicit restore-or-defer ownership.
use super::{
    Failures, dll_request,
    self_result::{self, SelfRole},
};
use anyhow::{Result, ensure};
pub const DENIED: i32 = 0xc0000022u32 as i32;
/// These callbacks retain the genuine intervention lease. Exactly one is invoked after begin;
/// callers must not make Drop silently restore a deferred or uncertain native operation.
pub struct Trial<'a> {
    pub restore: Box<dyn FnMut() -> Result<()> + 'a>,
    pub defer: Box<dyn FnMut() -> Result<()> + 'a>,
}
/// A parsed result does not prove producer identity or native process cleanup. The native
/// observation callback must finish its owned process/pipe lifetime before returning the wire.
pub fn execute_sweep<'a>(
    mut observe: impl FnMut(&str, i32) -> Result<String>,
    begin: impl FnOnce() -> Result<Trial<'a>>,
    mut emit: impl FnMut(&str) -> Result<()>,
    mut condition_line: impl FnMut(&str, &str) -> Result<String>,
    differential: impl FnOnce(&str, &str) -> Result<String>,
) -> Result<()> {
    let original = observe("original", DENIED)?;
    emit(&condition_line("original", &original)?)?;
    let mut trial = begin()?;
    let modified = (|| {
        let value = observe("modified", 0)?;
        emit(&condition_line("modified", &value)?)?;
        Ok(value)
    })();
    let modified = match modified {
        Ok(value) => {
            (trial.restore)()?;
            value
        }
        Err(primary) => {
            return match (trial.defer)() {
                Ok(()) => Err(primary),
                Err(recovery) => Err(Failures {
                    errors: vec![primary, recovery],
                }
                .into()),
            };
        }
    };
    let restored = observe("restored", DENIED)?;
    ensure!(
        original == restored,
        "fixed manual activation comparison contract failed"
    );
    emit(&condition_line("restored", &restored)?)?;
    emit(&differential(&original, &modified)?)
}
pub fn execute_manual<'a>(
    role: i32,
    observe: impl FnMut(&str, i32) -> Result<String>,
    begin: impl FnOnce() -> Result<Trial<'a>>,
    emit: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let role = SelfRole::try_from(role)?;
    ensure!(
        role != SelfRole::Original,
        "independent comparison requires a distinct fixed activation role"
    );
    execute_sweep(
        observe,
        begin,
        emit,
        |condition, value| self_result::condition(condition, Some(value), role),
        |original, modified| {
            Ok(format!(
                "{}_DIFFERENTIAL original_restored_equal=True result_changed={} {} target_admitted=False cause_claimed=False python_equivalence_claimed=False production_grant=False",
                role.label(),
                if original != modified {
                    "True"
                } else {
                    "False"
                },
                if role == SelfRole::Manual {
                    "manual_only=True"
                } else {
                    "explicit_id2_only=True"
                }
            ))
        },
    )
}
pub fn execute_dll<'a>(
    observe: impl FnMut(&str, i32) -> Result<String>,
    begin: impl FnOnce() -> Result<Trial<'a>>,
    emit: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    execute_sweep(
        observe,
        begin,
        emit,
        |condition, value| dll_request::condition(condition, Some(value)),
        |original, modified| {
            Ok(format!(
                "WINDOWS_DLL_RESOURCE_ACTIVATION_DIFFERENTIAL original_restored_equal=True result_changed={} dll_file_request_only=True target_admitted=False cause_claimed=False python_equivalence_claimed=False production_grant=False",
                if original != modified {
                    "True"
                } else {
                    "False"
                }
            ))
        },
    )
}
#[path = "sweep_validation.rs"]
mod validation;
pub use validation::check_manual_activation_validation;
