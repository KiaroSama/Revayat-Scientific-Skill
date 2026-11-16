//! Empty fixed artifacts share explicit length, flush and independent close ownership.
use crate::windows_security::activation::Failures;
use anyhow::{Result, ensure};
#[path = "seed_checks.rs"]
mod checks;
pub use checks::{check_canary_creation, check_validation};
fn finish<T>(operation: Result<T>, closing: Result<()>) -> Result<T> {
    match closing {
        Ok(()) => operation,
        Err(error) => {
            let mut errors = operation.err().into_iter().collect::<Vec<_>>();
            errors.push(error);
            Err(Failures { errors }.into())
        }
    }
}
pub fn create<H>(
    open: impl FnOnce() -> Result<H>,
    length: impl FnOnce(&mut H) -> Result<u64>,
    flush: impl FnOnce(&mut H) -> Result<()>,
    close: impl FnOnce(H) -> Result<()>,
) -> Result<()> {
    let mut held = open()?;
    let operation = (|| {
        ensure!(length(&mut held)? == 0, "fixed SxS seed is not empty");
        flush(&mut held)
    })();
    finish(operation, close(held))
}
pub fn read<H>(
    policy: impl FnOnce() -> Result<()>,
    open: impl FnOnce() -> Result<H>,
    length: impl FnOnce(&mut H) -> Result<u64>,
    close: impl FnOnce(H) -> Result<()>,
) -> Result<()> {
    policy()?;
    let mut held = open()?;
    let operation = (|| {
        ensure!(length(&mut held)? == 0, "fixed SxS seed is not empty");
        Ok(())
    })();
    finish(operation, close(held))
}
pub fn prepare_text(
    mut remaining: impl FnMut() -> Result<f64>,
    absent: impl FnOnce() -> Result<()>,
    create: impl FnOnce() -> Result<()>,
    readback: impl FnOnce() -> Result<()>,
) -> Result<()> {
    ensure!(remaining()? > 0.0, "fixed SxS seed deadline expired");
    absent()?;
    create()?;
    readback()?;
    ensure!(remaining()? > 0.0, "fixed SxS seed deadline expired");
    Ok(())
}
pub const CANARY: &[u8] = b"fixed SxS host control";
pub fn require_canary(bytes: &[u8]) -> Result<()> {
    ensure!(bytes == CANARY, "fixed SxS canary bytes differ");
    Ok(())
}
