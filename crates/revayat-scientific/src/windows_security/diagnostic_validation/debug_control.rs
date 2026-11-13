use super::*;
use std::{cell::Cell, sync::Arc};

/// A failed termination request stays retryable; only native success consumes it.
pub fn request_termination<E>(
    requested: &mut bool,
    terminate: impl FnOnce() -> std::result::Result<(), E>,
) -> std::result::Result<(), E> {
    if !*requested {
        terminate()?;
        *requested = true;
    }
    Ok(())
}
pub fn debug_control_status(stage: &str, expected: &[u8], actual: &[u8]) -> Result<String> {
    ensure!(
        ["fixture", "baseline", "arm-readback", "restore-readback"].contains(&stage),
        "unsupported fixed debug-control stage"
    );
    Ok(format!(
        "stage={stage} dr6_expected=0x{:016X} dr6_actual=0x{:016X} dr7_expected=0x{:016X} dr7_actual=0x{:016X} classic_cause=0x{:016X} raw_debug_equal={} control_integer_unchanged={}",
        value(expected, 104)?,
        value(actual, 104)?,
        value(expected, 112)?,
        value(actual, 112)?,
        value(actual, 104)? & 0xe00f,
        boolean(activation::raw_debug_equal(expected, actual)?),
        boolean(activation::unchanged_control_integer(expected, actual)?)
    ))
}
/// Direct DebugControl.CheckValidation assertions; called dependencies are exposed separately.
pub fn check_debug_control_core_validation() -> Result<()> {
    let mut requested = false;
    let attempts = Cell::new(0);
    for _ in 0..2 {
        request_termination::<anyhow::Error>(&mut requested, || {
            attempts.set(attempts.get() + 1);
            Ok(())
        })?;
    }
    ensure!(
        requested && attempts.get() == 1,
        "fixed control repeated successful termination"
    );
    requested = false;
    attempts.set(0);
    let primary = Arc::new(std::io::Error::other("fixed termination failure"));
    let error = request_termination(&mut requested, || {
        attempts.set(attempts.get() + 1);
        Err(primary.clone())
    })
    .unwrap_err();
    ensure!(
        !requested && attempts.get() == 1 && Arc::ptr_eq(&primary, &error),
        "fixed control lost failed termination request"
    );
    request_termination::<anyhow::Error>(&mut requested, || {
        attempts.set(attempts.get() + 1);
        Ok(())
    })?;
    ensure!(
        requested && attempts.get() == 2,
        "fixed control did not retry termination failure"
    );
    let before = vec![0; activation::CONTEXT_SIZE];
    let mut after = before.clone();
    put(&mut after, 104, 0xfffe0ff1);
    put(&mut after, 112, 0x401);
    let metadata = debug_control_status("fixture", &before, &after)?;
    ensure!(
        metadata.contains("dr6_actual=0x00000000FFFE0FF1")
            && metadata.contains("raw_debug_equal=False")
            && activation::unchanged_control_integer(&before, &after)?
            && metadata.len() <= 512,
        "fixed debugger-control status differs"
    );
    put(&mut after, 152, 0x123456789abcdef0);
    ensure!(
        !activation::unchanged_control_integer(&before, &after)?
            && !debug_control_status("fixture", &before, &after)?.contains("123456789ABCDEF0"),
        "fixed debugger-control metadata disclosed context address"
    );
    Ok(())
}
