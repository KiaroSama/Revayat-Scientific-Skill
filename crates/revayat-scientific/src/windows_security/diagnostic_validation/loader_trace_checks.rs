//! Original LoaderTrace.CheckValidation: LoaderTrace.cs:234–272.
use crate::windows_security::activation::loader::{DebugStringBudget, accept_initial};
use anyhow::{Result, ensure};
use std::cell::Cell;
pub fn check_loader_trace_validation() -> Result<()> {
    let mut strings = DebugStringBudget::default();
    ensure!(
        strings.take(false)
            && !strings.take(false)
            && strings.take(true)
            && strings.take(true)
            && strings.take(true),
        "Python debug-string ceiling or fixed clone separation differs"
    );
    let mut charged = DebugStringBudget::default();
    for _ in 0..16 {
        charged.charge(4096)?;
    }
    ensure!(
        charged.requested() == 65536,
        "clone read budget boundary differs"
    );
    for invalid in [1, 4097, 0, usize::MAX] {
        ensure!(
            charged.charge(invalid).is_err() && charged.requested() == 65536,
            "clone over-budget request accepted or charge changed"
        );
    }
    let mut charged = DebugStringBudget::default();
    charged.charge(4096)?;
    charged.charge(2)?;
    ensure!(
        charged.requested() == 4098,
        "failed read requests were refunded"
    );
    let qualified = Cell::new(0);
    let complete = || {
        qualified.set(qualified.get() + 1);
        Ok(())
    };
    ensure!(
        accept_initial(11, 11, 0x80000003, true, false, complete)? && qualified.get() == 1,
        "initial breakpoint did not qualify completed observation"
    );
    for (thread, code, first, seen) in [
        (12, 0x80000003, true, false),
        (11, 0x80000004, true, false),
        (11, 0x80000003, false, false),
        (11, 0x80000003, true, true),
    ] {
        ensure!(
            !accept_initial(thread, 11, code, first, seen, complete)? && qualified.get() == 1,
            "foreign/repeated/unsupported breakpoint accepted"
        );
    }
    ensure!(
        accept_initial(11, 11, 0x80000003, true, false, || anyhow::bail!(
            "incomplete window"
        ))
        .is_err(),
        "initial breakpoint hid incomplete observation"
    );
    ensure!(
        accept_initial(11, 11, 0x80000003, true, false, || Ok(()))?,
        "ordinary trace lost initial breakpoint handling"
    );
    Ok(())
}
