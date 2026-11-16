//! Original PythonLoaderComparison.CheckValidation/CheckOrder assertion products.
use super::*;
use std::{
    cell::{Cell, RefCell},
    fmt,
};
#[path = "loader_comparison_failures.rs"]
mod failures;
#[derive(Debug)]
struct Sentinel;
impl fmt::Display for Sentinel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fixed loader validation failure")
    }
}
impl std::error::Error for Sentinel {}
fn fault() -> (anyhow::Error, *const Sentinel) {
    let error = anyhow::Error::new(Sentinel);
    let address = error.downcast_ref::<Sentinel>().unwrap() as *const _;
    (error, address)
}
fn identity(error: &anyhow::Error, address: *const Sentinel) -> bool {
    error
        .downcast_ref::<Sentinel>()
        .is_some_and(|value| std::ptr::eq(value, address))
}
pub fn check_validation() -> Result<()> {
    for (text, expected) in [
        ("00000000", 0),
        ("FFFFFFFF", u32::MAX),
        ("C0000022", 0xC0000022),
        ("C0150002", 0xC0150002),
    ] {
        ensure!(require_exit(Some(&format!("LOADER_TRACE_EXIT=0x{text}")))? == expected);
    }
    for invalid in [
        None,
        Some(""),
        Some("LOADER_TRACE_EXIT=0xC0000022\n"),
        Some(" LOADER_TRACE_EXIT=0xC0000022"),
        Some("LOADER_TRACE_EXIT=0xc0000022"),
        Some("LOADER_TRACE_EXIT=0xC000022"),
        Some("LOADER_TRACE_EXIT=0x0C0000022"),
        Some("LOADER_TRACE_EXIT=0xG0000022"),
        Some("LOADER_TRACE_EXIT=0xC0000022private-sentinel"),
    ] {
        let failure = require_exit(invalid).unwrap_err();
        ensure!(!failure.to_string().contains("private-sentinel"));
    }
    ensure!(
        begin(Condition::Original)
            == "WINDOWS_PYTHON_LOADER_CONDITION condition=original phase=begin clone_only=True target_admitted=False cause_claimed=False"
    );
    ensure!(
        complete(Condition::Modified, 0xC0150002)
            == "WINDOWS_PYTHON_LOADER_CONDITION condition=modified phase=complete exit=0xC0150002 process_job_handle_cleanup=True ifeo_absent=True clone_only=True target_admitted=False cause_claimed=False"
    );
    ensure!(
        Condition::Original.expected() == 0xC0000022u32 as i32
            && Condition::Modified.expected() == 0
            && Condition::Restored.expected() == 0xC0000022u32 as i32
    );
    for invalid in [-1, 3, i32::MAX] {
        let effects = Cell::new(0);
        let changed = || {
            effects.set(effects.get() + 1);
            Ok(())
        };
        let result = observe_leg(
            invalid,
            changed,
            changed,
            |_| {
                changed()?;
                Ok(String::new())
            },
            |_| changed(),
            changed,
            |_| changed(),
        );
        ensure!(result.is_err() && effects.get() == 0);
    }
    check_order()?;
    failures::check_legs()?;
    failures::check_sweep()
}
fn check_order() -> Result<()> {
    for changed in [false, true] {
        let order = RefCell::new(Vec::<String>::new());
        let launches = Cell::new(0);
        let completions = Cell::new(0);
        execute(
            |condition| {
                let name = condition.label();
                let index = match condition {
                    Condition::Original => 0,
                    Condition::Modified => 1,
                    Condition::Restored => 2,
                };
                observe_leg(
                    index,
                    || {
                        order.borrow_mut().push(format!("{name}:hold"));
                        Ok(())
                    },
                    || {
                        order.borrow_mut().push(format!("{name}:enable"));
                        Ok(())
                    },
                    |selected| {
                        ensure!(selected == condition);
                        launches.set(launches.get() + 1);
                        order.borrow_mut().push(format!("{name}:trace-clean"));
                        Ok(if selected == Condition::Modified && changed {
                            "LOADER_TRACE_EXIT=0xC0150002"
                        } else {
                            "LOADER_TRACE_EXIT=0xC0000022"
                        }
                        .into())
                    },
                    |_| {
                        order.borrow_mut().push(format!("{name}:ifeo-clean"));
                        order.borrow_mut().push(format!("{name}:release"));
                        Ok(())
                    },
                    || {
                        order.borrow_mut().push(format!("{name}:absent"));
                        Ok(())
                    },
                    |line| {
                        if line == begin(condition) {
                            order.borrow_mut().push(format!("{name}:begin"));
                        } else {
                            ensure!(
                                line == complete(
                                    condition,
                                    if condition == Condition::Modified && changed {
                                        0xC0150002
                                    } else {
                                        0xC0000022
                                    }
                                )
                            );
                            order.borrow_mut().push(format!("{name}:complete"));
                            completions.set(completions.get() + 1);
                        }
                        Ok(())
                    },
                )
            },
            || {
                order.borrow_mut().push("policy-begin".into());
                Ok(Trial {
                    restore: Box::new(|| {
                        order.borrow_mut().push("policy-restore".into());
                        Ok(())
                    }),
                    defer: Box::new(|| {
                        order.borrow_mut().push("policy-defer".into());
                        Ok(())
                    }),
                })
            },
        )?;
        ensure!(launches.get() == 3 && launches.get() - 1 == 2 && completions.get() == 3);
        ensure!(
            order.borrow().join(",")
                == "original:hold,original:enable,original:begin,original:trace-clean,original:ifeo-clean,original:release,original:absent,original:complete,policy-begin,modified:hold,modified:enable,modified:begin,modified:trace-clean,modified:ifeo-clean,modified:release,modified:absent,modified:complete,policy-restore,restored:hold,restored:enable,restored:begin,restored:trace-clean,restored:ifeo-clean,restored:release,restored:absent,restored:complete"
        );
    }
    Ok(())
}
