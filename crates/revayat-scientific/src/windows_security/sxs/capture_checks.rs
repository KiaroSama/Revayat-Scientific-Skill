use super::super::{StorageLifecycle, canary, execute_capture, seed};
use super::*;
use std::{
    cell::{Cell, RefCell},
    sync::Arc,
};
#[path = "capture_parse_checks.rs"]
mod parse;
#[path = "capture_storage_checks.rs"]
mod storage;
#[derive(Clone, Debug)]
pub(super) struct Failure(pub Arc<()>);
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("private-capture-sentinel")
    }
}
impl std::error::Error for Failure {}
pub(super) fn error(id: &Arc<()>) -> anyhow::Error {
    Failure(id.clone()).into()
}
pub(super) fn same(error: &anyhow::Error, id: &Arc<()>) -> bool {
    error
        .downcast_ref::<Failure>()
        .is_some_and(|f| Arc::ptr_eq(&f.0, id))
}
pub(super) fn address(error: &anyhow::Error) -> usize {
    let value: &(dyn std::error::Error + Send + Sync) = error.as_ref();
    value as *const _ as *const () as usize
}
pub fn check_capture_validation() -> Result<()> {
    canary::check_validation()?;
    seed::check_canary_creation()?;
    seed::check_validation()?;
    lifecycle()?;
    parse::check()?;
    super::super::session::check_validation()?;
    super::super::check_evidence_validation()?;
    super::super::storage::check_validation()?;
    tool_completion()?;
    storage::acquisition()?;
    storage::failures()?;
    let operation = Arc::new(());
    let stop = Arc::new(());
    for mode in 0..4 {
        let order = RefCell::new(String::new());
        let result = execute_capture(
            || {
                order.borrow_mut().push('o');
                if mode > 0 {
                    return Err(error(&operation));
                }
                Ok(())
            },
            || Ok(()),
            || {
                order.borrow_mut().push('s');
                if mode == 2 {
                    return Err(error(&stop));
                }
                Ok(())
            },
            |_| {
                order.borrow_mut().push('p');
                if mode == 3 {
                    return Err(error(&stop));
                }
                Ok(())
            },
        );
        ensure!(
            *order.borrow() == if mode == 2 { "os" } else { "osp" },
            "capture operation/stop/parse order differs"
        );
        match mode {
            0 => result?,
            1 => ensure!(
                same(&result.unwrap_err(), &operation),
                "capture operation identity changed"
            ),
            _ => {
                let caught = result.unwrap_err();
                let errors = &caught.downcast_ref::<Failures>().unwrap().errors;
                ensure!(
                    same(&errors[0], &operation) && !format!("{caught:?}").contains("sentinel"),
                    "capture stop/parse retained cause exposed or replaced"
                );
            }
        }
    }
    Ok(())
}
fn lifecycle() -> Result<()> {
    let raw = Arc::new(());
    for phase in 0..3 {
        let caught = boundary(phase, || Err(error(&raw))).unwrap_err();
        let safe = caught.downcast_ref::<PrivateFailure>().unwrap();
        ensure!(
            same(safe.original(), &raw) && !format!("{safe:?}").contains("sentinel"),
            "storage boundary private original lost"
        );
    }
    for phase in [-1, 3, i32::MAX] {
        let calls = Cell::new(0);
        ensure!(
            boundary(phase, || {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .is_err()
                && calls.get() == 0,
            "unsupported storage boundary executed"
        );
    }
    let inputs = [
        Some("run"),
        Some("state"),
        Some("volume"),
        Some("python"),
        Some("package"),
    ];
    same_inputs(&inputs, &inputs)?;
    for field in 0..5 {
        let mut other = inputs;
        other[field] = Some("foreign");
        ensure!(
            same_inputs(&inputs, &other).is_err(),
            "capture input changed between prepare/seal/enter"
        );
    }
    for failure in -1..3 {
        let mut lifecycle = StorageLifecycle::default();
        let order = RefCell::new(String::new());
        let step = |phase: i32| -> Result<()> {
            order.borrow_mut().push(char::from(b'0' + phase as u8));
            if phase == failure {
                return Err(error(&raw));
            }
            Ok(())
        };
        let operation = lifecycle
            .prepare(|| step(0))
            .and_then(|()| lifecycle.seal(|| step(1)))
            .and_then(|()| lifecycle.enter(|| step(2)));
        ensure!(
            *order.borrow()
                == if failure == 0 {
                    "0"
                } else if failure == 1 {
                    "01"
                } else {
                    "012"
                }
                && (if failure < 0 {
                    operation.is_ok()
                } else {
                    operation.is_err_and(|error| same(&error, &raw))
                }),
            "capture lifecycle original order differs"
        );
        ensure!(
            lifecycle
                .prepare(|| {
                    order.borrow_mut().push('p');
                    Ok(())
                })
                .is_err()
                && lifecycle
                    .seal(|| {
                        order.borrow_mut().push('s');
                        Ok(())
                    })
                    .is_err()
                && lifecycle
                    .enter(|| {
                        order.borrow_mut().push('e');
                        Ok(())
                    })
                    .is_err()
                && !order.borrow().contains(['p', 's', 'e']),
            "capture lifecycle retry reached callback"
        );
    }
    let mut missing = StorageLifecycle::default();
    ensure!(
        missing.enter(|| Err(error(&raw))).is_err(),
        "storage entered without seal"
    );
    Ok(())
}
fn tool_completion() -> Result<()> {
    ensure!(
        tool_arguments("fixed.etl", "fixed.txt", true)
            == ["parse", "-logfile:fixed.etl", "-outfile:fixed.txt"]
            && tool_arguments("fixed.etl", "fixed.txt", false)
                == ["trace", "-logfile:fixed.etl", "-nostop"],
        "fixed SxS tool arguments differ"
    );
    require_sxs_completion(0, false, 1.0, 10.0)?;
    for (exit, stderr, remaining, elapsed, expected) in [
        (
            0,
            false,
            0.0,
            10.0,
            "tool-result exit32=00000000 stderr_present=False deadline_expired=True wall_exceeded=False",
        ),
        (
            0,
            false,
            1.0,
            10.1,
            "tool-result exit32=00000000 stderr_present=False deadline_expired=False wall_exceeded=True",
        ),
        (
            0,
            true,
            1.0,
            10.0,
            "tool-result exit32=00000000 stderr_present=True deadline_expired=False wall_exceeded=False",
        ),
        (
            5,
            false,
            1.0,
            10.0,
            "tool-result exit32=00000005 stderr_present=False deadline_expired=False wall_exceeded=False",
        ),
        (
            u32::MAX,
            true,
            0.0,
            11.0,
            "tool-result exit32=FFFFFFFF stderr_present=True deadline_expired=True wall_exceeded=True",
        ),
    ] {
        let caught = require_sxs_completion(exit, stderr, remaining, elapsed).unwrap_err();
        ensure!(
            caught
                .downcast_ref::<PrivateFailure>()
                .is_some_and(|safe| safe.original().is::<CompletionContract>())
                && caught.to_string()
                    == format!("fixed SxS trace failed stage={expected} raw_error_withheld=True")
                && !format!("{caught:?}").contains("did not complete cleanly"),
            "SxS completion projection differs"
        );
    }
    Ok(())
}
