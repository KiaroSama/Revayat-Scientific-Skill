//! Original LoaderTrace.CheckActivationEventValidation/DestructionValidation bodies.
use super::*;
use crate::windows_security::activation::Failures;
use std::{cell::Cell, sync::Arc};
#[derive(Debug)]
struct Identity(SharedError);
impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fixed lifecycle error")
    }
}
impl Error for Identity {}
fn identified(error: &SharedError) -> anyhow::Error {
    Identity(error.clone()).into()
}
fn same(error: &anyhow::Error, expected: &SharedError) -> bool {
    error
        .downcast_ref::<Identity>()
        .is_some_and(|v| Arc::ptr_eq(&v.0, expected))
}
pub fn check_activation_event_validation() -> Result<()> {
    let failure = crate::windows_security::scratch::failure;
    let primary = failure("operation");
    let restoration = failure("restore");
    let close = failure("close");
    let continuation = failure("continue");
    let attempts = RefCell::new(Vec::new());
    let error = activation_event(
        || {
            attempts.borrow_mut().push("operation");
            Err(identified(&primary))
        },
        || {
            attempts.borrow_mut().push("restore");
            Err(identified(&restoration))
        },
        vec![
            Box::new(|| {
                attempts.borrow_mut().push("close");
                Err(identified(&close))
            }),
            Box::new(|| {
                attempts.borrow_mut().push("second-close");
                Ok(())
            }),
        ],
        || {
            attempts.borrow_mut().push("continue");
            Err(identified(&continuation))
        },
    )
    .unwrap_err();
    let group = error.downcast_ref::<Failures>().unwrap();
    ensure!(
        group.errors.len() == 4
            && same(&group.errors[0], &primary)
            && same(&group.errors[1], &restoration)
            && same(&group.errors[2], &close)
            && same(&group.errors[3], &continuation)
            && *attempts.borrow() == ["operation", "restore", "close", "second-close", "continue"],
        "activation event lost ordered failures or skipped cleanup"
    );
    attempts.borrow_mut().clear();
    let error = activation_event_optional(
        || Err(identified(&primary)),
        || {
            attempts.borrow_mut().push("restore");
            Ok(())
        },
        vec![Box::new(|| {
            attempts.borrow_mut().push("close");
            Ok(())
        })],
        None,
    )
    .unwrap_err();
    ensure!(
        same(&error, &primary) && *attempts.borrow() == ["restore", "close"],
        "CREATE failure replaced or prematurely continued"
    );
    attempts.borrow_mut().clear();
    let error = activation_event(
        || {
            attempts.borrow_mut().push("operation");
            Ok(())
        },
        || {
            attempts.borrow_mut().push("restore");
            Ok(())
        },
        vec![
            Box::new(|| {
                attempts.borrow_mut().push("close");
                Err(identified(&close))
            }),
            Box::new(|| {
                attempts.borrow_mut().push("second-close");
                Ok(())
            }),
        ],
        || {
            attempts.borrow_mut().push("continue");
            Ok(())
        },
    )
    .unwrap_err();
    ensure!(
        same(&error, &close)
            && *attempts.borrow() == ["operation", "close", "second-close", "restore", "continue"],
        "close failure skipped restoration or continuation"
    );
    Ok(())
}
pub fn check_activation_destruction_validation() -> Result<()> {
    for (elapsed, expected) in [
        (0, 5000),
        (1, 4999),
        (4999, 1),
        (5000, 0),
        (5001, 0),
        (i64::MAX, 0),
    ] {
        ensure!(
            remaining_activation_cleanup(elapsed)? == expected,
            "cleanup replenished its deadline"
        );
    }
    ensure!(
        remaining_activation_cleanup(-1).is_err(),
        "cleanup accepted negative clock"
    );
    let called = Cell::new(0);
    let destroyed = Cell::new(false);
    confirm_activation_destruction(
        true,
        false,
        true,
        4999,
        |timeout| {
            called.set(called.get() + 1);
            ensure!(timeout == 1, "timeout differs");
            Ok(WaitOutcome {
                result: 0,
                error: 0,
            })
        },
        || {
            destroyed.set(true);
            Ok(())
        },
    )?;
    ensure!(
        called.get() == 1 && destroyed.get(),
        "destruction did not wait for signaling"
    );
    for result in [258, u32::MAX, 128, 1] {
        destroyed.set(false);
        ensure!(
            confirm_activation_destruction(
                true,
                false,
                true,
                5000,
                |_| Ok(WaitOutcome { result, error: 5 }),
                || {
                    destroyed.set(true);
                    Ok(())
                }
            )
            .is_err()
                && !destroyed.get(),
            "destruction accepted nonsignaled wait"
        );
    }
    for [exit, pending, handle] in [
        [false, false, true],
        [true, true, true],
        [true, false, false],
    ] {
        called.set(0);
        destroyed.set(false);
        ensure!(
            confirm_activation_destruction(
                exit,
                pending,
                handle,
                0,
                |_| {
                    called.set(called.get() + 1);
                    Ok(WaitOutcome {
                        result: 0,
                        error: 0,
                    })
                },
                || {
                    destroyed.set(true);
                    Ok(())
                }
            )
            .is_err()
                && called.get() == 0
                && !destroyed.get(),
            "destruction ignored prerequisites"
        );
    }
    let queries = Cell::new(0);
    let pauses = Cell::new(0);
    await_activation_job_zero(
        || {
            queries.set(queries.get() + 1);
            Ok(u32::from(queries.get() < 3))
        },
        || Ok(if queries.get() == 1 { 21 } else { 1 }),
        |milliseconds| {
            ensure!(
                milliseconds == if pauses.get() == 0 { 20 } else { 1 },
                "job remainder differs"
            );
            pauses.set(pauses.get() + 1);
            Ok(())
        },
    )?;
    ensure!(
        queries.get() == 3 && pauses.get() == 2,
        "Job-zero was not qualified"
    );
    ensure!(
        await_activation_job_zero(|| Ok(1), || Ok(0), |_| panic!("expired pause")).is_err(),
        "Job-zero replenished deadline"
    );
    await_activation_job_zero(
        || Ok(0),
        || panic!("zero job waited"),
        |_| panic!("zero job paused"),
    )
}
