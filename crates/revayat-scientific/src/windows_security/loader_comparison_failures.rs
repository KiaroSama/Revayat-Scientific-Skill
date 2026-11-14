//! Original nine leg and seven sweep failures, retaining exact error owners.
use super::*;
pub(super) fn check_legs() -> Result<()> {
    for stage in 0..9 {
        let (primary, address) = fault();
        let primary = RefCell::new(Some(primary));
        let fail = || Err(primary.borrow_mut().take().unwrap());
        let effects = Cell::new(0);
        let cleaned = Cell::new(0);
        let released = Cell::new(0);
        let absent = Cell::new(0);
        let completed = Cell::new(0);
        let result = observe_leg(
            1,
            || if stage == 0 { fail() } else { Ok(()) },
            || {
                effects.set(effects.get() + 1);
                if stage == 1 { fail() } else { Ok(()) }
            },
            |_| {
                effects.set(effects.get() + 1);
                if stage == 3 {
                    return Err(primary.borrow_mut().take().unwrap());
                }
                Ok(if stage == 4 {
                    "private-sentinel"
                } else {
                    "LOADER_TRACE_EXIT=0xC0150002"
                }
                .into())
            },
            |_| {
                cleaned.set(cleaned.get() + 1);
                released.set(released.get() + 1);
                if matches!(stage, 5 | 6) {
                    fail()
                } else {
                    Ok(())
                }
            },
            || {
                absent.set(absent.get() + 1);
                if stage == 7 { fail() } else { Ok(()) }
            },
            |line| {
                if line == begin(Condition::Modified) {
                    if stage == 2 {
                        return fail();
                    }
                } else {
                    completed.set(completed.get() + 1);
                    if stage == 8 {
                        return fail();
                    }
                }
                Ok(())
            },
        );
        let error = result.expect_err("fixed loader leg failure must remain fatal");
        ensure!(
            cleaned.get() == i32::from(stage != 0)
                && released.get() == cleaned.get()
                && absent.get() == i32::from(stage >= 7)
                && completed.get() == i32::from(stage == 8)
        );
        ensure!(
            effects.get()
                == if stage == 0 {
                    0
                } else if stage <= 2 {
                    1
                } else {
                    2
                }
        );
        ensure!(if stage == 4 {
            !identity(&error, address) && !error.to_string().contains("private-sentinel")
        } else {
            identity(&error, address)
        });
    }
    let (operation, operation_id) = fault();
    let (cleanup, cleanup_id) = fault();
    let attempts = Cell::new(0);
    let result = observe_leg(
        1,
        || Ok(()),
        || Ok(()),
        |_| Err(operation),
        |_| {
            attempts.set(attempts.get() + 1);
            Err(cleanup)
        },
        || anyhow::bail!("absence must not run"),
        |_| Ok(()),
    );
    let error = result.unwrap_err();
    let group = error.downcast_ref::<Failures>().unwrap();
    ensure!(
        attempts.get() == 1
            && group.errors.len() == 2
            && identity(&group.errors[0], operation_id)
            && identity(&group.errors[1], cleanup_id)
    );
    Ok(())
}
pub(super) fn check_sweep() -> Result<()> {
    for stage in 0..7 {
        let (primary, primary_id) = fault();
        let (recovery, recovery_id) = fault();
        let primary = RefCell::new(Some(primary));
        let recovery = RefCell::new(Some(recovery));
        let visits = Cell::new(0);
        let begins = Cell::new(0);
        let restores = Cell::new(0);
        let defers = Cell::new(0);
        let result = execute(
            |condition| {
                visits.set(visits.get() + 1);
                if (stage == 0 && condition == Condition::Original)
                    || (matches!(stage, 2 | 3) && condition == Condition::Modified)
                    || (stage == 5 && condition == Condition::Restored)
                {
                    return Err(primary.borrow_mut().take().unwrap());
                }
                Ok(if condition == Condition::Modified {
                    u32::MAX
                } else {
                    0
                })
            },
            || {
                begins.set(begins.get() + 1);
                if stage == 1 {
                    return Err(primary.borrow_mut().take().unwrap());
                }
                Ok(Trial {
                    restore: Box::new(|| {
                        restores.set(restores.get() + 1);
                        if matches!(stage, 4 | 6) {
                            Err(recovery.borrow_mut().take().unwrap())
                        } else {
                            Ok(())
                        }
                    }),
                    defer: Box::new(|| {
                        defers.set(defers.get() + 1);
                        if stage == 3 {
                            Err(recovery.borrow_mut().take().unwrap())
                        } else {
                            Ok(())
                        }
                    }),
                })
            },
        );
        let error = result.expect_err("fixed loader sweep failure must remain fatal");
        ensure!(
            visits.get()
                == if stage <= 1 {
                    1
                } else if stage == 5 {
                    3
                } else {
                    2
                }
        );
        ensure!(
            begins.get() == i32::from(stage != 0)
                && restores.get() == i32::from(stage >= 4)
                && defers.get() == i32::from(matches!(stage, 2 | 3))
        );
        if stage == 3 {
            let group = error.downcast_ref::<Failures>().unwrap();
            ensure!(
                group.errors.len() == 2
                    && identity(&group.errors[0], primary_id)
                    && identity(&group.errors[1], recovery_id)
            );
        } else {
            ensure!(identity(
                &error,
                if matches!(stage, 4 | 6) {
                    recovery_id
                } else {
                    primary_id
                }
            ));
        }
    }
    Ok(())
}
