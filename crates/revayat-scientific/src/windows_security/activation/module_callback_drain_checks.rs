//! Frozen seven-mode callback cleanup drain, preserving error identity and finite limits.
use super::*;
use crate::windows_security::{
    activation::{activation_event, boundary::check_io::*, event_lifecycle as lifecycle},
    scratch::{
        self, SharedError,
        cleanup::{OwnedCleanupFailure, QualifiedModuleCallbackFailure},
    },
};
use std::{
    cell::{Cell, RefCell},
    sync::Arc,
};

pub(super) fn check_drain() -> Result<()> {
    for mode in 0..=6 {
        let mut observer = observer(BoundaryMode::ModuleCallback, |_| Ok(()))?;
        observer.changed = true;
        observer.stopped = true;
        observer.stage = 2;
        let process = Cell::new(if mode == 6 { 8 } else { 7 });
        let primary = shared(observer.stop(process.get(), 12, 1, false).unwrap_err());
        ensure!(
            observer.invalidated && !observer.restoration_allowed(),
            "drain begins without invalidated primary"
        );
        let observer = RefCell::new(observer);
        let pending = Cell::new(true);
        let exited = Cell::new(false);
        let received = Cell::new(0usize);
        let continued = Cell::new(0usize);
        let releases = Cell::new(0usize);
        let accesses = Cell::new(0usize);
        let kind = Cell::new(2);
        let failures = RefCell::new(Vec::<SharedError>::new());
        let close = failure("fixed close failure");
        let continuation = failure("fixed continuation failure");
        let finish = || -> Result<()> {
            lifecycle::require_callback_event_process(process.get(), 7)?;
            let result = activation_event(
                || {
                    if kind.get() == 5 {
                        exited.set(true)
                    }
                    Ok(())
                },
                || {
                    let mut o = observer.borrow_mut();
                    if o.restoration_allowed() {
                        accesses.set(accesses.get() + 1)
                    }
                    o.restore()
                },
                vec![Box::new(|| {
                    releases.set(releases.get() + 1);
                    if mode == 1 && releases.get() == 1 {
                        Err(error(&close))
                    } else {
                        Ok(())
                    }
                })],
                || {
                    continued.set(continued.get() + 1);
                    if mode == 2 {
                        return Err(error(&continuation));
                    }
                    pending.set(false);
                    observer.borrow_mut().continued();
                    Ok(())
                },
            );
            if let Err(error) = result {
                failures.borrow_mut().push(shared(error));
            }
            Ok(())
        };
        let result = lifecycle::drain_callback_events(
            || exited.get(),
            || pending.get(),
            || Ok(if mode == 3 { 0 } else { 5000 }),
            |milliseconds| {
                ensure!(milliseconds <= 100, "callback drain wait exceeds 100ms");
                ensure!(!pending.get(), "fixed pending continuation");
                received.set(received.get() + 1);
                kind.set(if mode == 4 {
                    6
                } else if received.get() == 3 {
                    5
                } else {
                    4
                });
                let thread = if kind.get() == 5 {
                    11
                } else {
                    12 + received.get() as u32
                };
                pending.set(true);
                process.set(if mode == 5 { 8 } else { 7 });
                let mut o = observer.borrow_mut();
                o.stop(process.get(), thread, kind.get(), true)?;
                ensure!(
                    o.invalidated && !o.restoration_allowed(),
                    "drain authorized creator state"
                );
                Ok(true)
            },
            finish,
        );
        if let Err(error) = result {
            failures.borrow_mut().push(shared(error));
        }
        ensure!(
            observer.borrow().invalidated
                && accesses.get() == 0
                && observer.borrow().io.reads.get() == 0,
            "drain read creator context"
        );
        if mode == 0 || mode == 1 {
            ensure!(
                exited.get()
                    && !pending.get()
                    && received.get() == 3
                    && continued.get() == 4
                    && releases.get() == 4,
                "continued EXIT drain order/count differs"
            );
        }
        let failures = failures.into_inner();
        if mode == 0 {
            ensure!(failures.is_empty(), "clean drain failed");
            lifecycle::confirm_activation_destruction(
                exited.get(),
                pending.get(),
                true,
                0,
                |_| {
                    Ok(lifecycle::WaitOutcome {
                        result: 0,
                        error: 0,
                    })
                },
                || Ok(()),
            )?;
            let qualified =
                scratch::cleanup::completion_failure(Some(primary.clone()), failures, true, true)
                    .unwrap();
            ensure!(
                qualified
                    .downcast_ref::<QualifiedModuleCallbackFailure>()
                    .is_some_and(|v| Arc::ptr_eq(&v.original, &primary)),
                "qualified cleanup lost primary identity"
            );
        } else {
            ensure!(!failures.is_empty(), "failed drain invented qualification");
            let group =
                scratch::cleanup::completion_failure(Some(primary.clone()), failures, true, false)
                    .unwrap();
            let group = group.downcast_ref::<OwnedCleanupFailure>().unwrap();
            ensure!(
                Arc::ptr_eq(&group.errors[0], &primary),
                "drain aggregate lost primary identity/order"
            );
            match mode {
                1 => ensure!(
                    Arc::ptr_eq(&group.errors[1], &close),
                    "drain lost close failure identity"
                ),
                2 => ensure!(
                    pending.get() && received.get() == 0 && continued.get() == 1 && !exited.get(),
                    "failed continuation was retried/qualified"
                ),
                3 => ensure!(
                    received.get() == 0 && !exited.get(),
                    "expired deadline received an event"
                ),
                4 => ensure!(
                    received.get() == 128 && !exited.get(),
                    "callback drain exceeded/lowered event ceiling"
                ),
                5 => ensure!(
                    received.get() == 1
                        && continued.get() == 1
                        && pending.get()
                        && !observer.borrow().restoration_allowed(),
                    "foreign drain event was continued/accessed"
                ),
                6 => ensure!(
                    received.get() == 0
                        && continued.get() == 0
                        && releases.get() == 0
                        && pending.get()
                        && !exited.get(),
                    "foreign pending event touched owned cleanup"
                ),
                _ => unreachable!(),
            }
        }
        for wait in [258, u32::MAX] {
            ensure!(
                lifecycle::confirm_activation_destruction(
                    true,
                    false,
                    true,
                    0,
                    |_| Ok(lifecycle::WaitOutcome {
                        result: wait,
                        error: 0
                    }),
                    || Ok(())
                )
                .is_err(),
                "unsignaled wait qualified destruction"
            );
        }
        let o = observer.borrow();
        ensure!(
            !complete(o.stage, o.restored, o.invalidated),
            "failed drain completed callback"
        );
    }
    Ok(())
}
