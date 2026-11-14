//! Exact peer/lifecycle/header matrices from ModuleCallbackTrace.cs.
use super::*;
use crate::windows_security::activation::{
    CONTEXT_SIZE, Failures, boundary::check_io::*, raw_debug_equal,
};
use std::cell::RefCell;
pub(super) fn check_peer_transport() -> Result<()> {
    for state in [1, 2, 3] {
        for kind in [2, 4] {
            let report = RefCell::new(None);
            let mut o = observer(BoundaryMode::ModuleCallback, |line| {
                *report.borrow_mut() = Some(line.to_owned());
                Ok(())
            })?;
            o.stage = state;
            o.changed = true;
            o.stopped = true;
            o.stop(7, 12, kind, false)?;
            o.other_thread(12, kind)?;
            ensure!(
                o.stage == state
                    && o.alive
                    && !o.stopped
                    && !o.invalidated
                    && !o.restoration_allowed()
                    && !o.restored
                    && !o.software.initial()
                    && o.original.is_none()
                    && o.addresses[0] == 0
                    && !o.enabled[0]
                    && report.borrow().as_deref()
                        == Some(&format!(
                            "phase=module-callback-peer-transport kind={kind} context_read=False observation_advanced=False"
                        ))
                    && o.require_complete().is_err(),
                "peer transport advanced or qualified callback"
            );
            o.stop(7, 11, 6, false)?;
            ensure!(
                o.stopped && o.restoration_allowed(),
                "creator stop did not permit cleanup"
            );
            o.continued();
            ensure!(
                !o.restoration_allowed(),
                "continued creator permits context access"
            );
        }
    }
    for state in [0, 1, 2, 3, 4] {
        for kind in [1, 2, 3, 4, 5, 6, 7, 8, 9, u32::MAX] {
            let mut o = observer(BoundaryMode::ModuleCallback, |_| Ok(()))?;
            o.stage = state;
            o.changed = true;
            o.stopped = true;
            let allowed = (1..=3).contains(&state) && matches!(kind, 2 | 4 | 5);
            let refused = o.stop(7, 12, kind, false).is_err();
            ensure!(
                refused != allowed && o.invalidated != allowed && !o.restoration_allowed(),
                "peer state/kind product differs"
            );
            if allowed {
                for mode in [BoundaryMode::Child, BoundaryMode::ModuleCallback] {
                    let mut foreign = observer(mode, |_| Ok(()))?;
                    foreign.stage = state;
                    let result = foreign
                        .stop(
                            if mode == BoundaryMode::ModuleCallback {
                                8
                            } else {
                                7
                            },
                            12,
                            kind,
                            false,
                        )
                        .and_then(|_| foreign.other_thread(12, kind));
                    ensure!(
                        result.is_err() && !foreign.restoration_allowed(),
                        "foreign peer mode/process admitted"
                    );
                }
                o.invalidate();
                ensure!(
                    o.stop(7, 12, kind, false).is_err() && !o.restoration_allowed(),
                    "invalidated peer event admitted"
                );
            }
        }
    }
    Ok(())
}
pub(super) fn check_lifecycle_transport() -> Result<()> {
    for state in [1, 2, 3] {
        for retired in [false, true] {
            for exit_thread in [11, 12] {
                let report = RefCell::new(None);
                let mut o = observer(BoundaryMode::ModuleCallback, |line| {
                    *report.borrow_mut() = Some(line.to_owned());
                    Ok(())
                })?;
                o.stage = state;
                o.restored = state == 3;
                o.changed = state == 2;
                o.original = Some(vec![0; CONTEXT_SIZE]);
                o.addresses[0] = if state == 2 { 0x8000 } else { 0 };
                o.enabled[0] = state == 2;
                initial(&mut o)?;
                let original = o.original.as_ref().unwrap().clone();
                if retired {
                    o.stop(7, 11, 4, false)?;
                    o.other_thread(11, 4)?;
                    ensure!(
                        !o.alive
                            && !o.stopped
                            && !o.restoration_allowed()
                            && !o.callback_process_exited
                            && report.borrow().as_deref()
                                == Some(
                                    "phase=module-callback-creator-retirement kind=4 context_read=False observation_advanced=False"
                                ),
                        "creator retirement changed callback evidence"
                    );
                    o.continued();
                }
                for kind in [2, 4] {
                    o.stop(7, 12, kind, false)?;
                    o.other_thread(12, kind)?;
                    ensure!(
                        o.alive != retired
                            && !o.stopped
                            && !o.restoration_allowed()
                            && !o.callback_process_exited,
                        "peer lifecycle transport changed creator state"
                    );
                    o.continued();
                }
                o.stop(7, exit_thread, 5, false)?;
                ensure!(
                    o.callback_process_exited
                        && !o.alive
                        && !o.stopped
                        && !o.invalidated
                        && !o.restoration_allowed()
                        && o.stage == state
                        && o.restored == (state == 3)
                        && o.changed == (state == 2)
                        && o.software.initial()
                        && o.addresses[0] == if state == 2 { 0x8000 } else { 0 }
                        && o.enabled[0] == (state == 2)
                        && raw_debug_equal(o.original.as_ref().unwrap(), &original)?,
                    "EXIT changed observation/restoration/baseline state"
                );
                o.continued();
                ensure!(
                    o.require_complete().is_err() == (state != 3),
                    "EXIT invented callback completion"
                );
                ensure!(
                    o.stop(7, 12, 2, false).is_err() && o.invalidated && !o.restoration_allowed(),
                    "post-EXIT event admitted"
                );
            }
        }
    }
    for state in [0, 1, 2, 3, 4] {
        for kind in [4, 5] {
            for invalid in [false, true] {
                let mut o = observer(BoundaryMode::ModuleCallback, |_| Ok(()))?;
                o.stage = state;
                o.invalidated = invalid;
                let allowed = (1..=3).contains(&state) && !invalid;
                let result = o.stop(7, 11, kind, false).and_then(|_| {
                    if kind == 4 {
                        o.other_thread(11, kind)
                    } else {
                        Ok(())
                    }
                });
                ensure!(
                    result.is_err() != allowed && !o.restoration_allowed(),
                    "retirement stage/invalid product differs"
                );
            }
        }
    }
    for kind in [1, 2, 3, 4, 5, 6, 7, 8, 9, u32::MAX] {
        for thread in [11, 12] {
            let mut o = observer(BoundaryMode::ModuleCallback, |_| Ok(()))?;
            o.stage = 3;
            o.restored = true;
            o.stop(7, 11, 4, false)?;
            o.other_thread(11, 4)?;
            o.continued();
            let allowed = kind == 5 || thread != 11 && matches!(kind, 2 | 4);
            let result = o.stop(7, thread, kind, false).and_then(|_| {
                if matches!(kind, 2 | 4) {
                    o.other_thread(thread, kind)
                } else {
                    Ok(())
                }
            });
            ensure!(
                result.is_err() != allowed && !o.restoration_allowed() && !o.alive,
                "retired creator event product differs"
            );
            if !allowed {
                ensure!(
                    o.require_complete().is_err() && o.invalidated,
                    "retired refused event retained completion"
                );
            }
            for mode in [BoundaryMode::Child, BoundaryMode::ModuleCallback] {
                let mut foreign = observer(mode, |_| Ok(()))?;
                foreign.stage = 3;
                ensure!(
                    foreign
                        .stop(
                            if mode == BoundaryMode::ModuleCallback {
                                8
                            } else {
                                7
                            },
                            thread,
                            kind,
                            false
                        )
                        .and_then(|_| foreign.other_thread(thread, kind))
                        .is_err(),
                    "foreign retired event admitted"
                );
            }
        }
    }
    Ok(())
}
pub(super) fn check_header() -> Result<()> {
    let report = RefCell::new(None);
    let mut o = observer(BoundaryMode::ModuleCallback, |line| {
        *report.borrow_mut() = Some(line.to_owned());
        Ok(())
    })?;
    o.binding.path = "private-path".into();
    o.binding.digest = "private-digest".into();
    o.stage = 2;
    o.stopped = true;
    o.changed = true;
    ensure!(
        o.stop(7, 12, 1, false).is_err()
            && o.invalidated
            && !o.restoration_allowed()
            && report.borrow().as_deref()
                == Some(
                    "phase=module-callback-stop-refusal kind=1 process_match=True creator=False cleanup=False stage=2 context_read=False"
                ),
        "callback stop header leaks/omits fields"
    );
    *report.borrow_mut() = None;
    o.stop(7, 12, 4, true)?;
    ensure!(
        report.borrow().is_none() && !o.restoration_allowed(),
        "cleanup peer reported/authorized context"
    );
    o.stop(7, 11, 6, true)?;
    ensure!(
        report.borrow().is_none() && o.restoration_allowed(),
        "cleanup creator authorization differs"
    );
    ensure!(
        o.stop(8, 11, 5, true).is_err()
            && !o.restoration_allowed()
            && report.borrow().as_deref()
                == Some(
                    "phase=module-callback-stop-refusal kind=5 process_match=False creator=True cleanup=True stage=2 context_read=False"
                ),
        "foreign cleanup process accepted/header differs"
    );
    let reporting = failure("private-reporting");
    let mut o = observer(BoundaryMode::ModuleCallback, |_| Err(error(&reporting)))?;
    o.binding.path = "private-path".into();
    o.binding.digest = "private-digest".into();
    let retained = o.stop(7, 12, u32::MAX, false).unwrap_err();
    let group = retained.downcast_ref::<Failures>().unwrap();
    ensure!(
        group.errors.len() == 2
            && group.errors[0].to_string()
                == "fixed activation observation refused check=callback-thread"
            && same(&group.errors[1], &reporting)
            && o.invalidated
            && !o.restoration_allowed()
            && o.callback_stop_header(7, 12, u32::MAX, false)
                == "phase=module-callback-stop-refusal kind=4294967295 process_match=True creator=False cleanup=False stage=0 context_read=False",
        "callback refusal lost primary/report identity"
    );
    Ok(())
}
