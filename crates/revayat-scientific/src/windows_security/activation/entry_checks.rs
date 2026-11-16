use super::super::{
    CONTEXT_SIZE,
    csr::thread_checks::{Io, change, put},
};
use super::*;
use std::sync::Arc;
pub(super) fn fixture(stage: u8) -> Result<(Entry<Io>, Io)> {
    let io = Io::default();
    let baseline = vec![0; CONTEXT_SIZE];
    let mut entry = Entry::new(7, 11, 11, io.clone())?;
    entry.stage = stage;
    entry.baseline = Some(baseline.clone());
    entry.sites[0] = 0x8000;
    entry.enabled[0] = true;
    entry.stopped = true;
    entry.changed = true;
    io.0.borrow_mut().contexts.insert(
        11,
        software::desired(&baseline, &baseline, &entry.sites, &entry.enabled, false)?,
    );
    Ok((entry, io))
}
#[derive(Clone, Debug)]
pub(super) struct Failure(pub Arc<()>);
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fixed entry restoration")
    }
}
impl std::error::Error for Failure {}
pub fn check_explicit_entry_validation() -> Result<()> {
    let mut baseline = vec![0; CONTEXT_SIZE];
    put(&mut baseline, 112, 0x400);
    let mut current = baseline.clone();
    put(&mut current, 120, u64::MAX);
    put(&mut current, 248, 0x8000);
    let armed = software::desired(&current, &baseline, &[0x8000, 0], &[true, false], false)?;
    let reset = software::desired(&armed, &baseline, &[0; 2], &[false; 2], true)?;
    ensure!(
        software::value(&armed, 72)? == 0x8000
            && software::value(&armed, 80)? == 0
            && software::value(&armed, 112)? == 0x401
            && raw_debug_equal(&reset, &baseline)?
            && unchanged_control_integer(&current, &reset)?,
        "entry arm/reset changes integer/control"
    );
    for kind in [2, 4, 6, 7, 8] {
        let (mut observer, _) = fixture(1)?;
        observer.stop(7, 12, kind, false)?;
        ensure!(
            !observer.stopped
                && !observer.restoration_allowed()
                && !observer.invalidated
                && observer.alive,
            "entry metadata peer stop changed creator lifetime"
        );
        observer.stop(7, 11, 4, false)?;
        ensure!(
            !observer.alive && !observer.stopped,
            "entry creator EXIT_THREAD left alive"
        );
        observer.stop(7, 11, 6, false)?;
        ensure!(
            !observer.alive && !observer.stopped,
            "later entry load resurrected creator"
        );
    }
    for cleanup in [false, true] {
        let (mut observer, _) = fixture(1)?;
        ensure!(
            observer.stop(7, 12, 1, cleanup).is_err() != cleanup
                && observer.invalidated
                && !observer.restoration_allowed(),
            "entry peer exception scope differs"
        );
    }
    for status in [0xfffe0ff1, 0xffff0ff1] {
        ensure!(
            trap_accepted(11, 11, true, true, 0x8000, 0x8000, 0x8000, status, 0x401, 1),
            "entry owned trap refused"
        );
        for input in [
            (12, true, true, 0x8000, 0x8000),
            (11, false, true, 0x8000, 0x8000),
            (11, true, false, 0x8000, 0x8000),
            (11, true, true, 0x8001, 0x8000),
            (11, true, true, 0x8000, 0x8001),
        ] {
            ensure!(
                !trap_accepted(
                    input.0, 11, input.1, input.2, input.3, 0x8000, input.4, status, 0x401, 1
                ),
                "entry invalid trap site accepted"
            );
        }
        for foreign in [2, 4, 8, 0x1000, 0x2000, 0x4000, 0x8000, 0x100000000] {
            ensure!(
                !trap_accepted(
                    11,
                    11,
                    true,
                    true,
                    0x8000,
                    0x8000,
                    0x8000,
                    status | foreign,
                    0x401,
                    1
                ),
                "entry foreign trap cause accepted"
            );
        }
    }
    for fail in [false, true] {
        let (mut observer, _) = fixture(1)?;
        let original = Arc::new(());
        let result = observer.entry_hit(0xfffe0ff1, |owner| {
            if fail {
                return Err(Failure(original.clone()).into());
            }
            owner.restored = true;
            Ok(())
        });
        ensure!(
            observer.hit && observer.stage == if fail { 1 } else { 2 } && observer.restored != fail,
            "entry failed restoration reset first hit"
        );
        if fail {
            ensure!(
                result
                    .unwrap_err()
                    .downcast_ref::<Failure>()
                    .is_some_and(|v| Arc::ptr_eq(&v.0, &original)),
                "entry restoration failure identity replaced"
            );
        } else {
            result?;
        }
        ensure!(
            observer.entry_hit(0xfffe0ff1, |_| Ok(())).is_err(),
            "entry repeat hit accepted"
        );
    }
    ensure!(
        software::require_modes(software::ObservationRoles {
            callback: true,
            entry: true,
            ..Default::default()
        })
        .is_err(),
        "entry/callback roles overlap"
    );
    Ok(())
}
pub fn check_software_presentation() -> Result<()> {
    for role in [
        SoftwareRole::Boundary,
        SoftwareRole::Callback,
        SoftwareRole::Entry,
    ] {
        for stage in 1..=3 {
            if matches!(role, SoftwareRole::Boundary) && stage != 1
                || matches!(role, SoftwareRole::Entry) && stage == 3
            {
                continue;
            }
            for status in [0xfffe07f0, 0xfffe0ff0, 0xffff07f0, 0xffff0ff0] {
                for fixed in [0, 0x400] {
                    let baseline = vec![0; CONTEXT_SIZE];
                    let active = matches!(role, SoftwareRole::Boundary)
                        || matches!(role, SoftwareRole::Callback) && stage == 2
                        || matches!(role, SoftwareRole::Entry) && stage == 1;
                    let sites = [if active { 0x8000 } else { 0 }, 0];
                    let enabled = [active, false];
                    let mut context =
                        software::desired(&baseline, &baseline, &sites, &enabled, false)?;
                    put(&mut context, 104, status);
                    put(
                        &mut context,
                        112,
                        software::control(&baseline, &enabled)? ^ fixed,
                    );
                    let mut presentation = SoftwarePresentation::default();
                    let event = SoftwareEvent {
                        thread: 11,
                        creator: 11,
                        code: 0x80000003,
                        first: true,
                    };
                    ensure!(
                        software::software_stage(role, stage, false, false, event)
                            && !software::software_stage(
                                role,
                                stage,
                                false,
                                false,
                                SoftwareEvent {
                                    thread: 12,
                                    ..event
                                }
                            )
                            && !software::software_stage(
                                role,
                                stage,
                                false,
                                false,
                                SoftwareEvent {
                                    code: 0x80000004,
                                    ..event
                                }
                            )
                            && !software::software_stage(
                                role,
                                stage,
                                false,
                                false,
                                SoftwareEvent {
                                    first: false,
                                    ..event
                                }
                            ),
                        "software event scope differs"
                    );
                    if matches!(role, SoftwareRole::Callback) {
                        ensure!(
                            presentation
                                .callback_load_ownership(&context, &baseline, &sites, &enabled)
                                .is_err(),
                            "callback pre-software load accepted presentation"
                        );
                        presentation
                            .callback_load_ownership(&baseline, &baseline, &sites, &enabled)?;
                    }
                    for offset in [72, 80, 88, 96, 104, 112] {
                        let mut foreign = context.clone();
                        let value = software::value(&foreign, offset)?
                            ^ if offset == 104 {
                                0x1000
                            } else if offset == 112 {
                                0x800
                            } else {
                                1
                            };
                        put(&mut foreign, offset, value);
                        ensure!(
                            presentation
                                .accept(&foreign, &baseline, &sites, &enabled)
                                .is_err()
                                && !presentation.initial()
                                && presentation.snapshot().is_none(),
                            "foreign software ownership latched"
                        );
                    }
                    presentation.accept(&context, &baseline, &sites, &enabled)?;
                    let first = presentation.snapshot().unwrap().to_owned();
                    ensure!(
                        presentation.initial()
                            && first.contains(&format!("software_raw_dr6=0x{status:016X}"))
                            && first.contains("software_origin_verified=False")
                            && !software::software_stage(role, stage, false, true, event),
                        "software presentation advanced observation or omitted qualifiers"
                    );
                    put(&mut context, 104, status ^ 0x10800);
                    ensure!(
                        presentation
                            .accept(&context, &baseline, &sites, &enabled)
                            .is_err()
                            && presentation.snapshot() == Some(first.as_str()),
                        "software first snapshot replaced"
                    );
                    if matches!(role, SoftwareRole::Callback) {
                        presentation
                            .callback_load_ownership(&context, &baseline, &sites, &enabled)?;
                    }
                    if matches!(role, SoftwareRole::Entry) {
                        let (mut observer, _) = fixture(stage)?;
                        observer.software = presentation;
                        observer.sites = sites;
                        observer.enabled = enabled;
                        observer.destroyed = true;
                        ensure!(
                            !observer.hit
                                && !observer.restored
                                && observer.require_complete().is_err(),
                            "software alone completed entry"
                        );
                        let line = observer.metadata()?;
                        ensure!(
                            line.len() <= 1024
                                && line.contains(&first)
                                && line.contains("entry_observed=False")
                                && !line.contains("private-")
                                && !line.contains("0000000000008000"),
                            "entry software metadata differs"
                        );
                        super::super::fixtures::self_host::check_rejected_entry(|| {
                            observer.require_complete()
                        })?;
                        if stage == 1 {
                            observer.entry_hit(0xfffe0ff1, |owner| {
                                owner.restored = true;
                                Ok(())
                            })?;
                            observer.natural_exit = true;
                            let line = observer.metadata()?;
                            ensure!(
                                line.len() <= 1024
                                    && line.contains(&first)
                                    && line.contains("raw_dr6=0x00000000FFFE0FF1")
                                    && line.contains("entry_observed=True")
                                    && line.contains("observation_qualified=True"),
                                "entry software then hardware metadata differs"
                            );
                        }
                    }
                }
            }
        }
    }
    software_then_hardware_failure()
}
fn software_then_hardware_failure() -> Result<()> {
    for mode in 0..6 {
        let (mut observer, io) = fixture(1)?;
        change(&io, 11, 104, 0xfffe07f0);
        change(&io, 11, 112, 0x401);
        let event = SoftwareEvent {
            thread: 11,
            creator: 11,
            code: 0x80000003,
            first: true,
        };
        ensure!(
            observer.software_stage(event),
            "entry initial software phase differs"
        );
        observer.accept_software(event)?;
        change(
            &io,
            11,
            104,
            if mode == 0 {
                0xfffe07f1
            } else if mode == 1 {
                0xfffe0ff3
            } else {
                0xfffe0ff1
            },
        );
        change(&io, 11, 248, if mode == 2 { 0x8001 } else { 0x8000 });
        let bytes = io.0.borrow().contexts[&11].clone();
        let owner = RefCell::new(observer);
        let restores = Cell::new(0);
        let continuations = Cell::new(0);
        let result = finalize_entry_event(
            &owner,
            Event {
                kind: 1,
                unloaded: 0,
                cleanup: false,
            },
            |entry| {
                if mode == 5 {
                    ensure!(
                        entry.single_step(
                            SoftwareEvent {
                                code: 0xc0000005,
                                ..event
                            },
                            0x8000
                        )? || entry.accept_software(SoftwareEvent {
                            code: 0xc0000005,
                            ..event
                        })?,
                        "fixed entry observation encountered an unexpected exception"
                    );
                }
                entry.hardware_context(
                    if mode == 3 { 12 } else { 11 },
                    mode != 4,
                    0x8000,
                    &bytes,
                    |_| {
                        restores.set(restores.get() + 1);
                        Ok(())
                    },
                )
            },
            || Ok(()),
            vec![],
            |status| {
                ensure!(status == 0x80010001, "entry failed exception handled");
                continuations.set(continuations.get() + 1);
                Ok(())
            },
        );
        ensure!(
            result.is_err()
                && continuations.get() == 1
                && restores.get() == 0
                && owner.borrow().invalidated
                && !owner.borrow().hit
                && !owner.borrow().complete(),
            "entry bad hardware after software qualified"
        );
        change(&io, 11, 104, 0xfffe0ff1);
        change(&io, 11, 248, 0x8000);
        ensure!(
            !owner.borrow().software_stage(event)
                && owner
                    .borrow_mut()
                    .single_step(
                        SoftwareEvent {
                            code: 0x80000004,
                            ..event
                        },
                        0x8000
                    )
                    .is_err()
                && !owner.borrow().hit
                && owner.borrow().require_complete().is_err(),
            "entry invalidated hardware rescued"
        );
        super::super::fixtures::self_host::check_rejected_entry(|| {
            owner.borrow().require_complete()
        })?;
    }
    Ok(())
}
