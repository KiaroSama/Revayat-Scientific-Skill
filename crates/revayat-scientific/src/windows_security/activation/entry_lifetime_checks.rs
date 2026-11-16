use super::super::{CONTEXT_SIZE, EventCleanup, Failures, csr::thread_checks::Io};
use super::checks::{Failure, fixture};
use super::*;
use std::sync::Arc;
fn create(image: &PeImage<'_>) -> Result<RefCell<Entry<Io>>> {
    let (mut entry, _) = fixture(1)?;
    entry.base = image.base;
    entry.sites[0] = image
        .base
        .checked_add(u64::from(image.entry))
        .ok_or_else(|| anyhow::anyhow!("entry fixture overflow"))?;
    entry.baseline = Some(vec![0; CONTEXT_SIZE]);
    Ok(RefCell::new(entry))
}
pub fn check_entry_lifetime_validation(image: &PeImage<'_>) -> Result<()> {
    ensure!(
        image.entry != 0 && image.executable(image.entry, 1),
        "entry validation fixture entry differs"
    );
    for kind in [2, 4, 6, 7, 8] {
        let observer = create(image)?;
        let exceptions = Cell::new(0);
        let exits = Cell::new(0);
        let closes = Cell::new(0);
        let continuations = Cell::new(0);
        observer.borrow_mut().stop(7, 12, kind, false)?;
        finalize_entry_event(
            &observer,
            Event {
                kind,
                unloaded: 0x20000000,
                cleanup: false,
            },
            |_| {
                exceptions.set(exceptions.get() + 1);
                Ok(())
            },
            || {
                exits.set(exits.get() + 1);
                Ok(())
            },
            vec![Box::new(|| {
                ensure!(
                    !observer.borrow().restoration_allowed() && !observer.borrow().stopped,
                    "entry peer release borrowed creator epoch"
                );
                closes.set(closes.get() + 1);
                Ok(())
            })],
            |status| {
                ensure!(
                    status == 0x10002 && !observer.borrow().stopped,
                    "entry peer metadata continuation differs"
                );
                continuations.set(continuations.get() + 1);
                observer.borrow_mut().continued();
                Ok(())
            },
        )?;
        ensure!(
            !observer.borrow().invalidated
                && exceptions.get() == 0
                && exits.get() == 0
                && closes.get() == 1
                && continuations.get() == 1
                && !observer.borrow().restored,
            "entry metadata-only event altered observation"
        );
    }
    for kind in [1, 3, 9, u32::MAX] {
        let observer = create(image)?;
        let exceptions = Cell::new(0);
        let releases = Cell::new(0);
        let continuations = Cell::new(0);
        let result = observer.borrow_mut().stop(7, 12, kind, false);
        let result = match result {
            Err(error) => Err(error),
            Ok(()) => finalize_entry_event(
                &observer,
                Event {
                    kind,
                    unloaded: 0,
                    cleanup: false,
                },
                |_| {
                    exceptions.set(exceptions.get() + 1);
                    Ok(())
                },
                || Ok(()),
                vec![Box::new(|| {
                    releases.set(releases.get() + 1);
                    Ok(())
                })],
                |_| {
                    continuations.set(continuations.get() + 1);
                    Ok(())
                },
            ),
        };
        ensure!(
            result.is_err()
                && observer.borrow().invalidated
                && !observer.borrow().restoration_allowed()
                && !observer.borrow().restored
                && exceptions.get() == 0
                && releases.get() == usize::from(kind != 1)
                && continuations.get() == releases.get(),
            "unsupported entry event ownership/order differs"
        );
    }
    for own in [false, true] {
        let observer = create(image)?;
        observer.borrow_mut().stop(7, 12, 7, false)?;
        let continued = Cell::new(0);
        let result = finalize_entry_event(
            &observer,
            Event {
                kind: 7,
                unloaded: if own {
                    image.base
                } else {
                    image.base + 0x10000
                },
                cleanup: false,
            },
            |_| anyhow::bail!("unload dispatched as exception"),
            || Ok(()),
            vec![],
            |_| {
                continued.set(continued.get() + 1);
                Ok(())
            },
        );
        ensure!(
            result.is_err() == own
                && observer.borrow().invalidated == own
                && continued.get() == 1
                && !observer.borrow().restoration_allowed(),
            "entry unload association differs"
        );
    }
    for hit in [false, true] {
        for forced in [false, true] {
            let observer = create(image)?;
            if hit {
                observer.borrow_mut().entry_hit(0xfffe0ff1, |entry| {
                    entry.restored = true;
                    entry.changed = false;
                    Ok(())
                })?;
            }
            observer.borrow_mut().stop(7, 11, 5, forced)?;
            let exits = Cell::new(0);
            let continued = Cell::new(0);
            finalize_entry_event(
                &observer,
                Event {
                    kind: 5,
                    unloaded: 0,
                    cleanup: forced,
                },
                |_| anyhow::bail!("EXIT dispatched as exception"),
                || {
                    exits.set(exits.get() + 1);
                    Ok(())
                },
                vec![],
                |status| {
                    ensure!(status == 0x10002, "entry exit continuation differs");
                    continued.set(continued.get() + 1);
                    observer.borrow_mut().continued();
                    Ok(())
                },
            )?;
            ensure!(
                !observer.borrow().alive
                    && !observer.borrow().restoration_allowed()
                    && exits.get() == 1
                    && continued.get() == 1,
                "entry EXIT lifetime differs"
            );
            observer.borrow_mut().destroyed()?;
            let complete = observer.borrow().require_complete().is_ok();
            ensure!(
                complete == (hit && !forced),
                "entry forced/natural completion differs"
            );
            let metadata = observer.borrow().metadata()?;
            ensure!(
                !metadata.contains("private-")
                    && metadata.contains("creator_scope=True")
                    && metadata.contains(&format!("entry_observed={}", b(hit)))
                    && metadata.contains(&format!("restored={}", b(hit)))
                    && metadata.contains(&format!("natural_exit={}", b(!forced)))
                    && metadata.contains("state_destroyed=True")
                    && metadata.contains(&format!("observation_qualified={}", b(complete)))
                    && metadata
                        .ends_with("cause_claimed=False undebugged_equivalence_claimed=False"),
                "entry lifetime metadata differs"
            );
            observer.borrow_mut().stop(7, 11, 6, true)?;
            ensure!(
                !observer.borrow().alive && !observer.borrow().restoration_allowed(),
                "entry dead process resurrected"
            );
        }
    }
    let observer = create(image)?;
    observer.borrow_mut().stop(7, 12, 6, false)?;
    let close = Arc::new(());
    let continuation = Arc::new(());
    let attempts = Cell::new(0);
    let failure = finalize_entry_event(
        &observer,
        Event {
            kind: 6,
            unloaded: 0,
            cleanup: false,
        },
        |_| Ok(()),
        || Ok(()),
        vec![
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                Err(Failure(close.clone()).into())
            }),
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                Ok(())
            }),
        ],
        |_| {
            attempts.set(attempts.get() + 1);
            Err(Failure(continuation.clone()).into())
        },
    )
    .unwrap_err();
    let errors = &failure.downcast_ref::<Failures>().unwrap().errors;
    ensure!(
        observer.borrow().invalidated
            && !observer.borrow().restoration_allowed()
            && attempts.get() == 3
            && errors.len() == 2
            && errors[0]
                .downcast_ref::<Failure>()
                .is_some_and(|f| Arc::ptr_eq(&f.0, &close))
            && errors[1]
                .downcast_ref::<Failure>()
                .is_some_and(|f| Arc::ptr_eq(&f.0, &continuation)),
        "entry event close/continue error precedence differs"
    );
    Ok(())
}
pub fn check_entry_event_validation() -> Result<()> {
    for kind in [2, 4, 6, 7, 8] {
        ensure!(metadata_event(kind), "entry metadata event refused");
    }
    for kind in [0, 1, 3, 5, 9, u32::MAX] {
        ensure!(
            !metadata_event(kind),
            "unqualified entry metadata event accepted"
        );
    }
    let mut ledger = EventCleanup::default();
    let mut handle = 11;
    let mut attempts = 0;
    ensure!(
        ledger
            .close(&mut handle, |_| {
                attempts += 1;
                anyhow::bail!("fixed close")
            })
            .is_err()
            && ledger.require_clean().is_err()
            && handle == 0
            && attempts == 1,
        "entry event close uncertainty lost"
    );
    Ok(())
}
