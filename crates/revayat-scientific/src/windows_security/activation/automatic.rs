//! First process-wide automatic-resource delivery; completion never implies an undebugged result.
use super::{
    Failures,
    csr::thread_checks::{self as contexts, Io, change, get, put, setup},
    dispatch::{execute_trace, finish_trace},
    threads::ObservationState,
};
use anyhow::{Result, ensure};
use std::cell::{Cell, RefCell};
#[path = "automatic_checks.rs"]
mod checks;
pub use checks::check_validation;
fn b(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}
pub fn complete(state: &ObservationState, natural_exit: bool, invalidated: bool) -> bool {
    state.captured
        && state.base_equal
        && state.restored
        && !state.failed
        && natural_exit
        && !invalidated
}
pub fn require_complete(
    state: &ObservationState,
    natural_exit: bool,
    invalidated: bool,
) -> Result<()> {
    ensure!(
        complete(state, natural_exit, invalidated),
        "fixed resource observation incomplete captured={} register_base_equal={} capture_live_restored={} failed={} natural_exit={} invalidated={}",
        b(state.captured),
        b(state.base_equal),
        b(state.restored),
        b(state.failed),
        b(natural_exit),
        b(invalidated)
    );
    Ok(())
}
pub fn metadata(state: &ObservationState, natural_exit: bool, invalidated: bool) -> Result<String> {
    ensure!(
        state.destroyed,
        "fixed resource observation refused check=metadata-destruction"
    );
    let raw = state
        .raw_eax
        .filter(|_| state.captured)
        .map(|v| format!(" raw_eax=0x{v:08X}"))
        .unwrap_or_default();
    let line = format!(
        "WINDOWS_AUTOMATIC_RESOURCE traced=True process_scope=True first_delivery={} captured={} creator={}{raw} register_base_equal={} capture_live_restored={} prior_dead_retired={} retired_count={} enrolled_count={} natural_exit={} state_destroyed=True observation_qualified={}{}{} cause_claimed=False undebugged_equivalence_claimed=False",
        b(state.captured),
        b(state.captured),
        b(state.creator),
        b(state.base_equal),
        b(state.restored),
        state.prior_dead_retired,
        state.retired,
        state.enrolled,
        b(natural_exit),
        b(complete(state, natural_exit, invalidated)),
        state.traps,
        state.software
    );
    ensure!(
        line.len() <= 1024,
        "fixed resource observation refused check=resource-metadata-budget"
    );
    Ok(line)
}
pub(crate) fn resource_trap(io: &Io, h: usize, base: u64) {
    let mut memory = io.0.borrow_mut();
    let c = memory.contexts.get_mut(&h).unwrap();
    for (at, value) in [
        (104, 0xffff0ff1),
        (112, 0x401),
        (120, 0x12345678c0000022),
        (176, base),
        (248, 0x8000),
    ] {
        put(c, at, value);
    }
}
pub(crate) fn arm(r: &mut super::threads::ResourceThreads<Io>) -> Result<()> {
    r.stop(7, 11, 6, false)?;
    r.arm(0x8000)?;
    r.continued()
}
pub(crate) fn resource_checks() -> Result<()> {
    let io = Io::default();
    io.0.borrow_mut()
        .contexts
        .insert(11, vec![0; super::CONTEXT_SIZE]);
    let mut r = super::threads::ResourceThreads::new(7, 11, io.clone())?;
    ensure!(
        r.enroll(11, &mut 11, false).is_err()
            && io.0.borrow().reads == 0
            && io.0.borrow().writes == 0,
        "resource queried before stopped epoch"
    );
    r.stop(7, 11, 3, false)?;
    r.enroll(11, &mut 11, false)?;
    r.continued()?;
    ensure!(
        r.arm(0x8000).is_err() && io.0.borrow().writes == 0,
        "resource armed without event"
    );
    arm(&mut r)?;
    ensure!(
        get(&io.0.borrow().contexts[&11], 72) == 0x8000 && io.0.borrow().writes == 1,
        "resource creator not armed"
    );
    io.0.borrow_mut()
        .contexts
        .insert(12, vec![0; super::CONTEXT_SIZE]);
    r.stop(7, 12, 2, false)?;
    r.enroll(12, &mut 12, true)?;
    r.continued()?;
    ensure!(
        get(&io.0.borrow().contexts[&12], 72) == 0x8000 && io.0.borrow().writes == 2,
        "resource peer not armed"
    );
    resource_trap(&io, 12, 0x10000000);
    r.stop(7, 12, 1, false)?;
    r.capture(12, true, 0x8000, 0x10000000)?;
    let state = r.observation();
    ensure!(
        state.captured
            && state.restored
            && state.raw_eax == Some(0xc0000022)
            && state.base_equal
            && !state.creator
            && io.0.borrow().writes == 4
            && get(&io.0.borrow().contexts[&12], 120) == 0x12345678c0000022
            && get(&io.0.borrow().contexts[&12], 176) == 0x10000000
            && get(&io.0.borrow().contexts[&12], 248) == 0x8000,
        "resource capture damaged integer/control or outcome"
    );
    ensure!(
        r.capture(12, true, 0x8000, 0x10000000).is_err(),
        "resource first capture repeated"
    );
    r.continued()?;
    r.stop(7, 12, 4, false)?;
    r.continued()?;
    ensure!(
        io.0.borrow().closed == [12],
        "resource peer retirement differs"
    );
    contexts::die(&mut r, false)?;
    ensure!(
        r.observation().restored && r.observation().destroyed,
        "resource destruction state differs"
    );
    let (mut r, io) = setup(1, 0)?;
    for index in 0..127 {
        let id = 20 + index;
        io.0.borrow_mut()
            .contexts
            .insert(id, vec![0; super::CONTEXT_SIZE]);
        r.stop(7, id as u32, 2, false)?;
        let mut handle = id;
        r.enroll(id as u32, &mut handle, true)?;
        r.continued()?;
        r.stop(7, id as u32, 4, false)?;
        r.continued()?;
    }
    r.stop(7, 200, 2, false)?;
    ensure!(
        r.enroll(200, &mut 200, true).is_err() && r.enrolled() == 128,
        "resource lifetime capacity refunded"
    );
    let (mut r, io) = setup(2, 0)?;
    r.stop(7, 12, 4, false)?;
    r.continued()?;
    io.0.borrow_mut()
        .contexts
        .insert(13, vec![0; super::CONTEXT_SIZE]);
    r.stop(7, 12, 2, false)?;
    r.enroll(12, &mut 13, true)?;
    r.continued()?;
    ensure!(
        r.enrolled() == 3
            && r.observation().retired == 1
            && r.observation().prior_dead_retired == 1,
        "resource TID generation reuse differs"
    );
    for mismatch in [false, true] {
        let (mut r, io) = setup(1, 0)?;
        arm(&mut r)?;
        resource_trap(&io, 11, if mismatch { 0x20000000 } else { 0x10000000 });
        r.stop(7, 11, 1, false)?;
        ensure!(
            r.capture(11, true, 0x8000, 0x10000000).is_err() == mismatch
                && r.captured()
                && r.capture_restored()
                && r.observation().base_equal != mismatch,
            "resource first equality mismatch did not consume capture"
        );
    }
    let (mut r, io) = setup(2, 0)?;
    arm(&mut r)?;
    io.0.borrow_mut().fail_restore = Some(11);
    resource_trap(&io, 11, 0x10000000);
    r.stop(7, 11, 1, false)?;
    let writes = io.0.borrow().writes;
    ensure!(
        r.capture(11, true, 0x8000, 0x10000000).is_err()
            && io.0.borrow().writes == writes + 2
            && !r.capture_restored(),
        "resource independent restore omitted"
    );
    {
        let mut m = io.0.borrow_mut();
        m.contexts.get_mut(&11).unwrap()[72..120].fill(0);
    }
    ensure!(
        r.software(11, true).is_err(),
        "resource failed restore accepted software"
    );
    r.continued()?;
    ensure!(
        contexts::die(&mut r, true).is_err() && r.failed() && !r.capture_restored(),
        "resource uncertainty cleared by death"
    );
    let reads = io.0.borrow().reads;
    r.stop(7, 11, 6, true)?;
    r.restore_all()?;
    ensure!(io.0.borrow().reads == reads, "resource queried after death");
    prearm()?;
    software_presentation()?;
    refusal()?;
    finalization()?;
    let (mut r, _) = setup(1, 0)?;
    ensure!(
        r.stop(8, 11, 6, false).is_err() && r.enroll(11, &mut 11, false).is_err(),
        "unsupported resource event retained authority"
    );
    Ok(())
}
fn prearm() -> Result<()> {
    for variant in 0..5 {
        let (mut r, io) = setup(1, 0)?;
        if variant == 1 {
            change(&io, 11, 104, 0x10);
        }
        r.stop(7, 11, 1, false)?;
        let first = r.software(if variant == 2 { 12 } else { 11 }, variant != 3);
        let rejected = if first.is_err() {
            true
        } else if variant == 4 {
            r.software(11, true).is_err()
        } else {
            false
        };
        ensure!(
            rejected == (variant != 0) && io.0.borrow().writes == 0 && !r.captured(),
            "resource prearm software product differs"
        );
        if variant == 0 {
            r.continued()?;
            r.stop(7, 11, 6, false)?;
            r.arm(0x8000)?;
            ensure!(
                io.0.borrow().writes == 1,
                "resource software snapshot prevented later arm"
            );
        }
    }
    for captured in [false, true] {
        for canonical in [false, true] {
            let (mut r, io) = setup(1, 0)?;
            arm(&mut r)?;
            if captured {
                resource_trap(&io, 11, 0x10000000);
                r.stop(7, 11, 1, false)?;
                r.capture(11, true, 0x8000, 0x10000000)?;
                r.continued()?;
            }
            change(&io, 11, 104, if captured { 0x10 } else { 0 });
            change(&io, 11, 112, 0);
            r.stop(7, 11, 1, false)?;
            ensure!(
                r.software(11, true).is_err(),
                "resource incomplete software state accepted"
            );
            if captured {
                let writes = io.0.borrow().writes;
                change(&io, 11, 104, if canonical { 0xffff0ff0 } else { 0 });
                r.software(11, true)?;
                ensure!(
                    io.0.borrow().writes == writes && r.software(11, true).is_err(),
                    "restored resource software altered state/repeated"
                );
            } else {
                change(&io, 11, 104, 0xffff0ff0);
                change(&io, 11, 112, 0x401);
                r.software(11, true)?;
            }
        }
    }
    Ok(())
}
fn software_presentation() -> Result<()> {
    for status in [0xfffe07f0, 0xfffe0ff0, 0xffff07f0, 0xffff0ff0] {
        for fixed in [0, 0x400] {
            let (mut r, io) = setup(1, 0)?;
            arm(&mut r)?;
            change(&io, 11, 104, status);
            change(&io, 11, 112, 1 | fixed);
            r.stop(7, 11, 1, false)?;
            r.software(11, true)?;
            let first = r.observation().software;
            ensure!(
                io.0.borrow().writes == 1
                    && !r.captured()
                    && !r.capture_restored()
                    && first.contains(&format!("software_raw_dr6=0x{status:016X}"))
                    && first.contains("software_origin_verified=False"),
                "resource software snapshot differs"
            );
            change(&io, 11, 104, status ^ 0x10800);
            ensure!(
                r.software(11, true).is_err() && r.observation().software == first,
                "resource software snapshot replaced"
            );
            let mut state = r.observation();
            state.destroyed = true;
            let line = metadata(&state, false, false)?;
            ensure!(
                line.len() <= 1024
                    && line.contains(&first)
                    && line.contains("observation_qualified=False")
                    && !line.contains("private-")
                    && require_complete(&state, false, false).is_err(),
                "software alone qualified automatic resource"
            );
            r.continued()?;
            resource_trap(&io, 11, 0x10000000);
            r.stop(7, 11, 1, false)?;
            r.capture(11, true, 0x8000, 0x10000000)?;
            r.continued()?;
            contexts::die(&mut r, false)?;
            let state = r.observation();
            require_complete(&state, true, false)?;
            let line = metadata(&state, true, false)?;
            ensure!(
                line.contains(&first)
                    && line.contains("raw_dr6=0x00000000FFFF0FF1")
                    && line.contains("observation_qualified=True")
                    && io.0.borrow().writes == 2,
                "resource natural completed metadata differs"
            );
        }
    }
    Ok(())
}
fn refusal() -> Result<()> {
    let (mut r, io) = setup(1, 0)?;
    ensure!(
        r.arm(0x8000).unwrap_err().to_string()
            == "fixed resource observation refused check=arm-state",
        "resource refusal check differs"
    );
    arm(&mut r)?;
    resource_trap(&io, 11, 0x20000000);
    r.stop(7, 11, 1, false)?;
    ensure!(
        r.capture(11, true, 0x8000, 0x10000000)
            .unwrap_err()
            .to_string()
            == "fixed resource observation refused check=first-base-equality"
            && r.captured()
            && r.capture_restored()
            && r.failed()
            && !r.observation().base_equal
            && get(&io.0.borrow().contexts[&11], 72) == 0,
        "resource mismatch refusal state differs"
    );
    let (r, _) = setup(1, 0)?;
    ensure!(
        require_complete(&r.observation(), false, false)
            .unwrap_err()
            .to_string()
            == "fixed resource observation incomplete captured=False register_base_equal=False capture_live_restored=False failed=False natural_exit=False invalidated=False",
        "resource incomplete metadata differs"
    );
    let (mut r, io) = setup(1, 0)?;
    arm(&mut r)?;
    change(&io, 11, 104, 0xfffe17f0);
    change(&io, 11, 112, 0x401);
    r.stop(7, 11, 1, false)?;
    ensure!(
        r.software(11, true).unwrap_err().to_string()
            == "fixed resource observation refused check=software-control-ownership raw_dr6=0x00000000FFFE17F0 rtm_bit_set=False bld_bit_set=False transaction_context=unknown raw_dr7=0x0000000000000401",
        "resource software refusal metadata differs"
    );
    Ok(())
}
fn finalization() -> Result<()> {
    use super::event_lifecycle::{ResourceContinuation, finalize_resource_cleanup};
    use crate::windows_security::scratch::SharedError;
    let mut continuation = ResourceContinuation::default();
    let failure: SharedError = std::sync::Arc::new(std::io::Error::other("fixed continue failure"));
    let attempts = Cell::new(0);
    let original = continuation
        .run(|| {
            attempts.set(attempts.get() + 1);
            Err(failure.clone())
        })
        .unwrap_err();
    continuation
        .run(|| {
            attempts.set(attempts.get() + 1);
            Ok(())
        })
        .map_err(|error| anyhow::anyhow!("resource continuation retry failed: {error}"))?;
    let final_error = continuation.require_clean().unwrap_err();
    ensure!(
        attempts.get() == 2 && std::sync::Arc::ptr_eq(&original, &failure),
        "resource continuation first failure lost"
    );
    let emitted = Cell::new(0);
    let later = Cell::new(0);
    let carrier = finish_trace(
        Some(anyhow::anyhow!("fixed continue failure")),
        vec![final_error],
        true,
        true,
        || Ok("fixed".into()),
        |_| {
            emitted.set(emitted.get() + 1);
            Ok(())
        },
    )
    .unwrap_err();
    ensure!(
        execute_trace(
            || Err(carrier),
            || {
                later.set(later.get() + 1);
                Ok(())
            }
        )
        .is_err()
            && emitted.get() == 0
            && later.get() == 0,
        "uncertain resource continuation qualified later work"
    );
    let (mut r, io) = setup(1, 0)?;
    arm(&mut r)?;
    r.stop(7, 11, 8, true)?;
    let owner = RefCell::new(r);
    let order = RefCell::new(Vec::new());
    finalize_resource_cleanup(
        || {
            order.borrow_mut().push("invalidate");
            owner.borrow_mut().invalidate();
            Ok(())
        },
        || {
            order.borrow_mut().push("restore");
            owner.borrow_mut().restore_all()
        },
        || {
            order.borrow_mut().push("exit");
            Ok(())
        },
        false,
        vec![Box::new(|| {
            order.borrow_mut().push("close");
            Ok(())
        })],
        || {
            order.borrow_mut().push("continue");
            owner.borrow_mut().continued()
        },
    )?;
    ensure!(
        io.0.borrow().writes == 2
            && get(&io.0.borrow().contexts[&11], 72) == 0
            && order.borrow().as_slice() == ["invalidate", "restore", "close", "continue"],
        "resource finalization order differs"
    );
    Ok(())
}
