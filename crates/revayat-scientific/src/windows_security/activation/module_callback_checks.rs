//! Frozen CheckModuleCallbackValidation products; portable assertions create no native receipt.
use super::*;
use crate::windows_security::activation::{
    CONTEXT_SIZE, boundary::check_io::*, raw_debug_equal, unchanged_control_integer,
};
use std::cell::RefCell;

pub fn check_validation() -> Result<()> {
    let mut context = vec![0; CONTEXT_SIZE];
    for (value, expected) in [0, 1, 0xffffffff, 0x12345678ffffffff, u64::MAX]
        .into_iter()
        .zip([false, false, false, false, true])
    {
        software::put(&mut context, 120, value)?;
        software::put(&mut context, 144, u64::MAX)?;
        ensure!(
            callback_result(&context)?
                == format!(
                    "failure_sentinel={}",
                    if expected { "True" } else { "False" }
                ),
            "callback sentinel lost full width"
        );
    }
    let baseline = baseline()?;
    let mut current = baseline.clone();
    for (at, value) in [
        (120, u64::MAX),
        (128, 0x12345678),
        (152, 0x5000),
        (248, 0x8000),
    ] {
        software::put(&mut current, at, value)?;
    }
    let armed = software::desired(&current, &baseline, &[0x8000, 0], &[true, false], false)?;
    let restored = software::desired(&armed, &baseline, &[0; 2], &[false; 2], true)?;
    ensure!(
        software::value(&armed, 72)? == 0x8000
            && software::value(&armed, 80)? == 0
            && software::value(&armed, 112)? == 0x401
            && raw_debug_equal(&restored, &baseline)?
            && unchanged_control_integer(&current, &restored)?
            && software::value(&restored, 120)? == u64::MAX
            && software::value(&restored, 248)? == 0x8000
            && !unchanged_control_integer(&baseline, &restored)?,
        "callback restoration changed current integer state"
    );
    for state in [1, 2, 3] {
        let mut observer = observer(BoundaryMode::ModuleCallback, |_| Ok(()))?;
        observer.stage = state;
        observer.original = Some(baseline.clone());
        observer.restored = state == 3;
        ensure!(
            complete(state, observer.restored, false) == (state == 3)
                && !complete(state, false, false)
                && !complete(state, true, true),
            "callback completion products differ"
        );
        ensure!(
            observer.callback_software_stage(11, 0x80000003, true)
                && !observer.callback_software_stage(12, 0x80000003, true)
                && !observer.callback_software_stage(11, 0x80000003, false)
                && !observer.callback_software_stage(11, 0x80000004, true),
            "callback software stage differs"
        );
        initial(&mut observer)?;
        ensure!(
            !observer.callback_software_stage(11, 0x80000003, true),
            "duplicate callback software stop admitted"
        );
        observer.software = software::SoftwarePresentation::default();
        observer.kernel = Some(kernel());
        ensure!(
            observer.callback_hardware_stage(11, true) == (state == 2)
                && !observer.callback_hardware_stage(12, true)
                && !observer.callback_hardware_stage(11, false),
            "callback hardware stage differs"
        );
        observer.invalidated = true;
        ensure!(
            !observer.callback_hardware_stage(11, true)
                && !observer.callback_software_stage(11, 0x80000003, true),
            "invalidated callback stage admitted"
        );
        observer.invalidated = false;
        observer.kernel = None;
        observer.stopped = true;
        ensure!(
            observer.callback_load_stage() == (state == 1),
            "callback LOAD stage differs"
        );
        observer.changed = true;
        ensure!(
            !observer.callback_load_stage(),
            "changed callback LOAD admitted"
        );
        observer.changed = false;
        observer.stopped = false;
        ensure!(
            !observer.callback_load_stage(),
            "running callback LOAD admitted"
        );
        observer.stopped = true;
        observer.alive = false;
        ensure!(
            !observer.callback_load_stage(),
            "dead callback LOAD admitted"
        );
        observer.alive = true;
        if state == 2 {
            observer.addresses[0] = 0x8000;
            observer.enabled[0] = true;
        }
        let mut presented = software::desired(
            &current,
            &baseline,
            &observer.addresses,
            &observer.enabled,
            state == 3,
        )?;
        software::put(&mut presented, 104, 0xffff0ff0)?;
        observer.ownership(&presented, false)?;
        for offset in [72, 80, 88, 96] {
            let mut foreign = presented.clone();
            software::put(&mut foreign, offset, 0x9999)?;
            ensure!(
                observer.ownership(&foreign, false).is_err(),
                "callback foreign debug address admitted"
            );
        }
        ensure!(
            observer.require_complete().is_err() == (state != 3),
            "callback require-complete differs"
        );
        ensure!(
            observer.stop(7, 12, 6, false).is_err()
                && observer.invalidated
                && observer.io.reads.get() == 0,
            "callback foreign transition admitted/accessed context"
        );
    }
    for state in [0, 4] {
        let mut observer = observer(BoundaryMode::ModuleCallback, |_| Ok(()))?;
        observer.stage = state;
        observer.original = Some(baseline.clone());
        observer.stopped = true;
        ensure!(
            !observer.callback_software_stage(11, 0x80000003, true)
                && !observer.callback_hardware_stage(11, true)
                && !observer.callback_load_stage()
                && !complete(state, true, false),
            "outside callback stage admitted"
        );
    }
    check_load_ownership_reporting()?;
    crate::windows_security::image::check_module_callback_profile_validation()?;
    transport_checks::check_peer_transport()?;
    transport_checks::check_lifecycle_transport()?;
    drain_checks::check_drain()?;
    transport_checks::check_header()
}
fn check_load_ownership_reporting() -> Result<()> {
    let report = RefCell::new(None);
    let mut o = observer(BoundaryMode::ModuleCallback, |line| {
        *report.borrow_mut() = Some(line.to_owned());
        Ok(())
    })?;
    let baseline = baseline()?;
    o.original = Some(baseline.clone());
    o.stage = 1;
    o.callback_load_ownership(&baseline)?;
    let mut foreign = baseline.clone();
    software::put(&mut foreign, 72, 0x9999)?;
    ensure!(
        o.callback_load_ownership(&foreign).is_err() && report.borrow().is_none(),
        "pre-initial LOAD accepted changed raw baseline or reported software ownership"
    );
    initial(&mut o)?;
    let mut presented = baseline;
    software::put(&mut presented, 104, 0xffff0ff0)?;
    o.callback_load_ownership(&presented)?;
    software::put(&mut presented, 72, 0x9999)?;
    ensure!(
        o.callback_load_ownership(&presented).is_err()
            && report.borrow().as_deref().is_some_and(|line| line
                .starts_with("phase=activation-refusal check=software-address-ownership stage=1 ")
                && line.contains("context_read=True"))
            && o.io.reads.get() == 0,
        "post-initial LOAD lost typed refusal metadata or read native context"
    );
    Ok(())
}
