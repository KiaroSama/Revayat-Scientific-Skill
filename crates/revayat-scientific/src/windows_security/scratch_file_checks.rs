//! Full original fixed create-only request, outcome and cleanup fault matrix.
use super::{Failures, failure, file::*, volume};
use anyhow::{Result, ensure};
use std::{cell::Cell, sync::Arc};

pub fn check_file_creation_validation() -> Result<()> {
    let count = volume::MASKS.len();
    let mut policy = vec![0; 2 + count * 5];
    policy[2..2 + count].fill(volume::DENIED);
    for file_error in [0, 5] {
        let result = file_policy_result(&policy, &[0, file_error])?;
        ensure!(
            result.len() == policy.len() + 2 && !reject_file_policy(&result)?,
            "scratch file policy shape or rejection differs"
        );
        for phase in ["baseline", "modified", "restored"] {
            let frames = file_policy_frames(phase, &result)?;
            ensure!(
                frames.len() == count + 2
                    && frames[count].contains(&format!("phase={phase} role=host opened=True"))
                    && frames[count + 1].contains(&format!(
                        "phase={phase} role=lpac opened={}",
                        super::truth(file_error == 0)
                    )),
                "scratch file policy frame phase/role differs"
            );
        }
        for index in 1..count {
            let mut changed = result.clone();
            changed[2 + index] = 0;
            changed[2 + count + index] = volume::MASKS[index] as i32;
            ensure!(
                reject_file_policy(&changed)? == (volume::MASKS[index] & 0xc0003 != 0),
                "scratch file policy failed to reject volume data or security authority"
            );
        }
    }
    for errors in [vec![], vec![0], vec![5, 5], vec![0, 2]] {
        ensure!(
            file_policy_result(&policy, &errors).is_err(),
            "scratch file policy accepted invalid host/LPAC creation result"
        );
    }
    for mode in 0..9 {
        let enters = Cell::new(0);
        let leaves = Cell::new(0);
        let closes = Cell::new(0);
        let deletes = Cell::new(0);
        let absences = Cell::new(0);
        let original = failure("fixed create failure");
        let cleanup = failure("fixed close failure");
        let result = file_creation(
            false,
            FileCalls {
                create: &mut |value| {
                    if mode == 1 {
                        value.handle = usize::MAX;
                        value.error = 5;
                        return Ok(());
                    }
                    value.handle = 17;
                    if mode == 2 {
                        return Err(original.clone());
                    }
                    if mode == 8 {
                        value.error = 5;
                    }
                    Ok(())
                },
                enter: &mut || {
                    enters.set(enters.get() + 1);
                    Ok(())
                },
                check: &mut || {
                    if mode == 3 {
                        Err(original.clone())
                    } else {
                        Ok(())
                    }
                },
                leave: &mut || leaves.set(leaves.get() + 1),
                bind: &mut |_| {
                    if mode == 4 {
                        Err(original.clone())
                    } else {
                        Ok(())
                    }
                },
                close: &mut |handle| {
                    super::need(handle == 17)?;
                    closes.set(closes.get() + 1);
                    if mode == 5 || mode == 2 {
                        Err(cleanup.clone())
                    } else {
                        Ok(())
                    }
                },
                remove: &mut |_| {
                    deletes.set(deletes.get() + 1);
                    if mode == 6 {
                        Err(cleanup.clone())
                    } else {
                        Ok(())
                    }
                },
                absent: &mut || {
                    absences.set(absences.get() + 1);
                    if mode == 7 {
                        Err(original.clone())
                    } else {
                        Ok(())
                    }
                },
                release: &mut |_| Ok(()),
            },
        );
        ensure!(
            enters.get() == if mode == 7 { 0 } else { 1 } && leaves.get() == enters.get(),
            "scratch file identity restoration ordering differs mode={mode}"
        );
        ensure!(
            closes.get() == if matches!(mode, 1 | 3 | 7) { 0 } else { 1 },
            "scratch file did not close every acquired handle mode={mode}"
        );
        ensure!(
            deletes.get() == usize::from(matches!(mode, 0 | 6 | 8)),
            "scratch file removed an unbound/unclosed object mode={mode}"
        );
        ensure!(
            result.is_ok() == matches!(mode, 0 | 1),
            "scratch file failure was swallowed mode={mode}"
        );
        if mode == 1 {
            ensure!(
                result.unwrap() == 5 && absences.get() == 2,
                "scratch denied create was not requalified absent"
            );
        } else if mode == 2 {
            let error = result.unwrap_err();
            let group = error.downcast_ref::<Failures>().unwrap();
            ensure!(
                group.errors.len() == 2
                    && Arc::ptr_eq(&group.errors[0], &original)
                    && Arc::ptr_eq(&group.errors[1], &cleanup),
                "scratch file lost independent create/close error identities"
            );
        }
    }
    for attributes in [0, 0x10, 0x400, u32::MAX] {
        for error in [0, 2, 3, 5] {
            ensure!(
                require_file_absent(attributes, error).is_err()
                    == (attributes != u32::MAX || error != 2),
                "scratch file absence accepted a directory/reparse or unknown error"
            );
        }
    }
    for handle in [0, usize::MAX, 17] {
        let errors = Cell::new(0);
        let calls = Cell::new(0);
        let request_qualified = Cell::new(false);
        let mut value = FileObservation::default();
        file_create_request(
            "fixed-leaf",
            &mut value,
            |request| {
                calls.set(calls.get() + 1);
                request_qualified.set(
                    request.path == "fixed-leaf"
                        && request.access == 0x40000000
                        && request.share == 3
                        && request.security == 0
                        && request.disposition == 1
                        && request.flags == 0x80
                        && request.template == 0,
                );
                handle
            },
            || {
                errors.set(errors.get() + 1);
                5
            },
        );
        let valid = super::valid_handle(handle);
        ensure!(
            calls.get() == 1
                && request_qualified.get()
                && value.handle == handle
                && errors.get() == usize::from(!valid)
                && value.error == if valid { 0 } else { 5 },
            "scratch file request read stale error or changed native output"
        );
    }
    for host in [false, true] {
        for error in [0, 2, 5, 80, 183] {
            let result = file_creation(
                host,
                FileCalls {
                    create: &mut |value| {
                        value.handle = usize::MAX;
                        value.error = error;
                        Ok(())
                    },
                    enter: &mut || Ok(()),
                    check: &mut || Ok(()),
                    leave: &mut || {},
                    bind: &mut |_| Ok(()),
                    close: &mut |_| Ok(()),
                    remove: &mut |_| Ok(()),
                    absent: &mut || Ok(()),
                    release: &mut |_| Ok(()),
                },
            );
            ensure!(
                result.is_err() == (host || error != 5),
                "scratch file accepted an unqualified native failure for its role"
            );
        }
    }
    Ok(())
}
