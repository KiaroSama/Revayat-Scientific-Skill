use super::super::super::{
    CONTEXT_SIZE, activation_event,
    dispatch::{DispatchRegion, DispatchTarget},
    raw_debug_equal,
};
use super::*;
pub(super) fn check() -> Result<()> {
    failures()?;
    selected_bus_lock()?;
    restore_drift()?;
    setter_readback()?;
    peer_refusals()?;
    reads()?;
    generations()?;
    metadata()?;
    queued_peer()?;
    refusal_reporting()
}
fn failures() -> Result<()> {
    for mode in 0..12 {
        let (mut r, io) = setup(2, 0)?;
        arm(&mut r)?;
        trap(&io, 11, false);
        match mode {
            0 => change(&io, 11, 184, 0),
            1 => change(&io, 11, 104, 0xffff0ff3),
            2 => change(&io, 11, 112, 0xc05),
            3 => change(&io, 12, 72, 0x9999),
            4 => {
                change(&io, 11, 104, 0xffff0ff2);
                change(&io, 11, 248, 0x8007);
            }
            _ => {}
        }
        r.stop(7, 11, 1, false)?;
        let mut targets = 0;
        if mode <= 4 || mode >= 10 {
            ensure!(
                r.capture_dispatch(
                    11,
                    mode != 10,
                    if mode == 4 { 0x8007 } else { 0x8000 },
                    || {
                        targets += 1;
                        ensure!(mode != 11, "fixed target mismatch");
                        Ok(())
                    }
                )
                .is_err(),
                "CSR bad first delivery accepted"
            );
        } else {
            r.capture_dispatch(11, true, 0x8000, || {
                targets += 1;
                Ok(())
            })?;
            r.continued()?;
            trap(&io, 11, true);
            match mode {
                5 => change(&io, 11, 152, 0x8f00),
                6 => change(&io, 11, 248, 0x8008),
                7 => change(&io, 11, 104, 0xfffe2ff2),
                8 => change(&io, 11, 72, 0x8000),
                _ => {}
            }
            let id = if mode == 9 { 12 } else { 11 };
            r.stop(7, id, 1, false)?;
            ensure!(
                r.capture_dispatch(id, true, 0x8007, || Ok(())).is_err(),
                "CSR wrong return accepted"
            );
        }
        ensure!(
            r.failed() && !r.captured() && r.capture_dispatch(11, true, 0x8007, || Ok(())).is_err(),
            "CSR first refusal was recoverable"
        );
        let expected = [1, 2, 3, 6, 7, 8, 9].contains(&mode);
        let writes = io.0.borrow().writes;
        ensure!(
            r.restore_all().is_err() == expected
                && io.0.borrow().writes - writes == if expected { 1 } else { 2 },
            "CSR safe restore attempts differ mode={mode}"
        );
        r.continued()?;
        ensure!(
            die(&mut r, true).is_err() == expected
                && r.failed()
                && r.observation().destroyed
                && !r.capture_restored()
                && targets <= 1,
            "CSR uncertainty disappeared mode={mode}"
        );
    }
    for close_failure in [false, true] {
        let (mut r, io) = setup(2, 0)?;
        arm(&mut r)?;
        if close_failure {
            io.0.borrow_mut().fail_close = true;
        } else {
            io.0.borrow_mut().fail_restore = Some(11);
        }
        r.stop(7, 11, 8, true)?;
        ensure!(
            r.restore_all().is_err() != close_failure,
            "CSR restore failure product differs"
        );
        r.continued()?;
        ensure!(
            die(&mut r, true).is_err()
                && r.failed()
                && r.observation().destroyed
                && io.0.borrow().closes == 1,
            "CSR close uncertainty disappeared"
        );
    }
    Ok(())
}
fn selected_bus_lock() -> Result<()> {
    for creator in [false, true] {
        for post in [false, true] {
            let (mut r, io) = setup(2, 0)?;
            arm(&mut r)?;
            let h = if creator { 11 } else { 12 };
            if post {
                capture(&mut r, &io, h, false)?;
            }
            trap(&io, h, post);
            change(&io, h, 104, if post { 0xfffe07f2 } else { 0xffff07f1 });
            r.stop(7, h as u32, 1, false)?;
            let writes = io.0.borrow().writes;
            ensure!(
                r.capture_dispatch(
                    h as u32,
                    true,
                    if post { 0x8007 } else { 0x8000 },
                    || Ok(())
                )
                .is_err()
                    && io.0.borrow().writes == writes
                    && r.failed()
                    && !r.captured(),
                "CSR selected bus-lock accepted"
            );
            trap(&io, h, post);
            ensure!(
                r.capture_dispatch(
                    h as u32,
                    true,
                    if post { 0x8007 } else { 0x8000 },
                    || Ok(())
                )
                .is_err()
                    && io.0.borrow().writes == writes,
                "CSR bus-lock retry accepted"
            );
            r.restore_all()?;
            r.continued()?;
            die(&mut r, true)?;
            ensure!(
                r.failed() && !r.capture_restored(),
                "CSR bus-lock failure cleared"
            );
        }
    }
    Ok(())
}
fn restore_drift() -> Result<()> {
    for offset in [72, 112] {
        let (mut r, io) = setup(2, 0)?;
        arm(&mut r)?;
        capture(&mut r, &io, 11, false)?;
        change(&io, 12, offset, 0x9999);
        trap(&io, 11, true);
        r.stop(7, 11, 1, false)?;
        let writes = io.0.borrow().writes;
        ensure!(
            r.capture_dispatch(11, true, 0x8007, || Ok(())).is_err()
                && r.failed()
                && !r.capture_restored()
                && io.0.borrow().writes == writes + 1,
            "CSR restore drift touched foreign peer"
        );
        r.continued()?;
        ensure!(
            die(&mut r, true).is_err(),
            "CSR restore drift uncertainty disappeared"
        );
    }
    Ok(())
}
fn setter_readback() -> Result<()> {
    for offset in [72, 80, 88, 96, 104, 112, 120, 248, -1] {
        let (mut r, io) = setup(1, 0)?;
        io.0.borrow_mut().drift.insert(
            1,
            if offset < 0 {
                vec![104, 248]
            } else {
                vec![offset as usize]
            },
        );
        r.stop(7, 11, 6, false)?;
        let refusal = r.arm_dispatch(0x8000, 0x8007).unwrap_err().to_string();
        let expected = format!(
            "fixed resource observation refused check=setter-readback snapshot=first phase=arm event_kind=6 event_thread_equal=True debug_equal={} control_integer_equal={} dr0_equal={} dr1_equal={} dr2_equal={} dr3_equal={} dr6_equal={} dr7_equal={} desired_dr6=0x0000000000000000 current_dr6=0x{} desired_dr7=0x0000000000000005 current_dr7=0x{}",
            b(offset == 120 || offset == 248),
            b((72..=112).contains(&offset)),
            b(offset != 72),
            b(offset != 80),
            b(offset != 88),
            b(offset != 96),
            b(offset != 104 && offset != -1),
            b(offset != 112),
            if offset == 104 || offset == -1 {
                "0000000000000001"
            } else {
                "0000000000000000"
            },
            if offset == 112 {
                "0000000000000004"
            } else {
                "0000000000000005"
            }
        );
        ensure!(
            refusal == expected
                && refusal.len() <= 1024
                && refusal.is_ascii()
                && !refusal.contains("000000000000800")
                && !refusal.contains("0000000000009000")
                && io.0.borrow().writes == 1
                && r.failed(),
            "CSR exact setter refusal differs offset={offset}"
        );
        let error = r.restore_all().unwrap_err();
        ensure!(
            error.to_string().contains("count=1") && io.0.borrow().writes == 1,
            "CSR unconfirmed setter retried write"
        );
        r.continued()?;
        ensure!(
            die(&mut r, true).is_err() && r.observation().destroyed,
            "CSR setter uncertainty cleared"
        );
    }
    for restore_drift in [false, true] {
        let (mut r, io) = setup(2, 0)?;
        io.0.borrow_mut().drift.insert(2, vec![104]);
        if restore_drift {
            io.0.borrow_mut().drift.insert(3, vec![104]);
        }
        r.stop(7, 11, 6, false)?;
        let first = r.arm_dispatch(0x8000, 0x8007).unwrap_err().to_string();
        ensure!(
            first.contains("snapshot=first phase=arm event_kind=6 event_thread_equal=False")
                && io.0.borrow().writes == 2,
            "CSR peer setter attribution differs"
        );
        ensure!(
            r.restore_all().is_err() && io.0.borrow().writes == 3,
            "CSR independent safe restore omitted"
        );
        if !restore_drift {
            ensure!(
                raw_debug_equal(&vec![0; CONTEXT_SIZE], &io.0.borrow().contexts[&11])?,
                "CSR safe creator restore differs"
            );
        }
        r.continued()?;
        ensure!(
            die(&mut r, true).is_err() && io.0.borrow().closes == 1,
            "CSR mixed setter cleanup disappeared"
        );
    }
    Ok(())
}
fn peer_refusals() -> Result<()> {
    let mut changes = vec![];
    for at in [72, 80, 88, 96] {
        changes.push((at, 0x9999));
    }
    for bit in [1, 2, 4, 8, 0x1000, 0x2000, 0x4000, 0x8000, 0x100000000] {
        changes.push((104, 0xffff0ff0 | bit));
    }
    changes.extend([(104, 0xffff0fe0), (104, 0xffff0fb0)]);
    for bit in [
        2,
        8,
        0x10,
        0x20,
        0x40,
        0x80,
        0x100,
        0x200,
        0x800,
        0x1000,
        0x2000,
        0x10000,
        0x40000,
        0x100000000,
    ] {
        changes.push((112, 0x405 | bit));
    }
    for (at, value) in changes {
        let (mut r, io) = setup(2, 0)?;
        arm(&mut r)?;
        change(&io, 12, 104, 0xffff0ff0);
        change(&io, 12, 112, 0x405);
        change(&io, 12, at, value);
        trap(&io, 11, false);
        r.stop(7, 11, 1, false)?;
        let writes = io.0.borrow().writes;
        ensure!(
            r.capture_dispatch(11, true, 0x8000, || Ok(())).is_err()
                && io.0.borrow().writes == writes + 1
                && get(&io.0.borrow().contexts[&12], at) == value
                && r.failed(),
            "CSR foreign peer overwritten"
        );
        let _ = r.restore_all();
        ensure!(
            get(&io.0.borrow().contexts[&12], at) == value,
            "CSR cleanup overwrote foreign peer"
        );
        r.continued()?;
        ensure!(
            die(&mut r, true).is_err() && !r.capture_restored(),
            "CSR peer uncertainty cleared"
        );
    }
    for mode in 0..5 {
        let (mut r, io) = setup(2, 0)?;
        arm(&mut r)?;
        if mode < 2 {
            r.stop(7, 11, if mode == 0 { 6 } else { 1 }, false)?;
            let reads = io.0.borrow().reads;
            let writes = io.0.borrow().writes;
            ensure!(
                r.capture_dispatch(if mode == 0 { 11 } else { 12 }, true, 0x8000, || Ok(()))
                    .is_err()
                    && io.0.borrow().reads == reads
                    && io.0.borrow().writes == writes,
                "CSR wrong event accessed context"
            );
        } else {
            capture(&mut r, &io, 11, false)?;
            r.stop(7, 11, if mode == 2 { 1 } else { 8 }, mode == 3)?;
        }
        change(&io, 12, 104, 0xffff0ff0);
        change(&io, 12, 112, if mode < 2 { 0x405 } else { 0x400 });
        ensure!(
            r.restore_all().is_err() && r.failed() && !r.capture_restored(),
            "CSR unqualified peer restore accepted"
        );
        r.continued()?;
        ensure!(
            die(&mut r, true).is_err(),
            "CSR unqualified peer uncertainty cleared"
        );
    }
    Ok(())
}
fn reads() -> Result<()> {
    let info = DispatchRegion {
        address: 0x1000,
        allocation: 0x1000,
        size: 0x1000,
        state: 0x1000,
        kind: 0x1000000,
        protect: 2,
    };
    ensure!(
        info.readable(0x1ff8, 0x1000) && !info.readable(0x1ff9, 0x1000),
        "CSR region boundary differs"
    );
    for protect in [0, 1, 0x10, 0x102] {
        ensure!(
            !DispatchRegion { protect, ..info }.readable(0x1100, 0x1000),
            "CSR foreign region protection accepted"
        );
    }
    ensure!(
        !info.readable(0x1100, 0x2000)
            && !DispatchRegion {
                state: 0x2000,
                ..info
            }
            .readable(0x1100, 0x1000)
            && !DispatchRegion {
                kind: 0x20000,
                ..info
            }
            .readable(0x1100, 0x1000),
        "CSR region identity differs"
    );
    for mode in 0..5 {
        let mut target = DispatchTarget::default();
        let mut reads = 0;
        let mut regions = 0;
        let result = target.read(
            0x1100,
            0x1000,
            0x1234,
            || {
                regions += 1;
                ensure!(mode != 1, "fixed region");
                Ok(info)
            },
            |bytes| {
                reads += 1;
                *bytes = (if mode == 3 { 0x1235u64 } else { 0x1234 }).to_le_bytes();
                ensure!(mode != 4, "fixed read");
                Ok(if mode == 2 { 7 } else { 8 })
            },
        );
        ensure!(
            result.is_err() == (mode != 0) && regions == 1 && reads == usize::from(mode != 1),
            "CSR one-shot read product differs"
        );
        ensure!(
            target
                .read(
                    0x1100,
                    0x1000,
                    0x1234,
                    || {
                        regions += 1;
                        Ok(info)
                    },
                    |_| Ok(8)
                )
                .is_err()
                && regions == 1,
            "CSR read budget refunded"
        );
    }
    Ok(())
}
fn generations() -> Result<()> {
    let (mut r, io) = setup(1, 0)?;
    arm(&mut r)?;
    for index in 0..127 {
        let h = 100 + index;
        io.0.borrow_mut().contexts.insert(h, vec![0; CONTEXT_SIZE]);
        r.stop(7, 12, 2, false)?;
        let mut handle = h;
        r.enroll(12, &mut handle, true)?;
        r.continued()?;
        ensure!(
            get(&io.0.borrow().contexts[&h], 72) == 0x8000
                && get(&io.0.borrow().contexts[&h], 80) == 0x8007,
            "CSR generation not armed"
        );
        r.stop(7, 12, 4, false)?;
        r.continued()?;
    }
    io.0.borrow_mut()
        .contexts
        .insert(300, vec![0; CONTEXT_SIZE]);
    r.stop(7, 12, 2, false)?;
    ensure!(
        r.enroll(12, &mut 300, true).is_err(),
        "CSR lifetime capacity refunded"
    );
    r.continued()?;
    ensure!(
        r.enrolled() == 128 && io.0.borrow().closes == 127 && io.0.borrow().writes == 128,
        "CSR generation lifetime counts differ"
    );
    die(&mut r, false)?;
    ensure!(
        !r.captured() && !r.capture_restored(),
        "CSR natural nonreach earned pair"
    );
    let (mut r, io) = setup(1, 0)?;
    ensure!(r.stop(8, 11, 3, false).is_err(), "CSR wrong pid accepted");
    let writes = io.0.borrow().writes;
    ensure!(
        r.arm_dispatch(0x8000, 0x8007).is_err() && io.0.borrow().writes == writes,
        "CSR invalid epoch retained authority"
    );
    Ok(())
}
fn metadata() -> Result<()> {
    let (mut r, _) = setup(1, 0)?;
    ensure!(
        trace_metadata(&r.observation(), false, false, Role::ExplicitId2).is_err(),
        "CSR metadata before destruction accepted"
    );
    die(&mut r, false)?;
    for role in [Role::ExplicitId2, Role::Module] {
        let line = trace_metadata(&r.observation(), false, false, role)?;
        ensure!(
            line.len() < 1024
                && line.contains("paired=False")
                && line.contains("observation_qualified=False")
                && !line.contains("raw_return=")
                && !line.contains("private-")
                && line.ends_with("undebugged_equivalence_claimed=False"),
            "CSR unpaired metadata differs"
        );
    }
    Ok(())
}
fn queued_peer() -> Result<()> {
    for creator in [false, true] {
        for after_post in [false, true] {
            let (mut r, io) = setup(2, 0)?;
            arm(&mut r)?;
            change(&io, 11, 104, 0xfffe07f0);
            change(&io, 11, 112, 0x405);
            r.stop(7, 11, 1, false)?;
            r.dispatch_software(11, true)?;
            r.continued()?;
            let software = r.observation().software;
            let selected = if creator { 11 } else { 12 };
            let peer = if creator { 12 } else { 11 };
            change(&io, peer, 104, 0xfffe07f0);
            change(&io, peer, 112, 0x405);
            capture(&mut r, &io, selected, false)?;
            ensure!(
                get(&io.0.borrow().contexts[&peer], 104) == 0,
                "CSR peer status not restored"
            );
            if after_post {
                capture(&mut r, &io, selected, true)?;
            }
            r.stop(7, peer as u32, 1, false)?;
            {
                let mut continuations = 0;
                let shared = RefCell::new(&mut r);
                let result = activation_event(
                    || {
                        shared
                            .borrow_mut()
                            .capture_dispatch(peer as u32, true, 0x8000, || Ok(()))
                    },
                    || {
                        let mut r = shared.borrow_mut();
                        r.invalidate();
                        r.restore_all()
                    },
                    vec![],
                    || {
                        continuations += 1;
                        shared.borrow_mut().continued()
                    },
                );
                ensure!(
                    result.is_err()
                        && continuations == 1
                        && shared.borrow().failed()
                        && shared.borrow().captured() == after_post
                        && shared.borrow().observation().software == software,
                    "CSR queued peer reinterpreted"
                );
            }
            trap(&io, selected, true);
            r.stop(7, selected as u32, 1, false)?;
            ensure!(
                r.capture_dispatch(selected as u32, true, 0x8007, || Ok(()))
                    .is_err(),
                "CSR queued peer refusal rescued"
            );
            r.continued()?;
            let _ = die(&mut r, true);
            ensure!(
                r.observation().destroyed && r.failed(),
                "CSR queued peer uncertainty cleared"
            );
        }
    }
    Ok(())
}
fn refusal_reporting() -> Result<()> {
    for mode in 0..4 {
        let (mut r, io) = setup(2, 0)?;
        arm(&mut r)?;
        if mode != 0 {
            capture(&mut r, &io, 11, false)?;
        }
        change(
            &io,
            12,
            if mode == 1 { 112 } else { 104 },
            if mode == 1 { 0x9999 } else { 0xfffe0ff0 },
        );
        if mode == 0 {
            trap(&io, 12, false);
        }
        if mode == 1 {
            change(&io, 12, 104, 0);
        }
        let writes = io.0.borrow().writes;
        let error = if mode < 2 {
            trap(&io, 11, mode == 1);
            r.stop(7, 11, 1, false)?;
            r.capture_dispatch(11, true, if mode == 1 { 0x8007 } else { 0x8000 }, || Ok(()))
                .unwrap_err()
        } else {
            r.stop(
                7,
                if mode == 3 { 12 } else { 11 },
                if mode == 3 { 1 } else { 8 },
                true,
            )?;
            r.restore_all().unwrap_err()
        };
        let first = r
            .dispatch_refusal()
            .ok_or_else(|| anyhow::anyhow!("CSR transition refusal absent"))?
            .to_owned();
        let phase = if mode == 0 {
            "call-disarm"
        } else if mode == 1 {
            "pair-restore"
        } else {
            "cleanup-restore"
        };
        let expected = format!(
            "fixed resource observation refused check=dispatch-transition-control snapshot=first phase={phase} event_kind={} pair_started=True paired={} cleanup={} event_thread_equal={} dr6_equal={} dr7_equal={} call_site_match={} post_site_match=False call_status_match={} post_status_match=False stored_dr6=0x0000000000000000 stored_dr7=0x{} current_dr6=0x{} current_dr7=0x{} transaction_context=unknown",
            if mode == 2 { 8 } else { 1 },
            b(mode == 1),
            b(mode >= 2),
            b(mode == 3),
            b(mode == 1),
            b(mode >= 2),
            b(mode == 0),
            b(mode == 0),
            if mode == 0 {
                "0000000000000005"
            } else {
                "0000000000000000"
            },
            if mode == 0 {
                "00000000FFFF0FF1"
            } else if mode == 1 {
                "0000000000000000"
            } else {
                "00000000FFFE0FF0"
            },
            if mode == 1 {
                "0000000000009999"
            } else if mode == 0 {
                "0000000000000405"
            } else {
                "0000000000000000"
            }
        );
        ensure!(
            first == expected
                && first.len() <= 1024
                && first.is_ascii()
                && !first.contains("0000000000008000")
                && !first.contains("0000000000008007")
                && !first.contains("0000000000009000")
                && io.0.borrow().writes == writes + 1,
            "CSR transition refusal metadata differs: {error}"
        );
        change(&io, 12, 104, u64::MAX);
        change(&io, 12, 112, u64::MAX);
        ensure!(
            r.restore_all().is_err()
                && r.dispatch_refusal() == Some(first.as_str())
                && !first.contains("FFFFFFFFFFFFFFFF"),
            "CSR first transition snapshot replaced"
        );
        r.continued()?;
        ensure!(
            die(&mut r, true).is_err() && io.0.borrow().closes == 1,
            "CSR transition refusal not sticky"
        );
    }
    Ok(())
}
