//! Full original scratch-volume inspection/query/cleanup fault matrix.
use super::{
    Failures, failure,
    volume::*,
    volume_checks::{ROOT, deny_zero, live_requests, name_buffer},
};
use anyhow::{Result, ensure};
use std::{cell::Cell, sync::Arc};

pub(super) fn check_faults() -> Result<()> {
    for mode in 0..4 {
        let mut probes = live_requests(-1)?;
        deny_zero(&mut probes);
        let closes = Cell::new(0);
        let operation = failure("fixed metadata fixture");
        let cleanup = failure("fixed close fixture");
        let result = qualify(
            &mut probes,
            ROOT,
            true,
            |handle, desired, _| {
                super::need(handle == 17)?;
                if mode == 1 || mode == 3 {
                    Err(operation.clone())
                } else {
                    Ok(desired)
                }
            },
            |_| {
                closes.set(closes.get() + 1);
                if mode == 2 || mode == 3 {
                    Err(cleanup.clone())
                } else {
                    Ok(())
                }
            },
        );
        ensure!(
            closes.get() == 8
                && result.is_err() == (mode != 0)
                && probes.iter().all(|probe| !probe.has_storage()),
            "scratch volume metadata/close failure matrix differs mode={mode}"
        );
        match mode {
            0 => {
                let frames = frames("modified", &combine(0, 0, &result.unwrap())?)?;
                ensure!(
                    frames.len() == 9
                        && frames[0].contains("information=0xFFFFFFFFFFFFFFFF")
                        && frames[0].contains("io_status=0xFFFFFFFF"),
                    "scratch metadata discarded opaque completion sentinels"
                );
            }
            1 => ensure!(
                Arc::ptr_eq(&result.unwrap_err(), &operation),
                "scratch clean close replaced original metadata error"
            ),
            3 => {
                let error = result.unwrap_err();
                let group = error.downcast_ref::<Failures>().unwrap();
                ensure!(
                    Arc::ptr_eq(&group.errors[0], &operation),
                    "scratch aggregate lost primary metadata error identity"
                );
            }
            _ => {}
        }
    }
    for mode in 0..11 {
        query_fault(mode)?;
    }
    Ok(())
}
fn query_fault(mode: usize) -> Result<()> {
    let mut probes = live_requests(0)?;
    deny_zero(&mut probes);
    let closes = Cell::new(0);
    let queries = Cell::new(0);
    let cleanup = failure("fixed close fixture");
    if mode == 8 {
        probes[1].returned = DENIED;
        probes[1].opened = false;
        probes[1].output.as_mut().unwrap().handle = 0;
    }
    if mode == 9 {
        probes[1].requested = u32::MAX;
    }
    ensure!(
        census(&probes).starts_with("C0000022,"),
        "scratch census lost zero-request denial"
    );
    if mode == 0 {
        probes[1].opened = false;
        ensure!(
            census(&probes).starts_with("C0000022,unknown,"),
            "scratch census admitted inconsistent opened flag"
        );
        probes[1].opened = true;
        probes[1].pending = true;
        ensure!(
            census(&probes).starts_with("C0000022,unknown,"),
            "scratch census admitted pending request"
        );
        probes[1].pending = false;
    }
    let mut query = |handle, kind, buffer: &mut [u8; 1024], capacity| {
        queries.set(queries.get() + 1);
        super::need(handle == 17 && capacity == if kind == 0 { 56 } else { 1024 })?;
        buffer.fill(0);
        let mut length = if kind == 0 { 56 } else { 16 };
        if kind == 0 {
            if mode == 1 || mode == 10 {
                return Ok(QueryResult {
                    status: DENIED,
                    returned: length,
                });
            }
            if mode == 2 {
                length = 55;
            }
            buffer[..4].copy_from_slice(&(if mode == 3 { 2u32 } else { 0 }).to_le_bytes());
            let desired = MASKS[1 + queries.get() / 2];
            let grant = if mode == 4 { u32::MAX } else { desired };
            buffer[4..8].copy_from_slice(&grant.to_le_bytes());
        } else {
            if mode == 5 {
                return Ok(QueryResult {
                    status: DENIED,
                    returned: length,
                });
            }
            let name = if mode == 7 {
                "private fixture name"
            } else {
                ROOT.trim_end_matches('\\')
            };
            length = name_buffer(buffer, name);
            if mode == 6 {
                length = 15;
            }
        }
        Ok(QueryResult {
            status: 0,
            returned: length,
        })
    };
    let result = qualify(
        &mut probes,
        ROOT,
        true,
        |handle, desired, evidence| inspect(handle, desired, ROOT, || Ok(()), evidence, &mut query),
        |_| {
            closes.set(closes.get() + 1);
            if mode == 10 {
                Err(cleanup.clone())
            } else {
                Ok(())
            }
        },
    );
    ensure!(
        closes.get() == if mode == 8 { 7 } else { 8 }
            && probes.iter().all(|probe| !probe.has_storage()),
        "scratch query fault skipped a close or retained storage mode={mode}"
    );
    if mode == 0 {
        ensure!(
            result.is_ok() && queries.get() == 16,
            "scratch qualified volume did not inspect all basic/name pairs"
        );
        return Ok(());
    }
    let stage = [0, 3, 4, 4, 5, 6, 7, 8, 2, 1, 3][mode];
    let error = result.unwrap_err();
    let operation = if mode == 10 {
        let group = error.downcast_ref::<Failures>().unwrap();
        ensure!(
            group.errors.len() == 9,
            "scratch query/close aggregate lost independent failures"
        );
        for released in &group.errors[1..] {
            let released = released.downcast_ref::<Failures>().unwrap();
            ensure!(
                released.errors.len() == 1 && Arc::ptr_eq(&released.errors[0], &cleanup),
                "scratch per-handle close failure identity was flattened or replaced"
            );
        }
        group.errors[0].clone()
    } else {
        error
    };
    let message = operation.to_string();
    ensure!(
        operation.downcast_ref::<Evidence>().is_some()
            && message.contains(&format!("stage={stage}"))
            && message.contains("information=0xFFFFFFFFFFFFFFFF")
            && message.len() < 640
            && !message.contains(ROOT)
            && !message.contains("private fixture name")
            && message.contains("open_statuses=C0000022,"),
        "scratch query refusal lost bounded stage/sentinel/census evidence mode={mode}"
    );
    ensure!(
        queries.get()
            == if mode == 8 || mode == 9 {
                0
            } else if mode < 5 || mode == 10 {
                1
            } else {
                2
            },
        "scratch query continued beyond its first failed qualification mode={mode}"
    );
    Ok(())
}
