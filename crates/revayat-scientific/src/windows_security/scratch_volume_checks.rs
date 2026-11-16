//! Original nine-request native-volume self-checks, excluding actual kernel operations.
use super::{access::*, failure, volume::*};
use anyhow::{Result, ensure};
use std::cell::Cell;

pub(super) const ROOT: &str = "\\Device\\HarddiskVolume12\\";
pub(super) fn live_requests(io_status: i32) -> Result<Vec<NativeRequest>> {
    let mut probes = requests(ROOT)?;
    for probe in &mut probes {
        probe.output = Some(Box::new(OpenOutput {
            handle: 17,
            io: IoStatus {
                status: io_status,
                information: usize::MAX,
            },
        }));
        probe.opened = true;
        probe.io_status = io_status;
        probe.information = u64::MAX;
    }
    Ok(probes)
}
pub(super) fn deny_zero(probes: &mut [NativeRequest]) {
    probes[0].returned = DENIED;
    probes[0].opened = false;
    probes[0].output.as_mut().unwrap().handle = 0;
}
pub(super) fn name_buffer(data: &mut [u8; 1024], name: &str) -> u32 {
    let units = name.encode_utf16().collect::<Vec<_>>();
    let bytes = units.len() * 2;
    data[..2].copy_from_slice(&(bytes as u16).to_le_bytes());
    data[2..4].copy_from_slice(&(bytes as u16).to_le_bytes());
    let pointer = data.as_ptr() as u64 + 16;
    data[8..16].copy_from_slice(&pointer.to_le_bytes());
    for (chunk, unit) in data[16..16 + bytes]
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(units)
    {
        chunk.copy_from_slice(&unit.to_le_bytes());
    }
    (16 + bytes) as u32
}
pub fn check_volume_access_validation() -> Result<()> {
    ensure!(
        MASKS == [0, 0x20, 0x100000, 0x100020, 1, 2, 0x20000, 0x40000, 0x80000],
        "scratch volume requests lost fixed reviewed access masks"
    );
    for mask in MASKS {
        for host in [false, true] {
            for status in [0, DENIED, 0xc000000du32 as i32, PENDING] {
                let expected = if mask == 0 {
                    status == DENIED
                } else {
                    status == 0 || !host && status == DENIED
                };
                ensure!(
                    status_allowed(mask, host, status) == expected,
                    "scratch volume status/role qualification differs"
                );
            }
        }
    }
    ensure!(
        frame("baseline", 0, DENIED, 0)?
            .contains("native_request_supported=False metadata_qualified=False"),
        "unsupported zero native access earned metadata authority"
    );
    for host in [false, true] {
        let mut probes = live_requests(0)?;
        let closes = Cell::new(0);
        let inspections = Cell::new(0);
        let result = qualify(
            &mut probes,
            ROOT,
            host,
            |_, desired, _| {
                inspections.set(inspections.get() + 1);
                Ok(desired)
            },
            |_| {
                closes.set(closes.get() + 1);
                Ok(())
            },
        );
        let error = result.unwrap_err();
        ensure!(
            error.to_string().contains("stage=2")
                && inspections.get() == 0
                && closes.get() == 9
                && probes.iter().all(|probe| !probe.has_storage()),
            "scratch unqualified zero access reached metadata or skipped close"
        );
        ensure!(
            census(&probes) == ["unknown"; 9].join(","),
            "released scratch requests retained a known census"
        );
    }
    request_checks()?;
    super::volume_faults::check_faults()?;
    direct_parser_checks()
}
fn request_checks() -> Result<()> {
    let mut probes = requests(ROOT)?;
    ensure!(probes.len() == 9, "scratch volume request census differs");
    for (index, request) in probes.iter_mut().enumerate() {
        ensure!(
            request.path == ROOT.trim_end_matches('\\')
                && request.requested == MASKS[index]
                && request.options == 0x200000,
            "scratch bare volume request differs"
        );
        let calls = Cell::new(0);
        let result = request.open(
            |call, output| {
                calls.set(calls.get() + 1);
                super::need(
                    call.access == MASKS[index]
                        && call.share == 7
                        && call.options == 0x200000
                        && call.object.root == 0,
                )?;
                output.io.status = DENIED;
                Ok(DENIED)
            },
            || Err(failure("unexpected pending scratch fixture")),
        );
        let opened = request.opened;
        let release = request.release(
            |_| Err(failure("unexpected bind scratch fixture")),
            |_| Err(failure("unexpected close scratch fixture")),
        );
        ensure!(
            result.is_ok()
                && calls.get() == 1
                && !opened
                && release.is_ok()
                && !request.has_storage(),
            "scratch denied volume request acquired a handle or repeated native call"
        );
        let frame = frame("modified", index, DENIED, 0)?;
        ensure!(
            frame.len() < 384
                && !frame.contains("Harddisk")
                && frame.contains("authority_qualified=False"),
            "scratch volume frame leaked a path or claimed authority"
        );
    }
    for device in [false, true] {
        for information in [0, 1, 2, usize::MAX] {
            let mut probe = NativeRequest::new(
                if device {
                    ROOT.trim_end_matches('\\')
                } else {
                    ROOT
                },
                "lpac",
                "volume",
            );
            probe.target = if device { "volume" } else { "root" }.into();
            probe.options = if device { 0x200000 } else { 0x200021 };
            let closes = Cell::new(0);
            let result = probe.open(
                |_, output| {
                    output.handle = 17;
                    output.io.status = 0;
                    output.io.information = information;
                    Ok(0)
                },
                || Err(failure("unexpected pending scratch fixture")),
            );
            let released = probe.release(
                |_| Ok(()),
                |_| {
                    closes.set(closes.get() + 1);
                    Ok(())
                },
            );
            ensure!(
                result.is_err() == (!device && information != 1)
                    && closes.get() == 1
                    && released.is_ok(),
                "scratch device/directory completion information was conflated"
            );
        }
    }
    for invalid in [0, usize::MAX] {
        let mut probe = requests(ROOT)?.remove(0);
        let closes = Cell::new(0);
        let result = probe.open(
            |_, output| {
                output.handle = invalid;
                output.io.status = 0;
                Ok(0)
            },
            || Err(failure("unexpected pending scratch fixture")),
        );
        let released = probe.release(
            |_| Ok(()),
            |_| {
                closes.set(closes.get() + 1);
                Ok(())
            },
        );
        ensure!(
            result.is_err() && closes.get() == 0 && released.is_ok() && !probe.has_storage(),
            "scratch invalid success handle was admitted or closed"
        );
    }
    for pending_return in [false, true] {
        let mut probe = requests(ROOT)?.remove(0);
        let fatal = Cell::new(0);
        let result = probe.open(
            |_, output| {
                output.io.status = if pending_return { 0 } else { PENDING };
                Ok(if pending_return { PENDING } else { 0 })
            },
            || {
                fatal.set(fatal.get() + 1);
                Ok(())
            },
        );
        ensure!(
            result.is_err() && fatal.get() == 1 && probe.pending && probe.has_storage(),
            "scratch pending completion freed backing storage or skipped fatal callback"
        );
        // Injected calls have no live I/O. Only these inert fixtures may qualify their retained storage releasable.
        probe.pending = false;
        ensure!(
            probe
                .release(
                    |_| Ok(()),
                    |_| Err(failure("unexpected pending fixture handle"))
                )
                .is_ok()
                && !probe.has_storage(),
            "inert scratch pending fixture did not release its storage"
        );
    }
    Ok(())
}
fn direct_parser_checks() -> Result<()> {
    let mut request = requests(ROOT)?.remove(0);
    request.io_status = -1;
    request.information = u64::MAX;
    let mut evidence = Evidence::new(&request, true);
    evidence.stage = 4;
    evidence.query_kind = 0;
    evidence.queried = true;
    evidence.query_status = -1;
    evidence.returned = 56;
    evidence.basic_known = true;
    evidence.attributes = u32::MAX;
    evidence.granted = 0x100020;
    let refusal = evidence.to_string();
    ensure!(
        refusal.len() < 640
            && refusal.contains("stage=4")
            && refusal.contains("information=0xFFFFFFFFFFFFFFFF")
            && refusal.contains("attributes=0xFFFFFFFF")
            && refusal.contains("query_status=0xFFFFFFFF")
            && refusal.contains("name_equal=-1")
            && !refusal.contains("Harddisk")
            && !refusal.contains("\\\\Device")
            && !refusal.contains("17"),
        "scratch evidence refusal leaked handle/name or lost numeric fields"
    );
    let mut data = Box::new([0u8; 1024]);
    data[4..8].copy_from_slice(&0x100020u32.to_le_bytes());
    ensure!(
        granted(data.as_ref(), 56)? == 0x100020,
        "scratch basic granted mask differs"
    );
    let returned = name_buffer(&mut data, ROOT.trim_end_matches('\\'));
    ensure!(
        object_name(data.as_ref(), returned as usize)? == ROOT.trim_end_matches('\\'),
        "scratch native name parser differs"
    );
    ensure!(
        granted(data.as_ref(), 55).is_err() && object_name(data.as_ref(), 15).is_err(),
        "scratch metadata parser trusted capacity instead of returned span"
    );
    let pointer = data.as_ptr() as u64 + 1023;
    data[8..16].copy_from_slice(&pointer.to_le_bytes());
    ensure!(
        object_name(data.as_ref(), 1024).is_err()
            && requests(&format!("{ROOT}temp")).is_err()
            && frame("other", 0, 0, 0).is_err()
            && frame("baseline", 1, 0, 0).is_err(),
        "scratch metadata accepted escaping name/role/granted mask"
    );
    Ok(())
}
