//! Frozen ActivationBoundaryTrace.CheckValidation assertions over production predicates.
use super::check_io::*;
use super::*;
use std::cell::Cell;

pub fn check_validation() -> Result<()> {
    for (mode, phase) in [
        (BoundaryMode::Child, "activation-software-stop"),
        (
            BoundaryMode::ModuleCallback,
            "module-callback-software-stop",
        ),
    ] {
        ensure!(
            software_stop_metadata(mode, 0xffff0ff0)
                == format!(
                    "phase={phase} origin_verified=False ordering_only=True raw_dr6=0x00000000FFFF0FF0 rtm_bit_set=True bld_bit_set=True transaction_context=unknown"
                ),
            "software-stop metadata omitted/mislabeled its mode or claimed verified origin"
        );
    }
    ensure!(
        software::software_status(0xfffe07f0, 0x401, 1),
        "supported software presentation refused"
    );
    super::super::entry::check_software_presentation()?;
    image::check_activation_boundary_validation()?;
    super::super::event_lifecycle::check_activation_event_validation()?;
    super::super::event_lifecycle::check_activation_destruction_validation()?;
    let role = super::super::fixtures::child::require_diagnostic_role;
    role(true, &[false; 4], false, true)?;
    role(true, &[false; 4], true, false)?;
    for r in [
        [true, false, false, false, false, true, true],
        [false, false, false, false, false, false, true],
        [true, true, false, false, false, false, true],
        [true, false, true, false, false, false, true],
        [true, false, false, true, false, false, true],
        [true, false, false, false, true, false, true],
    ] {
        ensure!(
            role(r[0], &[r[1], r[2], r[3], r[4]], r[5], r[6]).is_err(),
            "overlapping diagnostic role admitted"
        );
    }
    ensure!(
        next(1, 0, 0)? == 2
            && next(2, 0, 0)? == 3
            && next(3, 0, 0)? == 4
            && next(4, 1, 0xc0000022)? == 5
            && next(4, 1, 0x80000000)? == 5
            && next(4, 1, u32::MAX)? == 5,
        "boundary stage product differs"
    );
    for value in [0, 1, 0x7fffffff] {
        ensure!(next(4, 1, value).is_err(), "non-failure funnel admitted");
    }
    for (stage, slot) in [(0, 0), (1, 1), (2, 1), (3, 1), (4, 0), (5, 0), (5, 1)] {
        ensure!(
            next(stage, slot, 0).is_err(),
            "wrong boundary stage/slot admitted"
        );
    }
    let baseline = baseline()?;
    let entry = software::desired(&baseline, &baseline, &[0x1000, 0], &[true, false], false)?;
    let sites = software::desired(&entry, &baseline, &[0x2000, 0x3000], &[true, true], false)?;
    let restored = software::desired(&sites, &baseline, &[0x2000, 0x3000], &[true, true], true)?;
    ensure!(
        software::value(&entry, 72)? == 0x1000
            && software::value(&sites, 72)? == 0x2000
            && software::value(&sites, 80)? == 0x3000
            && software::value(&sites, 112)? == 0x405
            && raw_debug_equal(&restored, &baseline)?
            && unchanged_control_integer(&baseline, &sites)?
            && software::value(&baseline, 72)? == 0,
        "desired boundary context differs"
    );
    ensure!(
        raw(0x12345678c0000022) == "raw_ebx=0xC0000022" && raw(u64::MAX) == "raw_ebx=0xFFFFFFFF",
        "raw EBX width differs"
    );
    let mut scalar = vec![0; super::super::CONTEXT_SIZE];
    software::put(&mut scalar, 120, 1)?;
    software::put(&mut scalar, 144, 0x12345678c0000022)?;
    let value = raw(software::value(&scalar, 144)?);
    ensure!(
        value == "raw_ebx=0xC0000022" && !value.contains("raw_eax"),
        "EBX mislabeled"
    );
    ensure!(
        complete(5, true, false)
            && !complete(4, true, false)
            && !complete(5, false, false)
            && !complete(5, true, true),
        "completion predicate differs"
    );
    for (value, expected) in [
        0,
        1,
        0x7fffffff,
        0x80000000,
        0xc0000022,
        u32::MAX as u64,
        0x12345678c0000022,
    ]
    .into_iter()
    .zip([
        "00000000", "00000001", "7FFFFFFF", "80000000", "C0000022", "FFFFFFFF", "C0000022",
    ]) {
        software::put(&mut scalar, 120, value)?;
        software::put(&mut scalar, 144, 0x123456789abcdef0)?;
        ensure!(
            registry_result(&scalar)? == format!("raw_eax=0x{expected}")
                && next(3, 0, value as u32)? == 4,
            "registry scalar interpretation differs"
        );
    }
    let replaced = software::desired(&sites, &baseline, &[0x4000, 0x3000], &[true, true], false)?;
    let disabled = software::desired(&replaced, &baseline, &[0, 0x3000], &[false, true], false)?;
    ensure!(
        software::value(&replaced, 72)? == 0x4000
            && software::value(&replaced, 80)? == 0x3000
            && software::value(&replaced, 112)? == 0x405
            && software::value(&disabled, 72)? == 0
            && software::value(&disabled, 80)? == 0x3000
            && software::value(&disabled, 112)? == 0x404
            && raw_debug_equal(
                &software::desired(&disabled, &baseline, &[0, 0x3000], &[true, true], true)?,
                &baseline
            )?
            && unchanged_control_integer(&sites, &replaced)?
            && unchanged_control_integer(&replaced, &disabled)?,
        "replacement/disable changed integer state"
    );
    let stage = |state, initial, thread, first| {
        software::software_stage(
            SoftwareRole::Boundary,
            state,
            false,
            initial,
            SoftwareEvent {
                thread,
                creator: 7,
                code: 0x80000003,
                first,
            },
        )
    };
    ensure!(
        stage(1, false, 7, true)
            && !stage(2, false, 7, true)
            && !stage(1, true, 7, true)
            && !stage(1, false, 8, true)
            && !stage(1, false, 7, false),
        "software stage differs"
    );
    let mut info = MemoryRegion {
        address: 0x1000,
        allocation: 0x1000,
        size: 0x1000,
        state: 0x1000,
        protection: 0x20,
        kind: 0x1000000,
        ..Default::default()
    };
    ensure!(
        executable_region(info, 0x1100, 2, 0x1000)
            && !executable_region(info, 0x1fff, 2, 0x1000)
            && !executable_region(info, 0x1100, 2, 0x2000),
        "executable memory bounds differ"
    );
    for access in [0, 1, 2, 4, 8, 0x120] {
        info.protection = access;
        ensure!(
            !executable_region(info, 0x1100, 2, 0x1000),
            "non-executable region admitted"
        );
    }
    let mut observer = observer(BoundaryMode::Child, |_| Ok(()))?;
    observer.stage = 5;
    observer.restored = true;
    observer.require_complete()?;
    observer.invalidate();
    ensure!(
        observer.require_complete().is_err(),
        "invalidated completion admitted"
    );
    let reporting = failure("private-reporting-sentinel");
    let retained =
        require_check(false, "software-ownership", || Err(error(&reporting))).unwrap_err();
    let group = retained.downcast_ref::<Failures>().unwrap();
    ensure!(
        group.errors.len() == 2
            && group.errors[0].to_string()
                == "fixed activation observation refused check=software-ownership"
            && same(&group.errors[1], &reporting),
        "refusal/report failure identity/order differs"
    );
    observer.original = Some(vec![0; super::super::CONTEXT_SIZE]);
    observer.event_code = 0x80000003;
    observer.event_creator = true;
    observer.event_first = true;
    let metadata = observer.refusal_metadata("software-ownership", observer.original.as_deref())?;
    ensure!(
        metadata.contains(
            "check=software-ownership stage=5 event_code=0x80000003 creator=True first_chance=True"
        ) && metadata.contains("raw_dr6=0x0000000000000000")
            && metadata.contains("raw_dr7=0x0000000000000000")
            && !metadata.contains("raw_eax")
            && !metadata.contains("digest")
            && metadata.len() < 768,
        "refusal metadata differs or leaks private inputs"
    );
    let reported = Cell::new(false);
    require_check(true, "software-ownership", || {
        reported.set(true);
        Ok(())
    })?;
    ensure!(
        !reported.get()
            && observer
                .refusal_metadata("hardware-stage", None)?
                .ends_with("context_read=False"),
        "success reported refusal or absent-context claimed read"
    );
    software::put(observer.original.as_mut().unwrap(), 104, u64::MAX)?;
    software::put(observer.original.as_mut().unwrap(), 112, u64::MAX)?;
    let metadata = observer.refusal_metadata("hardware-trap", observer.original.as_deref())?;
    ensure!(
        metadata.contains("raw_dr6=0xFFFFFFFFFFFFFFFF")
            && metadata.contains("raw_dr7=0xFFFFFFFFFFFFFFFF")
            && !metadata.contains("raw_eax")
            && !metadata.contains("fixed")
            && !metadata.contains("digest")
            && metadata.len() < 768,
        "max-context refusal metadata differs"
    );
    observer.restored = false;
    observer.invalidated = false;
    observer.stage = 1;
    ensure!(
        observer.accept_software(12, 0x80000003, true).is_err()
            && !observer.software.initial()
            && observer.require_complete().is_err(),
        "foreign software stop latched/completed"
    );
    check_software_status()?;
    observer.original = Some(vec![0; super::super::CONTEXT_SIZE]);
    observer.enabled[0] = true;
    observer.addresses[0] = 0x1000;
    let mut presented = vec![0; super::super::CONTEXT_SIZE];
    software::put(&mut presented, 72, 0x1000)?;
    software::put(&mut presented, 104, 0xffff0ff0)?;
    software::put(&mut presented, 112, 0x401)?;
    observer.ownership(&presented, false)?;
    let original = observer.original.as_deref().unwrap();
    let idle = software::desired(
        original,
        original,
        &observer.addresses,
        &observer.enabled,
        false,
    )?;
    ensure!(
        !raw_debug_equal(&idle, &presented)?
            && software::value(&presented, 112)? != software::control(original, &observer.enabled)?
            && software::value(&presented, 104)? & !3 != software::value(original, 104)? & !3,
        "software API presentation aliased raw hardware state"
    );
    for offset in [72, 80, 88, 96] {
        let mut foreign = presented.clone();
        software::put(&mut foreign, offset, 0x9999)?;
        ensure!(
            observer.ownership(&foreign, false).is_err(),
            "foreign debug address admitted"
        );
    }
    ensure!(
        !observer.software.initial() && observer.stage == 1 && observer.io.reads.get() == 0,
        "ownership advanced software stage/read native state"
    );
    let qualifiers = trap_qualifiers(0xffff0ff0);
    ensure!(
        qualifiers.contains("rtm_bit_set=True")
            && qualifiers.contains("bld_bit_set=True")
            && qualifiers.contains("transaction_context=unknown"),
        "trap metadata differs"
    );
    let qualifiers = trap_qualifiers(0xfffe0ff0);
    ensure!(
        qualifiers.contains("rtm_bit_set=False")
            && qualifiers.contains("transaction_context=unknown"),
        "RTM metadata differs"
    );
    Ok(())
}
fn check_software_status() -> Result<()> {
    for rtm in [0, 0x10000] {
        for bld in [0, 0x800] {
            for fixed in [0, 0x400] {
                for expected in [0, 1, 4, 5, 0x400, 0x401, 0x404, 0x405] {
                    let status = 0xfffe07f0 | rtm | bld;
                    let flags = expected ^ fixed;
                    ensure!(
                        software::software_status(status, flags, expected),
                        "supported software status product refused"
                    );
                    for foreign in [1, 2, 4, 8, 0x1000, 0x2000, 0x4000, 0x8000, 0x100000000] {
                        ensure!(
                            !software::software_status(status | foreign, flags, expected),
                            "foreign DR6 product admitted"
                        );
                    }
                    ensure!(
                        !software::software_status(status ^ 0x10, flags, expected),
                        "noncanonical DR6 admitted"
                    );
                    for foreign in [
                        2,
                        8,
                        0x100,
                        0x200,
                        0x800,
                        0x2000,
                        0x10000,
                        0x40000,
                        0x100000000,
                    ] {
                        ensure!(
                            !software::software_status(status, flags | foreign, expected),
                            "foreign DR7 product admitted"
                        );
                    }
                    ensure!(
                        !software::software_status(status, flags | 0x800, expected | 0x800),
                        "unsupported expected DR7 admitted"
                    );
                }
            }
        }
    }
    Ok(())
}
