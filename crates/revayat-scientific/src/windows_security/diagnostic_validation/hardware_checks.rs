//! Full HardwareTrace.CheckValidation and CheckCheckpointReadValidation lineage.
use super::*;
pub fn check_hardware_trace_validation() -> Result<()> {
    super::super::check_trap_validation()?;
    check_loader_trace_validation()?;
    crate::windows_security::scratch::check_cleanup_validation()?;
    check_checkpoint_reads()?;
    let mut before = vec![0; activation::CONTEXT_SIZE];
    put(&mut before, 112, 0x400);
    let mut after = before.clone();
    ensure!(
        can_restore(true, true, true)
            && !can_restore(true, true, false)
            && !can_restore(true, false, true)
            && !can_restore(false, true, true)
            && free_debug_state(&before)?
            && activation::unchanged_control_integer(&before, &after)?
            && pair(108, 100, 200, 200)
            && !pair(109, 100, 200, 200)
            && !pair(108, 100, 201, 200)
            && !pair(0, u64::MAX, 200, 200),
        "hardware state/return pair positive fixture differs"
    );
    put(&mut after, 72, 100);
    ensure!(
        !free_debug_state(&after)? && activation::unchanged_control_integer(&before, &after)?,
        "hardware occupied-register fixture differs"
    );
    put(&mut after, 152, 1);
    ensure!(
        !activation::unchanged_control_integer(&before, &after)?,
        "hardware stack mutation accepted"
    );
    after = before.clone();
    put(&mut after, 112, 0x401);
    ensure!(
        !free_debug_state(&after)?,
        "hardware enabled collision accepted"
    );
    after = before.clone();
    put(&mut after, 104, 0x4000);
    ensure!(
        !free_debug_state(&after)?,
        "hardware foreign single-step cause accepted"
    );
    for collision in [0x800, 0x2000, 0x10000, 0xc0000000] {
        after = before.clone();
        put(&mut after, 112, 0x400 | collision);
        ensure!(
            !free_debug_state(&after)?,
            "hardware foreign control accepted"
        );
    }
    for offset in [68, 120, 128, 136, 152, 248] {
        after = before.clone();
        after[offset] = 1;
        ensure!(
            !activation::unchanged_control_integer(&before, &after)?,
            "hardware non-debug context mutation accepted"
        );
    }
    let entries = [100, 200];
    let mut active = [108, 0];
    let mut slots = [true, false];
    ensure!(
        !slots[1] && active[1] == 0,
        "event slot armed before attach window"
    );
    arm_site_window(&entries, &mut active, &mut slots, false)?;
    ensure!(
        slots[1] && active[1] == 200,
        "event slot failed to arm in attach window"
    );
    ensure!(
        arm_site_window(&entries, &mut active, &mut slots, false).is_err(),
        "duplicate site activation accepted"
    );
    require_site_window(true, false, false)?;
    for [outer, consumed, returning] in [
        [false, false, false],
        [true, true, false],
        [true, false, true],
    ] {
        ensure!(
            require_site_window(outer, consumed, returning).is_err(),
            "inactive/consumed/callee-return site accepted"
        );
    }
    consume_site(&mut active, &mut slots);
    ensure!(
        active == [108, 0] && slots == [true, false],
        "one-shot disarm altered enclosing return slot"
    );
    ensure!(
        arm_site_window(&entries, &mut active, &mut slots, true).is_err(),
        "consumed site rearmed"
    );
    for site in [0, 108] {
        ensure!(
            arm_site_window(&[100, site], &mut active, &mut slots, false).is_err(),
            "missing or aliased site accepted"
        );
    }
    let mut closed = HardwareWindow::new(1, 2, 7, 11)?;
    closed.completed = true;
    ensure!(
        closed.require_single_step(11, 0x80000004, true).is_err(),
        "closed window silently accepted repeated single-step"
    );
    closed.site_consumed = true;
    closed.outer_paired = true;
    closed.restored = true;
    closed.require_complete()?;
    closed.invalidate();
    ensure!(
        closed.require_complete().is_err(),
        "completed flag hid invalidated window"
    );
    for (input, expected) in [
        (0, "raw_eax=0x00000000"),
        (0x80000000, "raw_eax=0x80000000"),
        (u32::MAX, "raw_eax=0xFFFFFFFF"),
    ] {
        before = vec![0; activation::CONTEXT_SIZE];
        put(&mut before, 120, 0x1234567800000000 | u64::from(input));
        let scalar = raw_site_value(&before)?;
        ensure!(
            scalar == expected
                && scalar.len() == 18
                && !scalar.contains("12345678")
                && !scalar.contains("status")
                && !scalar.contains("return"),
            "raw site scalar lost low32-only semantics"
        );
    }
    require_observation_complete(true, true, true)?;
    for [consumed, paired, restored] in [
        [false, true, true],
        [true, false, true],
        [true, true, false],
        [false, false, true],
    ] {
        ensure!(
            require_observation_complete(consumed, paired, restored).is_err(),
            "completion accepted missing site/pair/restoration"
        );
    }
    before = vec![0; activation::CONTEXT_SIZE];
    after = before.clone();
    put(&mut after, 88, 0x123456789abcdef0);
    put(&mut after, 104, 0x1001);
    put(&mut after, 112, 0x401);
    let metadata = ownership_metadata(&after, &before, 0, 0x400)?;
    for expected in [
        "dr2_match=False",
        "dr3_match=True",
        "dr6_unowned_match=False",
        "dr7_control_match=False",
        "dr6_cause_mask=0x0000000000000001",
        "dr6_other_bits_xor=0x0000000000001000",
        "dr6_expected=0x0000000000000000",
        "dr6_actual=0x0000000000001001",
    ] {
        ensure!(
            metadata.contains(expected),
            "hardware ownership metadata omitted predicate"
        );
    }
    ensure!(
        metadata.len() <= 512 && !metadata.contains("123456789ABCDEF0"),
        "hardware metadata disclosed address or exceeded bound"
    );
    Ok(())
}
fn check_checkpoint_reads() -> Result<()> {
    const BASE: u64 = 0x180000000;
    const ADDRESS: u64 = 0x18039a7e8;
    const RVA: u32 = 0x39a7e8;
    let info = MemoryRegion {
        address: 0x18039a000,
        allocation_base: BASE as usize,
        size: 0x1000,
        state: 0x1000,
        kind: 0x1000000,
        protection: 4,
        ..MemoryRegion::default()
    };
    require_checkpoint_region(info, ADDRESS, BASE, RVA)?;
    require_checkpoint_region(
        MemoryRegion {
            protection: 8,
            ..info
        },
        ADDRESS,
        BASE,
        RVA,
    )?;
    for protection in [
        0, 1, 2, 0x10, 0x20, 0x40, 0x80, 0x104, 0x204, 0x404, 0x80000004,
    ] {
        ensure!(
            require_checkpoint_region(MemoryRegion { protection, ..info }, ADDRESS, BASE, RVA)
                .is_err(),
            "unqualified checkpoint protection accepted"
        );
    }
    for invalid in [
        MemoryRegion {
            state: 0x2000,
            ..info
        },
        MemoryRegion {
            kind: 0x20000,
            ..info
        },
        MemoryRegion {
            allocation_base: BASE as usize + 1,
            ..info
        },
        MemoryRegion {
            address: ADDRESS as usize + 1,
            ..info
        },
        MemoryRegion {
            size: 0x7e9,
            ..info
        },
        MemoryRegion { size: 0, ..info },
        MemoryRegion {
            size: usize::MAX,
            ..info
        },
    ] {
        ensure!(
            require_checkpoint_region(invalid, ADDRESS, BASE, RVA).is_err(),
            "unqualified checkpoint region accepted"
        );
    }
    for (address, base, rva) in [
        (ADDRESS + 1, BASE, RVA),
        (0x18039b8f8, BASE, RVA),
        (ADDRESS, 0, RVA),
        (ADDRESS, BASE, 0x39b8f8),
    ] {
        ensure!(
            require_checkpoint_region(info, address, base, rva).is_err(),
            "checkpoint accepted unmatched image/RVA"
        );
    }
    let historical = MemoryRegion {
        address: 0x18039b000,
        ..info
    };
    require_checkpoint_region(historical, 0x18039b8f8, BASE, 0x39b8f8)?;
    ensure!(
        require_checkpoint_region(historical, 0x18039b8f8, BASE, RVA).is_err(),
        "historical checkpoint switched profile RVA"
    );
    for (mut bytes, expected) in [
        ([0, 0], "raw_checkpoint=0x0000"),
        ([0x58, 2], "raw_checkpoint=0x0258"),
        ([0x12, 0x34], "raw_checkpoint=0x3412"),
        ([0xff, 0xff], "raw_checkpoint=0xFFFF"),
    ] {
        let scalar = raw_checkpoint(decode_checkpoint(true, 2, Some(&mut bytes))?);
        ensure!(
            scalar == expected && scalar.len() == 21 && bytes == [0, 0],
            "checkpoint scalar lost little-endian WORD or buffer not cleared"
        );
    }
    for count in [0, 1, 3, u64::MAX] {
        let mut bytes = [0x12, 0x34];
        ensure!(
            decode_checkpoint(true, count, Some(&mut bytes)).is_err() && bytes == [0, 0],
            "partial/oversized checkpoint read accepted or buffer not cleared"
        );
    }
    let mut bytes = [0x12, 0x34];
    ensure!(
        decode_checkpoint(false, 2, Some(&mut bytes)).is_err() && bytes == [0, 0],
        "native failed checkpoint read accepted or buffer not cleared"
    );
    ensure!(
        decode_checkpoint(true, 2, None).is_err(),
        "null checkpoint buffer accepted"
    );
    for mut bytes in [vec![], vec![0x12], vec![1, 2, 3]] {
        ensure!(
            decode_checkpoint(true, 2, Some(&mut bytes)).is_err() && bytes.iter().all(|v| *v == 0),
            "wrong checkpoint buffer width accepted or not cleared"
        );
    }
    Ok(())
}
