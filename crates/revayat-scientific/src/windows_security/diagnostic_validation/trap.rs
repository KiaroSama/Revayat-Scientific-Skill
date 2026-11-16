use super::*;
/// Complete original DebugContext.CheckTrapValidation body, using production predicates.
pub fn check_trap_validation() -> Result<()> {
    for slot in 0..=1 {
        for rtm in [0, 0x10000] {
            for fixed in [0, 0x400] {
                let control = 1u64 << (slot * 2);
                let status = 0xfffe0ff0 | rtm | (1 << slot);
                let old_idle = (status & !3) == 0 && (control | fixed) == control;
                ensure!(
                    !old_idle
                        && activation::owned_trap_status(status, control | fixed, control, slot),
                    "owned trap event/setter distinction differs"
                );
                for foreign in [4, 8, 0x2000, 0x4000, 0x8000, 0x100000000] {
                    ensure!(
                        !activation::owned_trap_status(status | foreign, control, control, slot),
                        "owned trap accepted foreign status"
                    );
                }
                for foreign in [
                    2,
                    0x100,
                    0x200,
                    0x800,
                    0x2000,
                    0x10000,
                    0x40000,
                    0x100000000,
                ] {
                    ensure!(
                        !activation::owned_trap_status(status, control | foreign, control, slot),
                        "owned trap accepted unowned control"
                    );
                }
                ensure!(
                    !activation::owned_trap_status(status ^ 0x800, control, control, slot)
                        && !activation::owned_trap_status(status ^ 0x10, control, control, slot)
                        && !activation::owned_trap_status(status | 0x1000, control, control, slot)
                        && !activation::owned_trap_status(status, control, control, 1 - slot)
                        && !activation::owned_trap_status(
                            status | (1 << (1 - slot)),
                            control,
                            control,
                            slot
                        )
                        && !activation::owned_trap_status(
                            status,
                            control | 0x800,
                            control | 0x800,
                            slot
                        )
                        && !activation::owned_trap_status(status, 0, 0, slot),
                    "owned trap accepted unsupported inactive controls"
                );
            }
        }
    }
    ensure!(
        activation::owned_trap_site(7, 7, true, true, 100, 100),
        "owned trap positive site differs"
    );
    for (thread, first, enabled, instruction, site) in [
        (8, true, true, 100, 100),
        (7, false, true, 100, 100),
        (7, true, false, 100, 100),
        (7, true, true, 101, 100),
        (7, true, true, 0, 0),
    ] {
        ensure!(
            !activation::owned_trap_site(thread, 7, first, enabled, instruction, site),
            "owned trap site attribution widened"
        );
    }
    let idle = vec![0; activation::CONTEXT_SIZE];
    let mut trap = idle.clone();
    put(&mut trap, 104, 0xfffe0ff1);
    put(&mut trap, 112, 0x401);
    ensure!(
        !activation::raw_debug_equal(&idle, &trap)?
            && activation::unchanged_control_integer(&idle, &trap)?,
        "trap event became exact setter readback"
    );
    for offset in [72, 80, 88, 96, 104, 112] {
        let mut changed = idle.clone();
        changed[offset] = 1;
        ensure!(
            !activation::raw_debug_equal(&idle, &changed)?,
            "raw debug equality omitted a register"
        );
    }
    for offset in [56, 66, 68, 120, 128, 136, 152, 248] {
        let mut changed = idle.clone();
        changed[offset] = 1;
        ensure!(
            !activation::unchanged_control_integer(&idle, &changed)?,
            "context immutability omitted CONTROL/INTEGER bytes"
        );
    }
    let clear = activation::trap_qualifiers(0xfffe0ff1);
    let set = activation::trap_qualifiers(0xffff0ff1);
    ensure!(
        clear.contains("rtm_bit_set=False")
            && set.contains("rtm_bit_set=True")
            && clear.contains("bld_bit_set=True")
            && clear.contains("transaction_context=unknown"),
        "owned trap qualifier projection differs"
    );
    Ok(())
}
