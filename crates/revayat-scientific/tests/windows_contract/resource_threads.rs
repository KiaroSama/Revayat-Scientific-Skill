//! Production all-thread stopped-event ownership, setter readback, and one-shot CSR pairing.
use revayat_scientific::windows_security::activation::CONTEXT_SIZE;
use revayat_scientific::windows_security::activation::threads::{ContextIo, ResourceThreads};
use std::collections::BTreeMap;
#[derive(Default)]
struct Io {
    contexts: BTreeMap<usize, Vec<u8>>,
    writes: usize,
    closed: Vec<usize>,
    drift: Option<usize>,
}
impl ContextIo for Io {
    fn read(&mut self, handle: usize) -> anyhow::Result<Vec<u8>> {
        Ok(self.contexts.get(&handle).unwrap().clone())
    }
    fn write(&mut self, handle: usize, value: &[u8]) -> anyhow::Result<()> {
        self.writes += 1;
        let mut value = value.to_vec();
        if let Some(at) = self.drift {
            value[at] ^= 1;
        }
        self.contexts.insert(handle, value);
        Ok(())
    }
    fn close(&mut self, handle: usize) -> anyhow::Result<()> {
        assert!(!self.closed.contains(&handle));
        self.closed.push(handle);
        Ok(())
    }
    fn deadline(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn get(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn registry() -> ResourceThreads<Io> {
    let mut io = Io::default();
    for handle in [11, 12, 13] {
        io.contexts.insert(handle, vec![0; CONTEXT_SIZE]);
    }
    let mut value = ResourceThreads::new(7, 11, io).unwrap();
    value.stop(7, 11, 3, false).unwrap();
    value.enroll(11, &mut 11, false).unwrap();
    value.continued().unwrap();
    value.stop(7, 12, 2, false).unwrap();
    value.enroll(12, &mut 12, true).unwrap();
    value.continued().unwrap();
    value
}
fn trap(value: &mut ResourceThreads<Io>, thread: usize, post: bool) {
    let context = value.io_mut().contexts.get_mut(&thread).unwrap();
    for (at, bytes) in [
        (104, if post { 0xfffe0ff2 } else { 0xffff0ff1 }),
        (112, if post { 0x404 } else { 0x405 }),
        (248, if post { 0x8007 } else { 0x8000 }),
        (152, 0x9000),
        (184, 0x1001001e),
        (192, 0x1f8),
        (120, 0x12345678c0150002),
    ] {
        put(context, at, bytes);
    }
}
#[test]
fn real_registry_seam_arms_all_generations_disarms_call_and_restores_exact_baselines() {
    for selected in [11u32, 12] {
        let mut value = registry();
        value.stop(7, 11, 6, false).unwrap();
        value.arm_dispatch(0x8000, 0x8007).unwrap();
        value.continued().unwrap();
        assert_eq!(value.io_mut().writes, 2);
        for thread in [11, 12] {
            assert_eq!(get(&value.io_mut().contexts[&thread], 112), 5);
        }
        trap(&mut value, selected as usize, false);
        value.stop(7, selected, 1, false).unwrap();
        let mut targets = 0;
        value
            .capture_dispatch(selected, true, 0x8000, || {
                targets += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(targets, 1);
        assert!(!value.captured());
        value.continued().unwrap();
        value.stop(7, 13, 2, false).unwrap();
        value.enroll(13, &mut 13, true).unwrap();
        value.continued().unwrap();
        assert_eq!(get(&value.io_mut().contexts[&13], 72), 0);
        trap(&mut value, selected as usize, true);
        value.stop(7, selected, 1, false).unwrap();
        value
            .capture_dispatch(selected, true, 0x8007, || {
                panic!("target may only be consumed on call")
            })
            .unwrap();
        assert!(value.captured() && value.capture_restored() && !value.failed());
        assert_eq!(value.raw_eax(), Some(0xc0150002));
        assert_eq!(value.creator_capture(), selected == 11);
        for context in value.io_mut().contexts.values() {
            assert_eq!(&context[72..120], &[0; 48]);
        }
        value.continued().unwrap();
        value.stop(7, 11, 5, false).unwrap();
        value.continued().unwrap();
        value.destroyed().unwrap();
        assert_eq!(value.io_mut().closed, [12, 13]);
    }
    let mut io = Io::default();
    for handle in [11, 12] {
        io.contexts.insert(handle, vec![0; CONTEXT_SIZE]);
    }
    let mut value = ResourceThreads::new(7, 11, io).unwrap();
    value.stop(7, 11, 3, false).unwrap();
    value.enroll(11, &mut 11, false).unwrap();
    value.arm(0x5000).unwrap();
    value.continued().unwrap();
    value.stop(7, 12, 2, false).unwrap();
    value.enroll(12, &mut 12, true).unwrap();
    value.continued().unwrap();
    for handle in [11, 12] {
        let ctx = value.io_mut().contexts.get_mut(&handle).unwrap();
        put(ctx, 104, 0xfffe07f0);
        put(ctx, 112, 0x401);
    }
    value.stop(7, 11, 1, false).unwrap();
    value.software(11, true).unwrap();
    value.continued().unwrap();
    {
        let ctx = value.io_mut().contexts.get_mut(&11).unwrap();
        put(ctx, 104, 0xffff0ff1);
        put(ctx, 112, 0x401);
        put(ctx, 248, 0x5000);
    }
    value.stop(7, 11, 1, false).unwrap();
    value
        .arm_dispatch_at_entry(11, true, 0x5000, 0x8000, 0x8007)
        .unwrap();
    value.continued().unwrap();
    for handle in [11, 12] {
        assert_eq!(get(&value.io_mut().contexts[&handle], 72), 0x8000);
        assert_eq!(get(&value.io_mut().contexts[&handle], 80), 0x8007);
        assert_eq!(get(&value.io_mut().contexts[&handle], 112), 5);
    }
    trap(&mut value, 11, false);
    value.stop(7, 11, 1, false).unwrap();
    value.capture_dispatch(11, true, 0x8000, || Ok(())).unwrap();
    value.continued().unwrap();
    trap(&mut value, 11, true);
    value.stop(7, 11, 1, false).unwrap();
    value.capture_dispatch(11, true, 0x8007, || Ok(())).unwrap();
    assert!(value.captured() && value.capture_restored() && !value.failed());
    value.continued().unwrap();
    value.stop(7, 11, 5, false).unwrap();
    value.continued().unwrap();
    value.destroyed().unwrap();
}
#[test]
fn foreign_peer_or_selected_trap_never_gets_overwritten_and_failure_stays_sticky() {
    for mode in 0..5 {
        let mut value = registry();
        value.stop(7, 11, 6, false).unwrap();
        value.arm_dispatch(0x8000, 0x8007).unwrap();
        value.continued().unwrap();
        trap(&mut value, 11, false);
        if mode == 0 {
            put(
                value.io_mut().contexts.get_mut(&11).unwrap(),
                104,
                0xffff07f1,
            );
        }
        if mode == 1 {
            put(value.io_mut().contexts.get_mut(&11).unwrap(), 112, 0xc05);
        }
        if mode == 2 {
            put(value.io_mut().contexts.get_mut(&12).unwrap(), 72, 0x9999);
        }
        if mode == 3 {
            put(value.io_mut().contexts.get_mut(&11).unwrap(), 184, 0);
        }
        value.stop(7, 11, 1, false).unwrap();
        assert!(
            value
                .capture_dispatch(11, mode != 4, 0x8000, || Ok(()))
                .is_err()
        );
        assert!(value.failed() && !value.captured());
        assert!(value.capture_dispatch(11, true, 0x8000, || Ok(())).is_err());
        if mode == 2 {
            assert_eq!(get(&value.io_mut().contexts[&12], 72), 0x9999);
        }
        let _ = value.restore_all();
        value.continued().unwrap();
        value.stop(7, 11, 5, true).unwrap();
        value.continued().unwrap();
        let _ = value.destroyed();
        assert!(value.failed() && !value.capture_restored());
    }
}
#[test]
fn setter_readback_is_exact_and_unconfirmed_state_is_never_repaired_by_guess() {
    for offset in [72, 80, 88, 96, 104, 112, 120, 248] {
        let mut value = registry();
        value.io_mut().drift = Some(offset);
        value.stop(7, 11, 6, false).unwrap();
        assert!(value.arm_dispatch(0x8000, 0x8007).is_err());
        assert!(value.failed());
        let before = value.io_mut().writes;
        assert!(value.restore_all().is_err());
        assert_eq!(value.io_mut().writes, before); // No confirmed dispatch baseline means no write.
        value.continued().unwrap();
        value.stop(7, 11, 5, true).unwrap();
        value.continued().unwrap();
        assert!(value.destroyed().is_err());
    }
}
#[test]
fn single_resource_entry_arms_and_restores_all_threads_without_a_csr_pair() {
    let mut value = registry();
    value.stop(7, 11, 6, false).unwrap();
    value.arm(0x8000).unwrap();
    value.continued().unwrap();
    let bytes = value.io_mut().contexts.get_mut(&12).unwrap();
    put(bytes, 104, 0xffff0ff1);
    put(bytes, 112, 0x401);
    put(bytes, 248, 0x8000);
    put(bytes, 176, 0x10000000);
    put(bytes, 120, 0x12345678c0150002);
    value.stop(7, 12, 1, false).unwrap();
    value.capture(12, true, 0x8000, 0x10000000).unwrap();
    assert!(value.captured() && value.capture_restored() && !value.failed());
    assert_eq!(value.raw_eax(), Some(0xc0150002));
    assert!(!value.creator_capture());
    for bytes in value.io_mut().contexts.values() {
        assert_eq!(&bytes[72..120], &[0; 48]);
    }
}

#[test]
fn software_breakpoint_acceptance_is_creator_first_chance_once_and_ownership_checked() {
    let mut value = registry();
    value.stop(7, 11, 6, false).unwrap();
    value.arm(0x8000).unwrap();
    value.continued().unwrap();
    let bytes = value.io_mut().contexts.get_mut(&11).unwrap();
    put(bytes, 104, 0xfffe07f0);
    put(bytes, 112, 0x401);
    value.stop(7, 11, 1, false).unwrap();
    assert!(value.software(12, true).is_err());
    assert!(value.software(11, false).is_err());
    value.software(11, true).unwrap();
    assert!(value.software(11, true).is_err());
}

#[test]
fn creator_entry_capture_does_not_claim_an_unrelated_argument_register_is_image_base() {
    let mut value = registry();
    value.stop(7, 11, 6, false).unwrap();
    value.arm(0x8000).unwrap();
    value.continued().unwrap();
    let bytes = value.io_mut().contexts.get_mut(&11).unwrap();
    put(bytes, 104, 0xffff0ff1);
    put(bytes, 112, 0x401);
    put(bytes, 248, 0x8000);
    put(bytes, 176, u64::MAX);
    value.stop(7, 11, 1, false).unwrap();
    value.capture_entry(11, true, 0x8000).unwrap();
    assert!(value.captured() && value.capture_restored() && value.creator_capture());
}

#[test]
fn enrollment_transfers_handle_before_read_failure_and_generations_do_not_alias() {
    let mut value = registry();
    value.stop(7, 11, 6, false).unwrap();
    value.arm_dispatch(0x8000, 0x8007).unwrap();
    value.continued().unwrap();
    value.stop(7, 12, 4, false).unwrap();
    value.continued().unwrap();
    assert_eq!(value.io_mut().closed, [12]);
    value.io_mut().contexts.insert(14, vec![0; CONTEXT_SIZE]);
    value.stop(7, 12, 2, false).unwrap();
    let mut handle = 14;
    value.enroll(12, &mut handle, true).unwrap();
    assert_eq!(handle, 0);
    value.continued().unwrap();
    assert_eq!(value.enrolled(), 3);
    assert!(value.stop(8, 11, 1, false).is_err());
    assert!(value.arm_dispatch(0x8000, 0x8007).is_err());
}
