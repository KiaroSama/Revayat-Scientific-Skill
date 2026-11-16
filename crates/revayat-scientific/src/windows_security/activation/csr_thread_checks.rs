//! Original CSR matrices against the same ContextIo operations used by native observers.
use super::super::threads::{ContextIo, ResourceThreads};
use super::*;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
#[path = "csr_fault_checks.rs"]
mod faults;
#[derive(Default)]
pub(crate) struct Memory {
    pub contexts: BTreeMap<usize, Vec<u8>>,
    pub reads: usize,
    pub writes: usize,
    pub closes: usize,
    pub closed: Vec<usize>,
    pub drift: BTreeMap<usize, Vec<usize>>,
    pub fail_restore: Option<usize>,
    pub fail_close: bool,
}
#[derive(Clone, Default)]
pub(crate) struct Io(pub Rc<RefCell<Memory>>);
impl ContextIo for Io {
    fn read(&mut self, h: usize) -> Result<Vec<u8>> {
        let mut m = self.0.borrow_mut();
        m.reads += 1;
        Ok(m.contexts
            .get(&h)
            .ok_or_else(|| anyhow::anyhow!("fixed context absent"))?
            .clone())
    }
    fn write(&mut self, h: usize, bytes: &[u8]) -> Result<()> {
        let mut m = self.0.borrow_mut();
        m.writes += 1;
        ensure!(
            m.fail_restore != Some(h) || get(bytes, 72) != 0 || get(bytes, 80) != 0,
            "fixed restore"
        );
        let mut bytes = bytes.to_vec();
        if let Some(offsets) = m.drift.get(&m.writes) {
            for at in offsets {
                bytes[*at] ^= 1;
            }
        }
        m.contexts.insert(h, bytes);
        Ok(())
    }
    fn close(&mut self, h: usize) -> Result<()> {
        let mut m = self.0.borrow_mut();
        m.closes += 1;
        m.closed.push(h);
        ensure!(!m.fail_close, "fixed close");
        Ok(())
    }
    fn deadline(&mut self) -> Result<()> {
        Ok(())
    }
}
pub(crate) fn get(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
pub(crate) fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn change(io: &Io, h: usize, at: usize, value: u64) {
    put(io.0.borrow_mut().contexts.get_mut(&h).unwrap(), at, value);
}
pub(crate) fn trap(io: &Io, h: usize, post: bool) {
    let mut m = io.0.borrow_mut();
    let c = m.contexts.get_mut(&h).unwrap();
    for (at, value) in [
        (104, if post { 0xfffe0ff2 } else { 0xffff0ff1 }),
        (112, if post { 0x404 } else { 0x405 }),
        (248, if post { 0x8007 } else { 0x8000 }),
        (152, 0x9000),
        (184, 0x1001001e),
        (192, 0x1f8),
        (120, 0x12345678c0150002),
    ] {
        put(c, at, value);
    }
}
pub(crate) fn setup(count: usize, status: u64) -> Result<(ResourceThreads<Io>, Io)> {
    let io = Io::default();
    for h in 11..11 + count {
        let mut c = vec![0; super::super::CONTEXT_SIZE];
        put(&mut c, 104, status);
        io.0.borrow_mut().contexts.insert(h, c);
    }
    let mut r = ResourceThreads::new(7, 11, io.clone())?;
    for h in 11..11 + count {
        r.stop(7, h as u32, if h == 11 { 3 } else { 2 }, false)?;
        let mut handle = h;
        r.enroll(h as u32, &mut handle, h != 11)?;
        ensure!(
            handle == if h == 11 { h } else { 0 },
            "resource handle transfer differs"
        );
        r.continued()?;
    }
    Ok((r, io))
}
pub(crate) fn arm(r: &mut ResourceThreads<Io>) -> Result<()> {
    r.stop(7, 11, 6, false)?;
    r.arm_dispatch(0x8000, 0x8007)?;
    r.continued()
}
pub(crate) fn capture(r: &mut ResourceThreads<Io>, io: &Io, h: usize, post: bool) -> Result<()> {
    trap(io, h, post);
    r.stop(7, h as u32, 1, false)?;
    r.capture_dispatch(
        h as u32,
        true,
        if post { 0x8007 } else { 0x8000 },
        || Ok(()),
    )?;
    r.continued()
}
pub(crate) fn die(r: &mut ResourceThreads<Io>, draining: bool) -> Result<()> {
    r.stop(7, 11, 5, draining)?;
    r.continued()?;
    r.destroyed()
}
pub(super) fn check() -> Result<()> {
    for creator in [false, true] {
        for baseline in [0, 0xffff0ff0] {
            for rtm in [0, 0x10000] {
                for bld in [0, 0x800] {
                    for fixed in [0, 0x400] {
                        let (mut r, io) = setup(2, baseline)?;
                        arm(&mut r)?;
                        ensure!(
                            io.0.borrow().writes == 2
                                && io
                                    .0
                                    .borrow()
                                    .contexts
                                    .values()
                                    .all(|c| get(c, 104) == baseline
                                        && get(c, 72) == 0x8000
                                        && get(c, 80) == 0x8007
                                        && get(c, 112) == 5),
                            "CSR arm baseline/status differs"
                        );
                        let selected = if creator { 11 } else { 12 };
                        let other = if creator { 12 } else { 11 };
                        let first = 0xfffe07f0 | rtm | bld;
                        change(&io, other, 104, first);
                        change(&io, other, 112, 5 | fixed);
                        trap(&io, selected, false);
                        change(&io, selected, 104, 0xfffe0ff1 | rtm);
                        r.stop(7, selected as u32, 1, false)?;
                        let mut targets = 0;
                        r.capture_dispatch(selected as u32, true, 0x8000, || {
                            targets += 1;
                            Ok(())
                        })?;
                        ensure!(
                            targets == 1 && io.0.borrow().writes == 4 && !r.captured(),
                            "CSR call consumption differs"
                        );
                        {
                            let m = io.0.borrow();
                            ensure!(
                                m.contexts.values().all(|c| get(c, 104) == baseline)
                                    && get(&m.contexts[&selected], 72) == 0
                                    && get(&m.contexts[&selected], 80) == 0x8007
                                    && get(&m.contexts[&other], 72) == 0
                                    && get(&m.contexts[&other], 80) == 0,
                                "CSR all-thread disarm differs"
                            );
                        }
                        r.continued()?;
                        io.0.borrow_mut()
                            .contexts
                            .insert(13, vec![0; super::super::CONTEXT_SIZE]);
                        change(&io, 13, 104, baseline);
                        r.stop(7, 13, 2, false)?;
                        r.enroll(13, &mut 13, true)?;
                        r.continued()?;
                        ensure!(
                            io.0.borrow().writes == 4 && get(&io.0.borrow().contexts[&13], 72) == 0,
                            "CSR late generation armed after selection"
                        );
                        let second = first ^ 0x10800;
                        change(&io, other, 104, second);
                        change(&io, other, 112, fixed);
                        trap(&io, selected, true);
                        change(&io, selected, 104, 0xfffe0ff2 | rtm);
                        change(&io, selected, 184, u64::MAX);
                        change(&io, selected, 192, u64::MAX);
                        r.stop(7, selected as u32, 1, false)?;
                        r.capture_dispatch(selected as u32, true, 0x8007, || {
                            anyhow::bail!("target reread")
                        })?;
                        r.continued()?;
                        let state = r.observation();
                        let mut original = vec![0; super::super::CONTEXT_SIZE];
                        put(&mut original, 104, baseline);
                        ensure!(
                            io.0.borrow()
                                .contexts
                                .values()
                                .all(|current| super::super::raw_debug_equal(&original, current)
                                    .unwrap_or(false)),
                            "CSR paired restore did not preserve every baseline debug field"
                        );
                        ensure!(
                            state.captured
                                && state.base_equal
                                && state.restored
                                && !state.failed
                                && state.raw_eax == Some(0xc0150002)
                                && state.creator == creator
                                && io.0.borrow().writes == 6,
                            "CSR paired state differs"
                        );
                        let retained = if first != baseline || fixed != 0 {
                            first
                        } else {
                            second
                        };
                        let snapshot = format!(
                            " peer_raw_dr6=0x{retained:016X} peer_raw_dr7=0x{:016X} peer_status_attributed=False peer_transaction_context=unknown peer_bld_bit_set={}",
                            if first != baseline || fixed != 0 {
                                5 | fixed
                            } else {
                                fixed
                            },
                            b(retained & 0x800 != 0)
                        );
                        ensure!(
                            state.traps.ends_with(&snapshot)
                                && state.traps.matches("peer_raw_dr6=").count() == 1
                                && state.traps.contains("call_transaction_context=unknown")
                                && state.traps.contains("return_raw_dr6="),
                            "CSR first peer snapshot differs"
                        );
                        let writes = io.0.borrow().writes;
                        change(&io, 11, 104, 0xfffe17f0);
                        r.stop(7, 11, 1, false)?;
                        ensure!(
                            r.dispatch_software(11, true).is_err()
                                && r.observation().software.is_empty(),
                            "unknown CSR software accepted"
                        );
                        change(&io, 11, 104, 0xfffe07f0);
                        r.dispatch_software(11, true)?;
                        let software = r.observation().software;
                        change(&io, 11, 104, baseline);
                        ensure!(
                            r.dispatch_software(11, true).is_err()
                                && r.observation().software == software
                                && io.0.borrow().writes == writes,
                            "CSR software snapshot replaced"
                        );
                        r.continued()?;
                        r.stop(7, 12, 4, false)?;
                        r.continued()?;
                        io.0.borrow_mut()
                            .contexts
                            .insert(14, vec![0; super::super::CONTEXT_SIZE]);
                        r.stop(7, 12, 2, false)?;
                        ensure!(
                            r.enroll(12, &mut 14, true).is_err(),
                            "paired CSR reenrolled generation"
                        );
                        r.continued()?;
                        die(&mut r, false)?;
                        ensure!(
                            io.0.borrow().closes == 2 && r.observation().destroyed && !r.failed(),
                            "CSR destruction differs"
                        );
                        let metadata =
                            trace_metadata(&r.observation(), true, false, Role::PythonPass)?;
                        ensure!(
                            metadata.len() <= 1024
                                && metadata.is_ascii()
                                && metadata.contains("raw_return=0xC0150002")
                                && metadata.contains(&snapshot)
                                && metadata.contains("observation_qualified=True")
                                && !metadata.contains("000000000000800")
                                && !metadata.contains("0000000000009000"),
                            "CSR metadata differs"
                        );
                    }
                }
            }
        }
    }
    software()?;
    faults::check()?;
    Ok(())
}
fn software() -> Result<()> {
    for phase in 0..3 {
        for status in [0, 0xfffe07f0, 0xfffe0ff0, 0xffff07f0, 0xffff0ff0] {
            for fixed in [0, 0x400] {
                let (mut r, io) = setup(1, 0)?;
                if phase != 0 {
                    arm(&mut r)?;
                }
                if phase == 2 {
                    capture(&mut r, &io, 11, false)?;
                    capture(&mut r, &io, 11, true)?;
                }
                change(&io, 11, 104, status);
                change(&io, 11, 112, if phase == 1 { 5 | fixed } else { fixed });
                r.stop(7, 11, 1, false)?;
                let reads = io.0.borrow().reads;
                ensure!(
                    r.dispatch_software(12, true).is_err()
                        && r.dispatch_software(11, false).is_err()
                        && io.0.borrow().reads == reads,
                    "CSR software invalid event read context"
                );
                let accepted = if phase == 0 {
                    status == 0 && fixed == 0
                } else if phase == 1 {
                    status != 0
                } else {
                    status != 0 || fixed == 0
                };
                let result = r.dispatch_software(11, true);
                ensure!(
                    result.is_ok() == accepted,
                    "CSR software phase acceptance differs"
                );
                if accepted {
                    let first = r.observation().software;
                    ensure!(
                        first.contains(&format!("software_raw_dr6=0x{status:016X}"))
                            && r.dispatch_software(11, true).is_err()
                            && r.observation().software == first,
                        "CSR software once-only snapshot differs"
                    );
                }
                ensure!(
                    io.0.borrow().writes
                        == if phase == 0 {
                            0
                        } else if phase == 1 {
                            1
                        } else {
                            3
                        }
                        && r.captured() == (phase == 2)
                        && r.capture_restored() == (phase == 2),
                    "CSR software changed ownership"
                );
                r.continued()?;
            }
        }
    }
    Ok(())
}
