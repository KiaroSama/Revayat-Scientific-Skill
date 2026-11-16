//! Two-slot creator-thread diagnostic state and exact bounded checkpoint reads.
//! All process/context I/O is supplied by an actual stopped-debug-event owner.
use super::{activation, boolean, put, value};
use anyhow::{Result, ensure};
#[path = "hardware_checks.rs"]
mod checks;
#[path = "loader_trace_checks.rs"]
mod loader_checks;
pub use checks::check_hardware_trace_validation;
pub use loader_checks::check_loader_trace_validation;
pub const CAUSE_MASK: u64 = 0xe00f;
pub const OCCUPIED_CONTROL: u64 = 0xffff28ff;
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct MemoryRegion {
    pub address: usize,
    pub allocation_base: usize,
    pub allocation_protection: u32,
    pub partition: u16,
    pub size: usize,
    pub state: u32,
    pub protection: u32,
    pub kind: u32,
}
pub fn require_checkpoint_region(
    info: MemoryRegion,
    address: u64,
    image_base: u64,
    expected_rva: u32,
) -> Result<()> {
    let start = info.address as u64;
    let length = info.size as u64;
    const USER_MAX: u64 = 0x7fffffffffffffff;
    ensure!(
        image_base != 0
            && image_base <= USER_MAX - u64::from(expected_rva) - 2
            && address == image_base + u64::from(expected_rva)
            && start <= address
            && start <= USER_MAX
            && length <= USER_MAX - start
            && address - start <= length
            && 2 <= length - (address - start)
            && info.state == 0x1000
            && info.kind == 0x1000000
            && info.allocation_base as u64 == image_base
            && matches!(info.protection, 4 | 8),
        "checkpoint read is not the complete fixed committed non-executable writable image span"
    );
    Ok(())
}
pub fn decode_checkpoint(copied: bool, count: u64, mut bytes: Option<&mut [u8]>) -> Result<u16> {
    let result = (|| {
        ensure!(
            copied && count == 2 && bytes.as_ref().is_some_and(|bytes| bytes.len() == 2),
            "checkpoint read did not return exactly one complete WORD"
        );
        let bytes = bytes.as_deref().unwrap();
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    })();
    if let Some(bytes) = bytes.as_mut() {
        bytes.fill(0);
    }
    result
}
pub trait CheckpointIo {
    fn query(&mut self, address: u64) -> Result<MemoryRegion>;
    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(bool, u64)>;
}
pub fn read_checkpoint(
    io: &mut impl CheckpointIo,
    address: u64,
    image_base: u64,
    expected_rva: u32,
) -> Result<u16> {
    require_checkpoint_region(io.query(address)?, address, image_base, expected_rva)?;
    let mut bytes = [0; 2];
    match io.read(address, &mut bytes) {
        Ok((copied, count)) => decode_checkpoint(copied, count, Some(&mut bytes)),
        Err(error) => {
            bytes.fill(0);
            Err(error)
        }
    }
}
pub fn raw_checkpoint(value: u16) -> String {
    format!("raw_checkpoint=0x{value:04X}")
}
pub fn raw_site_value(context: &[u8]) -> Result<String> {
    Ok(format!("raw_eax=0x{:08X}", value(context, 120)? as u32))
}
pub fn can_restore(changed: bool, alive: bool, pending: bool) -> bool {
    changed && alive && pending
}
pub fn pair(
    current_stack: u64,
    entry_stack: u64,
    current_address: u64,
    return_address: u64,
) -> bool {
    entry_stack.checked_add(8) == Some(current_stack) && current_address == return_address
}
pub fn free_debug_state(context: &[u8]) -> Result<bool> {
    for offset in (72..104).step_by(8) {
        if value(context, offset)? != 0 {
            return Ok(false);
        }
    }
    Ok(value(context, 112)? & OCCUPIED_CONTROL == 0 && value(context, 104)? & CAUSE_MASK == 0)
}
pub fn require_site_window(outer_pending: bool, consumed: bool, returning: bool) -> Result<()> {
    ensure!(
        outer_pending && !consumed && !returning,
        "one-shot site is outside its unconsumed outer attach window"
    );
    Ok(())
}
pub fn arm_site_window(
    entries: &[u64; 2],
    active: &mut [u64; 2],
    slots: &mut [bool; 2],
    consumed: bool,
) -> Result<()> {
    ensure!(
        !consumed && entries[1] != 0 && entries[1] != active[0] && !slots[1],
        "hardware attach window lacks a distinct inactive unconsumed site"
    );
    active[1] = entries[1];
    slots[1] = true;
    Ok(())
}
pub fn consume_site(active: &mut [u64; 2], slots: &mut [bool; 2]) {
    active[1] = 0;
    slots[1] = false;
}
pub fn require_observation_complete(consumed: bool, paired: bool, restored: bool) -> Result<()> {
    ensure!(
        consumed && paired && restored,
        "one-shot diagnostic is inconclusive: site, outer pair or restoration missing"
    );
    Ok(())
}
pub fn ownership_metadata(
    current: &[u8],
    baseline: &[u8],
    status: u64,
    control: u64,
) -> Result<String> {
    let dr6 = value(current, 104)?;
    let dr7 = value(current, 112)?;
    Ok(format!(
        "dr2_match={} dr3_match={} dr7_control_match={} dr6_unowned_match={} dr6_cause_mask=0x{:016X} dr6_other_bits_xor=0x{:016X} dr6_expected=0x{status:016X} dr6_actual=0x{dr6:016X} dr7_expected=0x{control:016X} dr7_actual=0x{dr7:016X}",
        boolean(value(current, 88)? == value(baseline, 88)?),
        boolean(value(current, 96)? == value(baseline, 96)?),
        boolean(dr7 == control),
        boolean(dr6 & !3 == status & !3),
        dr6 & CAUSE_MASK,
        (dr6 ^ status) & !CAUSE_MASK
    ))
}
pub trait ContextIo {
    fn read_context(&mut self) -> Result<Vec<u8>>;
    fn write_context(&mut self, desired: &[u8]) -> Result<()>;
}
pub struct HardwareWindow {
    pid: u32,
    tid: u32,
    original: Option<Vec<u8>>,
    entries: [u64; 2],
    addresses: [u64; 2],
    returns: [u64; 2],
    stacks: [u64; 2],
    entry_statuses: [u64; 2],
    enabled: [bool; 2],
    returning: [bool; 2],
    site_consumed: bool,
    outer_paired: bool,
    restored: bool,
    invalidated: bool,
    creator_alive: bool,
    stopped: bool,
    modified: bool,
    completed: bool,
}
impl HardwareWindow {
    pub fn new(process: usize, thread: usize, pid: u32, tid: u32) -> Result<Self> {
        ensure!(
            std::mem::size_of::<usize>() == 8
                && std::mem::size_of::<MemoryRegion>() == 48
                && process != 0
                && thread != 0,
            "hardware trace requires verified Windows x64 ABI and owned handles"
        );
        Ok(Self {
            pid,
            tid,
            original: None,
            entries: [0; 2],
            addresses: [0; 2],
            returns: [0; 2],
            stacks: [0; 2],
            entry_statuses: [0; 2],
            enabled: [false; 2],
            returning: [false; 2],
            site_consumed: false,
            outer_paired: false,
            restored: false,
            invalidated: false,
            creator_alive: true,
            stopped: false,
            modified: false,
            completed: false,
        })
    }
    pub fn stop(&mut self, pid: u32, tid: u32, kind: u32) -> Result<()> {
        ensure!(
            pid == self.pid,
            "hardware event is not the fixed owned process"
        );
        self.stopped = true;
        if kind == 5 || kind == 4 && tid == self.tid {
            self.creator_alive = false;
        }
        Ok(())
    }
    pub fn continued(&mut self) {
        self.stopped = false;
    }
    fn live_stop(&self) -> Result<()> {
        ensure!(
            self.stopped && self.creator_alive,
            "hardware context access requires a pending live debug event"
        );
        Ok(())
    }
    pub fn save(&mut self, io: &mut impl ContextIo) -> Result<()> {
        if self.original.is_some() {
            return Ok(());
        }
        self.live_stop()?;
        let original = io.read_context()?;
        ensure!(
            free_debug_state(&original)?,
            "hardware trace refuses existing debug-register ownership"
        );
        self.original = Some(original);
        Ok(())
    }
    pub fn require_single_step(&self, event_thread: u32, code: u32, first: bool) -> Result<bool> {
        if code != 0x80000004 {
            return Ok(false);
        }
        ensure!(
            !self.completed,
            "single-step arrived after the fixed observation window closed"
        );
        ensure!(
            event_thread == self.tid && first && self.original.is_some(),
            "hardware single-step cannot be attributed to owned creator protocol"
        );
        self.live_stop()?;
        Ok(true)
    }
    pub fn require_complete(&self) -> Result<()> {
        require_observation_complete(self.site_consumed, self.outer_paired, self.restored)?;
        ensure!(
            !self.invalidated,
            "one-shot diagnostic window invalidated after observation"
        );
        Ok(())
    }
    pub fn invalidate(&mut self) {
        self.invalidated = true;
    }
    /// Restoration sets only DEBUG_REGISTERS, verifies real readback and retains
    /// the modified flag on every failed setter/readback so cleanup can retry.
    pub fn restore(&mut self, io: &mut impl ContextIo) -> Result<bool> {
        if !can_restore(self.modified, self.creator_alive, self.stopped) {
            return Ok(false);
        }
        self.live_stop()?;
        let before = io.read_context()?;
        activation::unchanged_control_integer(&before, &before)?;
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("hardware restoration lacks saved context"))?;
        let mut desired = before.clone();
        for offset in (72..120).step_by(8) {
            put(&mut desired, offset, value(original, offset)?);
        }
        desired[48..52].copy_from_slice(&0x100010u32.to_le_bytes());
        self.modified = true;
        io.write_context(&desired)?;
        let after = io.read_context()?;
        ensure!(
            activation::unchanged_control_integer(&before, &after)?,
            "hardware context write altered CONTROL/INTEGER state"
        );
        ensure!(
            activation::raw_debug_equal(&desired, &after)?,
            "hardware debug-register readback differs from exact requested state"
        );
        self.modified = false;
        self.completed = true;
        self.restored = true;
        self.enabled.fill(false);
        self.returning.fill(false);
        Ok(true)
    }
    pub fn destroyed(&mut self) {
        self.creator_alive = false;
        self.modified = false;
        if let Some(original) = self.original.as_mut() {
            original.fill(0);
        }
        self.entries.fill(0);
        self.addresses.fill(0);
        self.returns.fill(0);
        self.stacks.fill(0);
        self.entry_statuses.fill(0);
    }
}
