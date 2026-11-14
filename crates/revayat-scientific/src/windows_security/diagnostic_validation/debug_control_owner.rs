//! Exact one-site trusted DebugControl register protocol; OS ownership stays with its native caller.
use super::*;
use crate::windows_security::diagnostic_validation::hardware::ContextIo;
use anyhow::Context;

pub(in crate::windows_security) trait ControlIo: ContextIo {
    fn emit_control(&mut self, line: &str) -> Result<()>;
}
/// This controller contains no native process, retirement or success capability.
/// The native event owner must qualify the actual compiled subject and site first.
pub(in crate::windows_security) struct ControlState {
    creator: u32,
    saved: Option<Vec<u8>>,
    address: u64,
    pending: bool,
    live: bool,
    changed: bool,
    initial: bool,
    hit: bool,
    exited: bool,
}
impl ControlState {
    pub(in crate::windows_security) fn new(creator: u32) -> Result<Self> {
        ensure!(creator != 0, "fixed control creator thread is absent");
        Ok(Self {
            creator,
            saved: None,
            address: 0,
            pending: false,
            live: true,
            changed: false,
            initial: false,
            hit: false,
            exited: false,
        })
    }
    /// Must run immediately after actual WaitForDebugEventEx, before dispatch or cleanup.
    pub(in crate::windows_security) fn received(&mut self, thread: u32, kind: u32) -> Result<()> {
        ensure!(!self.pending, "fixed control event is already pending");
        self.pending = true;
        if kind == 5 || kind == 4 && thread == self.creator {
            self.live = false;
        }
        Ok(())
    }
    /// Call only after the real ContinueDebugEvent succeeds.
    pub(in crate::windows_security) fn continued(&mut self) {
        self.pending = false;
    }
    fn stopped(&self) -> Result<()> {
        ensure!(
            self.pending && self.live,
            "fixed control requires a stopped live creator"
        );
        Ok(())
    }
    fn write(
        &mut self,
        io: &mut impl ControlIo,
        before: &[u8],
        mut desired: Vec<u8>,
        stage: &str,
    ) -> Result<()> {
        self.stopped()?;
        let result = (|| {
            ensure!(
                desired.len() == activation::CONTEXT_SIZE,
                "fixed control context length differs"
            );
            desired[48..52].copy_from_slice(&0x100010u32.to_le_bytes());
            // A failed setter can have changed the real registers. Retain restoration duty.
            self.changed = true;
            io.write_context(&desired)?;
            let mut after = io.read_context()?;
            let checked = (|| {
                // Original observes raw OS normalization before rejecting it.
                io.emit_control(&debug_control_status(stage, &desired, &after)?)?;
                ensure!(
                    activation::unchanged_control_integer(before, &after)?
                        && activation::raw_debug_equal(&desired, &after)?,
                    "fixed control raw context readback is inconclusive"
                );
                Ok(())
            })();
            after.fill(0);
            checked
        })();
        desired.fill(0);
        result
    }
    /// Actual CREATE hFile, full producer identity and committed six-byte image span are caller obligations.
    pub(in crate::windows_security) fn creation(
        &mut self,
        io: &mut impl ControlIo,
        thread: u32,
        address: u64,
    ) -> Result<()> {
        self.stopped()?;
        ensure!(
            thread == self.creator && self.saved.is_none() && address != 0,
            "fixed control creation event is ambiguous"
        );
        let before = io.read_context()?;
        ensure!(
            before.len() == activation::CONTEXT_SIZE,
            "fixed control baseline length differs"
        );
        self.saved = Some(before.clone());
        self.address = address;
        io.emit_control(&format!(
            "site_bytes_qualified=True transaction_context=unknown launch_context=trusted_host {}",
            debug_control_status("baseline", &before, &before)?
        ))?;
        for offset in (72..=96).step_by(8) {
            ensure!(
                value(&before, offset)? == 0,
                "fixed control refuses occupied debug addresses"
            );
        }
        ensure!(
            value(&before, 112)? & 0xffff2bff == 0 && value(&before, 104)? & 0xe00f == 0,
            "fixed control refuses pre-existing debug control/cause"
        );
        let mut desired = before.clone();
        put(&mut desired, 72, address);
        put(&mut desired, 112, value(&before, 112)? | 1);
        self.write(io, &before, desired, "arm-readback")
    }
    pub(in crate::windows_security) fn restore(&mut self, io: &mut impl ControlIo) -> Result<()> {
        if !self.changed || self.saved.is_none() || !self.pending || !self.live {
            return Ok(());
        }
        let mut before = io.read_context()?;
        let result = (|| {
            let mut desired = before.clone();
            let saved = self.saved.as_ref().unwrap();
            for offset in (72..=112).step_by(8) {
                put(&mut desired, offset, value(saved, offset)?);
            }
            self.write(io, &before, desired, "restore-readback")?;
            self.changed = false;
            Ok(())
        })();
        before.fill(0);
        result
    }
    pub(in crate::windows_security) fn exception(
        &mut self,
        io: &mut impl ControlIo,
        thread: u32,
        code: u32,
        first: bool,
    ) -> Result<()> {
        self.stopped()?;
        if code == 0x80000003 && first && thread == self.creator && !self.hit && !self.initial {
            self.initial = true;
            return Ok(());
        }
        ensure!(
            code == 0x80000004 && first && thread == self.creator && !self.hit,
            "fixed control observed an unexpected exception/thread"
        );
        let mut context = io.read_context()?;
        let result = (|| {
            let saved = self
                .saved
                .as_ref()
                .context("fixed control creation baseline absent")?;
            let dr6 = value(&context, 104)?;
            let dr7 = value(&context, 112)?;
            io.emit_control(&format!(
                "stage=known-site-event {} raw_dr7=0x{dr7:016X} setter_readback_claimed=False",
                activation::trap_qualifiers(dr6)
            ))?;
            ensure!(
                activation::owned_trap_site(
                    thread,
                    self.creator,
                    first,
                    dr7 & 1 != 0,
                    value(&context, 248)?,
                    self.address
                ) && value(&context, 72)? == self.address
                    && dr6 & 0xe00f == 1,
                "fixed control B0 cannot be paired to the qualified site"
            );
            for offset in (80..=96).step_by(8) {
                ensure!(
                    value(&context, offset)? == value(saved, offset)?,
                    "fixed control unowned debug address changed"
                );
            }
            ensure!(
                activation::owned_trap_status(dr6, dr7, value(saved, 112)? | 1, 0),
                "fixed control observed an unsupported owned-trap qualifier"
            );
            self.hit = true;
            self.restore(io)?;
            io.emit_control(&format!(
                "known_site_b0=True {} normalization_approved=False",
                activation::trap_qualifiers(dr6)
            ))
        })();
        context.fill(0);
        result
    }
    pub(in crate::windows_security) fn process_exit(&mut self, code: u32) -> Result<()> {
        ensure!(
            self.pending && !self.live && self.hit && !self.changed && code == 0,
            "fixed control did not complete its qualified site/exit"
        );
        self.exited = true;
        Ok(())
    }
    pub(in crate::windows_security) fn require_complete(&self) -> Result<()> {
        ensure!(
            self.saved.is_some() && self.hit && !self.changed && self.exited && !self.pending,
            "fixed control observation is incomplete"
        );
        Ok(())
    }
}
impl Drop for ControlState {
    fn drop(&mut self) {
        if let Some(saved) = &mut self.saved {
            saved.fill(0);
        }
    }
}
