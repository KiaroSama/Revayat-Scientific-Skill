//! Exact pre-entry callback mode. Peer transport never authorizes creator-context reads.
use super::{
    boundary::{Boundary, BoundaryIo, BoundaryMode, Kernel},
    boundary_software as software, owned_trap_site, owned_trap_status, trap_qualifiers,
};
use crate::windows_security::image::{BoundarySites, KernelImage, PeImage};
use anyhow::{Result, ensure};
#[path = "module_callback_checks.rs"]
mod checks;
#[path = "module_callback_drain_checks.rs"]
mod drain_checks;
#[path = "module_callback_transport_checks.rs"]
mod transport_checks;
pub use checks::check_validation;
pub fn complete(stage: u8, restored: bool, invalidated: bool) -> bool {
    stage == 3 && restored && !invalidated
}
pub fn callback_result(context: &[u8]) -> Result<String> {
    Ok(format!(
        "failure_sentinel={}",
        if software::value(context, 120)? == u64::MAX {
            "True"
        } else {
            "False"
        }
    ))
}
impl<I: BoundaryIo> Boundary<'_, I> {
    pub(super) fn callback_peer_transport(&self, thread: u32, kind: u32) -> bool {
        self.mode == BoundaryMode::ModuleCallback
            && !self.callback_process_exited
            && !self.invalidated
            && (1..=3).contains(&self.stage)
            && thread != self.owner.tid
            && matches!(kind, 2 | 4)
    }
    pub(super) fn callback_software_stage(&self, thread: u32, code: u32, first: bool) -> bool {
        software::software_stage(
            software::SoftwareRole::Callback,
            self.stage,
            self.invalidated,
            self.software.initial(),
            software::SoftwareEvent {
                thread,
                creator: self.owner.tid,
                code,
                first,
            },
        )
    }
    pub(super) fn callback_hardware_stage(&self, thread: u32, first: bool) -> bool {
        !self.invalidated
            && self.stage == 2
            && first
            && thread == self.owner.tid
            && self.original.is_some()
            && self.kernel.is_some()
    }
    pub(super) fn callback_load_stage(&self) -> bool {
        !self.invalidated
            && self.stopped
            && self.alive
            && self.stage == 1
            && self.kernel.is_none()
            && !self.changed
            && !self.restored
    }
    pub(super) fn callback_stop_header(
        &self,
        pid: u32,
        thread: u32,
        kind: u32,
        cleanup: bool,
    ) -> String {
        format!(
            "phase=module-callback-stop-refusal kind={kind} process_match={} creator={} cleanup={} stage={} context_read=False",
            if pid == self.owner.pid {
                "True"
            } else {
                "False"
            },
            if thread == self.owner.tid {
                "True"
            } else {
                "False"
            },
            if cleanup { "True" } else { "False" },
            self.stage
        )
    }
    fn callback_refuse_stop(
        &mut self,
        check: &str,
        pid: u32,
        thread: u32,
        kind: u32,
        cleanup: bool,
    ) -> Result<()> {
        let metadata = self.callback_stop_header(pid, thread, kind, cleanup);
        super::boundary::require_check(false, check, || (self.emit)(&metadata))
    }
    pub(super) fn callback_stop(
        &mut self,
        pid: u32,
        thread: u32,
        kind: u32,
        cleanup: bool,
    ) -> Result<()> {
        self.stopped = false;
        if cleanup || pid != self.owner.pid {
            self.invalidate();
        }
        if pid != self.owner.pid {
            return self.callback_refuse_stop("callback-process", pid, thread, kind, cleanup);
        }
        if !cleanup
            && (self.callback_process_exited
                || !self.alive && thread == self.owner.tid && kind != 5
                || (kind == 5 || kind == 4 && thread == self.owner.tid)
                    && (self.invalidated || !(1..=3).contains(&self.stage)))
        {
            self.invalidate();
            return self.callback_refuse_stop("callback-lifecycle", pid, thread, kind, cleanup);
        }
        if kind == 5 {
            self.callback_process_exited = true;
            self.alive = false;
            return Ok(());
        }
        if kind == 4 && thread == self.owner.tid {
            self.alive = false;
            return Ok(());
        }
        if thread != self.owner.tid {
            if !cleanup && !self.callback_peer_transport(thread, kind) {
                self.invalidate();
                return self.callback_refuse_stop("callback-thread", pid, thread, kind, cleanup);
            }
            return Ok(());
        }
        self.stopped = self.alive;
        Ok(())
    }
    pub(super) fn callback_other_thread(&mut self, thread: u32, kind: u32) -> Result<()> {
        if self.callback_peer_transport(thread, kind) {
            ensure!(
                !self.stopped,
                "callback peer transport authorized creator context"
            );
            return (self.emit)(&format!(
                "phase=module-callback-peer-transport kind={kind} context_read=False observation_advanced=False"
            ));
        }
        if !self.callback_process_exited
            && !self.alive
            && !self.stopped
            && !self.invalidated
            && (1..=3).contains(&self.stage)
            && thread == self.owner.tid
            && kind == 4
        {
            return (self.emit)(
                "phase=module-callback-creator-retirement kind=4 context_read=False observation_advanced=False",
            );
        }
        self.invalidate();
        anyhow::bail!("fixed activation diagnostic encountered another thread transition")
    }
    pub(super) fn callback_load(
        &mut self,
        bytes: Vec<u8>,
        base: u64,
        sites: BoundarySites,
    ) -> Result<()> {
        ensure!(
            self.callback_load_stage(),
            "callback LOAD is duplicated, late or invalidated"
        );
        let image = KernelImage::with_subject(&bytes, base, "kernel32.dll")?;
        let site = image.module_callback_site()?;
        let pe = PeImage::parse(&bytes, base)?;
        let executable = self.require_executable(&pe, site, 5);
        self.kernel = Some(Kernel { bytes, base, sites });
        executable?;
        let mut before = self.read()?;
        let result = (|| {
            self.callback_load_ownership(&before)?;
            self.addresses[0] = base + u64::from(site);
            self.enabled[0] = true;
            self.stage = 2;
            self.apply(&before, false)
        })();
        before.fill(0);
        result?;
        (self.emit)(
            "phase=module-callback-load identity_equal=True fixed_profile=True dr0_armed=True entry_armed=False control_integer_unchanged=True",
        )
    }
    pub(super) fn callback_load_ownership(&mut self, context: &[u8]) -> Result<()> {
        if self.software.initial() {
            self.ownership(context, false)
        } else {
            self.software.callback_load_ownership(
                context,
                self.original
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("callback LOAD baseline is absent"))?,
                &self.addresses,
                &self.enabled,
            )
        }
    }
    pub(super) fn callback_single_step(
        &mut self,
        thread: u32,
        code: u32,
        first: bool,
        exception: u64,
    ) -> Result<bool> {
        if code != 0x80000004 {
            return Ok(false);
        }
        self.check(
            self.callback_hardware_stage(thread, first),
            "hardware-stage",
            None,
        )?;
        let mut before = self.read()?;
        let result = (|| {
            let status = software::value(&before, 104)?;
            self.ownership(&before, true)?;
            self.check(
                owned_trap_site(
                    thread,
                    self.owner.tid,
                    first,
                    self.enabled[0],
                    software::value(&before, 248)?,
                    self.addresses[0],
                ) && exception == software::value(&before, 248)?
                    && owned_trap_status(
                        status,
                        software::value(&before, 112)?,
                        software::control(self.original.as_deref().unwrap(), &self.enabled)?,
                        0,
                    ),
                "hardware-trap",
                Some(&before),
            )?;
            let scalar = callback_result(&before)?;
            self.addresses[0] = 0;
            self.enabled[0] = false;
            self.apply(&before, true)?;
            self.stage = 3;
            (self.emit)(&format!(
                "phase=module-callback-result {scalar} {} process_level=True invocation_module_verified=False runtime_callee_verified=False restored=True control_integer_unchanged=True cause_claimed=False",
                trap_qualifiers(status)
            ))
        })();
        before.fill(0);
        result?;
        Ok(true)
    }
}
