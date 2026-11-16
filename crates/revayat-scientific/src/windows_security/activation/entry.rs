//! Creator-scoped explicit entry state, separate from all-thread resource and CSR modes.
use super::{
    activation_event,
    boundary_software::{self as software, SoftwareEvent, SoftwarePresentation, SoftwareRole},
    owned_trap_site, owned_trap_status, raw_debug_equal,
    threads::ContextIo,
    trap_qualifiers, unchanged_control_integer,
};
use crate::windows_security::image::PeImage;
use anyhow::{Result, ensure};
use std::cell::{Cell, RefCell};
#[path = "entry_checks.rs"]
mod checks;
#[path = "entry_lifetime_checks.rs"]
mod lifetime;
pub use checks::{check_explicit_entry_validation, check_software_presentation};
pub use lifetime::{check_entry_event_validation, check_entry_lifetime_validation};
pub struct Entry<I: ContextIo> {
    pid: u32,
    creator: u32,
    handle: usize,
    io: I,
    stage: u8,
    stopped: bool,
    alive: bool,
    invalidated: bool,
    changed: bool,
    restored: bool,
    hit: bool,
    natural_exit: bool,
    destroyed: bool,
    base: u64,
    baseline: Option<Vec<u8>>,
    sites: [u64; 2],
    enabled: [bool; 2],
    trap: String,
    software: SoftwarePresentation,
}
impl<I: ContextIo> Entry<I> {
    pub fn new(pid: u32, creator: u32, handle: usize, io: I) -> Result<Self> {
        software::require_modes(software::ObservationRoles {
            entry: true,
            ..Default::default()
        })?;
        ensure!(
            pid != 0 && creator != 0 && handle != 0 && handle != usize::MAX,
            "fixed entry owner is absent"
        );
        Ok(Self {
            pid,
            creator,
            handle,
            io,
            stage: 0,
            stopped: false,
            alive: true,
            invalidated: false,
            changed: false,
            restored: false,
            hit: false,
            natural_exit: false,
            destroyed: false,
            base: 0,
            baseline: None,
            sites: [0; 2],
            enabled: [false; 2],
            trap: String::new(),
            software: SoftwarePresentation::default(),
        })
    }
    pub fn stop(&mut self, pid: u32, thread: u32, kind: u32, cleanup: bool) -> Result<()> {
        self.stopped = false;
        if cleanup || pid != self.pid {
            self.invalidate();
        }
        ensure!(pid == self.pid, "fixed entry event process differs");
        if kind == 5 || kind == 4 && thread == self.creator {
            self.alive = false;
        }
        if !cleanup && kind == 1 && thread != self.creator {
            self.invalidate();
            anyhow::bail!("fixed entry exception is not creator-scoped");
        }
        self.stopped = self.alive && thread == self.creator;
        Ok(())
    }
    pub fn continued(&mut self) {
        self.stopped = false;
    }
    pub fn restoration_allowed(&self) -> bool {
        self.stopped && self.alive && self.changed && self.baseline.is_some()
    }
    pub fn invalidate(&mut self) {
        self.invalidated = true;
    }
    pub fn creation(&mut self, image: &PeImage<'_>) -> Result<()> {
        ensure!(
            self.stage == 0
                && self.stopped
                && self.alive
                && !self.invalidated
                && image.entry != 0
                && image.executable(image.entry, 1),
            "fixed entry creation state differs"
        );
        let mut original = self.io.read(self.handle)?;
        let result = (|| {
            ensure!(
                software::free(&original)?,
                "fixed entry baseline has foreign ownership"
            );
            self.base = image.base;
            self.sites[0] = image
                .base
                .checked_add(u64::from(image.entry))
                .ok_or_else(|| anyhow::anyhow!("fixed entry address overflow"))?;
            self.enabled[0] = true;
            self.stage = 1;
            self.baseline = Some(original.clone());
            self.apply(&original, false)
        })();
        original.fill(0);
        result
    }
    fn apply(&mut self, before: &[u8], restore: bool) -> Result<()> {
        ensure!(
            self.stopped && self.alive,
            "fixed entry setter lifetime differs"
        );
        let baseline = self
            .baseline
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("fixed entry baseline absent"))?;
        let mut desired = software::desired(before, baseline, &self.sites, &self.enabled, restore)?;
        self.changed = true;
        let mut after = Vec::new();
        let result = (|| {
            self.io.write(self.handle, &desired)?;
            after = self.io.read(self.handle)?;
            ensure!(
                raw_debug_equal(&desired, &after)? && unchanged_control_integer(before, &after)?,
                "fixed entry setter readback differs"
            );
            if restore {
                self.changed = false;
                self.restored = true;
            }
            Ok(())
        })();
        desired.fill(0);
        after.fill(0);
        result
    }
    pub fn restore(&mut self) -> Result<()> {
        if !self.restoration_allowed() {
            return Ok(());
        }
        let mut before = self.io.read(self.handle)?;
        let result = self.apply(&before, true);
        before.fill(0);
        result
    }
    pub fn software_stage(&self, event: SoftwareEvent) -> bool {
        software::software_stage(
            SoftwareRole::Entry,
            self.stage,
            self.invalidated,
            self.software.initial(),
            event,
        )
    }
    pub fn accept_software(&mut self, event: SoftwareEvent) -> Result<bool> {
        if event.code != 0x80000003 {
            return Ok(false);
        }
        ensure!(
            self.software_stage(event),
            "fixed entry software event differs"
        );
        let mut bytes = self.io.read(self.handle)?;
        let result = self.software.accept(
            &bytes,
            self.baseline
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("fixed entry baseline absent"))?,
            &self.sites,
            &self.enabled,
        );
        bytes.fill(0);
        result?;
        Ok(true)
    }
    pub fn single_step(&mut self, event: SoftwareEvent, exception: u64) -> Result<bool> {
        if event.code != 0x80000004 {
            return Ok(false);
        }
        ensure!(
            !self.invalidated
                && self.stage == 1
                && !self.hit
                && self.baseline.is_some()
                && self.stopped
                && self.alive,
            "fixed entry single-step state differs"
        );
        let mut bytes = self.io.read(self.handle)?;
        let result = self.hardware_context(event.thread, event.first, exception, &bytes, |owner| {
            owner.apply(&bytes, true)
        });
        bytes.fill(0);
        result?;
        Ok(true)
    }
    pub fn hardware_context(
        &mut self,
        thread: u32,
        first: bool,
        exception: u64,
        bytes: &[u8],
        restore: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        let baseline = self
            .baseline
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("fixed entry baseline absent"))?;
        software::ownership(bytes, baseline, &self.sites, &self.enabled, true)?;
        let status = software::value(bytes, 104)?;
        ensure!(
            trap_accepted(
                thread,
                self.creator,
                first,
                self.enabled[0],
                software::value(bytes, 248)?,
                self.sites[0],
                exception,
                status,
                software::value(bytes, 112)?,
                software::control(baseline, &self.enabled)?
            ),
            "fixed entry hardware observation differs"
        );
        self.entry_hit(status, restore)
    }
    pub fn entry_hit(
        &mut self,
        status: u64,
        restore: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            !self.hit && self.stage == 1,
            "fixed entry first hit was already consumed"
        );
        self.hit = true;
        self.trap = format!(" {}", trap_qualifiers(status));
        restore(self)?;
        self.sites[0] = 0;
        self.enabled[0] = false;
        self.stage = 2;
        Ok(())
    }
    pub fn exit(&mut self) -> Result<()> {
        ensure!(
            !self.alive && !self.invalidated && self.stage >= 1,
            "fixed entry exit state differs"
        );
        self.natural_exit = true;
        Ok(())
    }
    pub fn unload(&mut self, base: u64) -> Result<()> {
        if base == self.base {
            self.invalidate();
            anyhow::bail!("fixed entry image was unloaded");
        }
        Ok(())
    }
    pub fn destroyed(&mut self) -> Result<()> {
        ensure!(!self.alive, "fixed entry destruction lacks process death");
        if let Some(mut baseline) = self.baseline.take() {
            baseline.fill(0);
        }
        self.destroyed = true;
        Ok(())
    }
    pub fn complete(&self) -> bool {
        self.hit && self.restored && self.natural_exit && !self.invalidated
    }
    pub fn require_complete(&self) -> Result<()> {
        ensure!(self.complete(), "fixed entry observation is incomplete");
        Ok(())
    }
    pub fn metadata(&self) -> Result<String> {
        ensure!(self.destroyed, "fixed entry metadata precedes destruction");
        let line = format!(
            "WINDOWS_EXPLICIT_ENTRY traced=True creator_scope=True entry_observed={} restored={} natural_exit={} state_destroyed=True observation_qualified={}{}{} cause_claimed=False undebugged_equivalence_claimed=False",
            b(self.hit),
            b(self.restored),
            b(self.natural_exit),
            b(self.complete()),
            self.trap,
            self.software.snapshot().unwrap_or("")
        );
        ensure!(
            line.len() <= 1024,
            "fixed resource observation refused check=entry-metadata-budget"
        );
        Ok(line)
    }
}
impl<I: ContextIo> Drop for Entry<I> {
    fn drop(&mut self) {
        if let Some(bytes) = &mut self.baseline {
            bytes.fill(0);
        }
    }
}
fn b(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}
#[allow(clippy::too_many_arguments)]
pub fn trap_accepted(
    thread: u32,
    creator: u32,
    first: bool,
    active: bool,
    rip: u64,
    configured: u64,
    exception: u64,
    status: u64,
    control: u64,
    expected: u64,
) -> bool {
    owned_trap_site(thread, creator, first, active, rip, configured)
        && exception == configured
        && owned_trap_status(status, control, expected, 0)
}
pub fn metadata_event(kind: u32) -> bool {
    matches!(kind, 2 | 4 | 6 | 7 | 8)
}
pub struct Event {
    pub kind: u32,
    pub unloaded: u64,
    pub cleanup: bool,
}
pub fn finalize_entry_event<'a, I: ContextIo>(
    observer: &RefCell<Entry<I>>,
    event: Event,
    exception: impl FnOnce(&mut Entry<I>) -> Result<()>,
    exit: impl FnOnce() -> Result<()>,
    releases: Vec<Box<dyn FnMut() -> Result<()> + 'a>>,
    continuation: impl FnOnce(u32) -> Result<()>,
) -> Result<()> {
    let status = Cell::new(if event.kind == 1 { 0x80010001 } else { 0x10002 });
    let result = activation_event(
        || {
            let mut observer = observer.borrow_mut();
            if event.cleanup {
                observer.invalidate();
                if event.kind == 5 {
                    exit()?;
                }
                return Ok(());
            }
            match event.kind {
                1 => {
                    exception(&mut observer)?;
                    status.set(0x10002);
                }
                5 => {
                    observer.exit()?;
                    exit()?;
                }
                7 => observer.unload(event.unloaded)?,
                _ => ensure!(
                    metadata_event(event.kind),
                    "fixed entry observation received an unsupported event"
                ),
            };
            Ok(())
        },
        || {
            let mut observer = observer.borrow_mut();
            observer.invalidate();
            observer.restore()
        },
        releases,
        || continuation(status.get()),
    );
    if result.is_err() {
        observer.borrow_mut().invalidate();
    }
    result
}
