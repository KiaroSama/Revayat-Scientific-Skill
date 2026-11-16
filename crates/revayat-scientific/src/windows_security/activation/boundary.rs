//! Creator-scoped activation caller-site state, separate from all-thread CSR/resource modes.
//! Native callers supply actual event-file identity binding and stopped-thread I/O.
use super::{
    Failures,
    boundary_software::{self as software, SoftwareEvent, SoftwarePresentation, SoftwareRole},
    owned_trap_site, owned_trap_status, raw_debug_equal,
    threads::ContextIo,
    trap_qualifiers, unchanged_control_integer,
};
use crate::windows_security::{
    diagnostic_validation::static_kernel::SameRunBinding,
    image::{self, BoundarySites, KernelImage, PeImage},
};
use anyhow::{Result, ensure};
use std::path::{Path, PathBuf};
#[path = "boundary_checks.rs"]
mod checks;
pub use checks::check_validation;
#[path = "boundary_check_io.rs"]
pub(super) mod check_io;
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct MemoryRegion {
    pub address: usize,
    pub allocation: usize,
    pub allocation_protection: u32,
    pub partition: u16,
    pub size: usize,
    pub state: u32,
    pub protection: u32,
    pub kind: u32,
}
pub trait BoundaryIo: ContextIo {
    fn region(&mut self, process: usize, address: u64) -> Result<MemoryRegion>;
}
#[derive(Clone, Copy, Debug)]
pub struct BoundaryOwner {
    pub process: usize,
    pub thread: usize,
    pub pid: u32,
    pub tid: u32,
}
pub struct FixtureBinding {
    pub path: PathBuf,
    pub digest: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryMode {
    Child,
    ModuleCallback,
}
pub(super) struct ImageSpan {
    pub base: u64,
    pub entry: u32,
}
pub(super) struct Kernel {
    pub bytes: Vec<u8>,
    pub base: u64,
    pub sites: BoundarySites,
}
type BoundaryReport<'a> = Box<dyn FnMut(&str) -> Result<()> + 'a>;
pub struct Boundary<'a, I: BoundaryIo> {
    pub(super) owner: BoundaryOwner,
    pub(super) binding: FixtureBinding,
    pub(super) mode: BoundaryMode,
    pub(super) io: I,
    pub(super) emit: BoundaryReport<'a>,
    pub(super) fixture: Option<ImageSpan>,
    pub(super) kernel: Option<Kernel>,
    pub(super) original: Option<Vec<u8>>,
    pub(super) stage: u8,
    pub(super) addresses: [u64; 2],
    pub(super) enabled: [bool; 2],
    pub(super) software: SoftwarePresentation,
    pub(super) stopped: bool,
    pub(super) changed: bool,
    pub(super) restored: bool,
    pub(super) invalidated: bool,
    pub(super) alive: bool,
    pub(super) event_code: u32,
    pub(super) event_creator: bool,
    pub(super) event_first: bool,
    pub(super) callback_process_exited: bool,
}
pub fn next(stage: u8, slot: usize, raw: u32) -> Result<u8> {
    match (stage, slot) {
        (1, 0) => Ok(2),
        (2, 0) => Ok(3),
        (3, 0) => Ok(4),
        (4, 1) if raw & 0x80000000 != 0 => Ok(5),
        _ => anyhow::bail!("fixed activation observation order is invalid"),
    }
}
pub fn complete(stage: u8, restored: bool, invalidated: bool) -> bool {
    stage == 5 && restored && !invalidated
}
pub fn raw(value: u64) -> String {
    format!("raw_ebx=0x{:08X}", value as u32)
}
fn software_stop_metadata(mode: BoundaryMode, status: u64) -> String {
    let phase = match mode {
        BoundaryMode::Child => "activation-software-stop",
        BoundaryMode::ModuleCallback => "module-callback-software-stop",
    };
    format!(
        "phase={phase} origin_verified=False ordering_only=True {}",
        trap_qualifiers(status)
    )
}
pub fn registry_result(context: &[u8]) -> Result<String> {
    Ok(format!(
        "raw_eax=0x{:08X}",
        software::value(context, 120)? as u32
    ))
}
pub fn executable_region(info: MemoryRegion, address: u64, bytes: u32, image: u64) -> bool {
    let start = info.address as u64;
    let size = info.size as u64;
    let access = info.protection & 0xff;
    bytes != 0
        && address >= start
        && address - start <= size
        && u64::from(bytes) <= size - (address - start)
        && info.state == 0x1000
        && info.kind == 0x1000000
        && info.allocation as u64 == image
        && info.protection & 0x100 == 0
        && matches!(access, 0x10 | 0x20 | 0x40 | 0x80)
}
pub fn require_check(value: bool, check: &str, report: impl FnOnce() -> Result<()>) -> Result<()> {
    if value {
        return Ok(());
    }
    let primary = anyhow::anyhow!("fixed activation observation refused check={check}");
    match report() {
        Ok(()) => Err(primary),
        Err(reporting) => Err(Failures {
            errors: vec![primary, reporting],
        }
        .into()),
    }
}
impl<'a, I: BoundaryIo> Boundary<'a, I> {
    pub fn new(
        owner: BoundaryOwner,
        binding: FixtureBinding,
        mode: BoundaryMode,
        io: I,
        emit: impl FnMut(&str) -> Result<()> + 'a,
    ) -> Result<Self> {
        software::require_modes(software::ObservationRoles {
            callback: mode == BoundaryMode::ModuleCallback,
            ..Default::default()
        })?;
        ensure!(
            std::mem::size_of::<usize>() == 8
                && std::mem::size_of::<MemoryRegion>() == 48
                && owner.process != 0
                && owner.thread != 0,
            "fixed boundary owner/ABI differs"
        );
        Ok(Self {
            owner,
            binding,
            mode,
            io,
            emit: Box::new(emit),
            fixture: None,
            kernel: None,
            original: None,
            stage: 0,
            addresses: [0; 2],
            enabled: [false; 2],
            software: SoftwarePresentation::default(),
            stopped: false,
            changed: false,
            restored: false,
            invalidated: false,
            alive: true,
            event_code: 0,
            event_creator: false,
            event_first: false,
            callback_process_exited: false,
        })
    }
    pub fn stop(&mut self, pid: u32, thread: u32, kind: u32, cleanup: bool) -> Result<()> {
        if self.mode == BoundaryMode::ModuleCallback {
            return self.callback_stop(pid, thread, kind, cleanup);
        }
        self.stopped = false;
        ensure!(
            pid == self.owner.pid,
            "fixed activation event is not owned process"
        );
        self.stopped = true;
        if kind == 5 || kind == 4 && thread == self.owner.tid {
            self.alive = false;
        }
        Ok(())
    }
    pub fn continued(&mut self) {
        self.stopped = false;
    }
    pub fn event(&mut self, thread: u32, code: u32, first: bool) {
        self.event_code = code;
        self.event_creator = thread == self.owner.tid;
        self.event_first = first;
    }
    pub(super) fn read(&mut self) -> Result<Vec<u8>> {
        ensure!(
            self.stopped && self.alive,
            "boundary context requires pending live creator stop"
        );
        self.io.deadline()?;
        let bytes = self.io.read(self.owner.thread)?;
        software::value(&bytes, 0)?;
        Ok(bytes)
    }
    pub fn refusal_metadata(&self, check: &str, context: Option<&[u8]>) -> Result<String> {
        ensure!(
            check.len() <= 64 && check.bytes().all(|v| v.is_ascii_lowercase() || v == b'-'),
            "unsupported fixed boundary check label"
        );
        let boolean = |value| if value { "True" } else { "False" };
        let mut value = format!(
            "phase=activation-refusal check={check} stage={} event_code=0x{:08X} creator={} first_chance={} initial_seen={} kernel_qualified={}",
            self.stage,
            self.event_code,
            boolean(self.event_creator),
            boolean(self.event_first),
            boolean(self.software.initial()),
            boolean(self.kernel.is_some())
        );
        if let Some(context) = context {
            value.push_str(&format!(
                " context_read=True {} raw_dr7=0x{:016X}",
                trap_qualifiers(software::value(context, 104)?),
                software::value(context, 112)?
            ));
            if let Some(original) = &self.original {
                for (index, expected) in self
                    .addresses
                    .iter()
                    .copied()
                    .chain([
                        software::value(original, 88)?,
                        software::value(original, 96)?,
                    ])
                    .enumerate()
                {
                    value.push_str(&format!(
                        " dr{index}_match={}",
                        boolean(software::value(context, 72 + index * 8)? == expected)
                    ));
                }
                value.push_str(&format!(
                    " dr7_exact={} dr6_unowned_match={}",
                    boolean(
                        software::value(context, 112)?
                            == software::control(original, &self.enabled)?
                    ),
                    boolean(
                        software::value(context, 104)? & !3 == software::value(original, 104)? & !3
                    )
                ));
            } else {
                value.push_str(" baseline_present=False");
            }
        } else {
            value.push_str(" context_read=False");
        }
        ensure!(
            value.len() < 768,
            "boundary refusal metadata bound exceeded"
        );
        Ok(value)
    }
    pub(super) fn check(&mut self, value: bool, check: &str, context: Option<&[u8]>) -> Result<()> {
        if value {
            return Ok(());
        }
        let metadata = self.refusal_metadata(check, context)?;
        require_check(false, check, || (self.emit)(&metadata))
    }
    pub(super) fn ownership(&mut self, context: &[u8], trap: bool) -> Result<()> {
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("boundary baseline is absent"))?;
        let addresses_match = self
            .addresses
            .iter()
            .copied()
            .chain([
                software::value(original, 88)?,
                software::value(original, 96)?,
            ])
            .enumerate()
            .all(|(index, expected)| {
                software::value(context, 72 + index * 8).is_ok_and(|value| value == expected)
            });
        let status_match = trap
            || software::software_status(
                software::value(context, 104)?,
                software::value(context, 112)?,
                software::control(original, &self.enabled)?,
            );
        self.check(
            addresses_match,
            if trap {
                "hardware-address-ownership"
            } else {
                "software-address-ownership"
            },
            Some(context),
        )?;
        self.check(status_match, "software-control-ownership", Some(context))
    }
    pub(super) fn accept_software_context(&mut self, context: &[u8]) -> Result<()> {
        ensure!(
            !self.software.initial(),
            "software breakpoint already captured"
        );
        self.ownership(context, false)?;
        self.software.accept(
            context,
            self.original.as_deref().unwrap(),
            &self.addresses,
            &self.enabled,
        )
    }
    pub fn accept_software(&mut self, thread: u32, code: u32, first: bool) -> Result<bool> {
        if code != 0x80000003 {
            return Ok(false);
        }
        let role = if self.mode == BoundaryMode::ModuleCallback {
            SoftwareRole::Callback
        } else {
            SoftwareRole::Boundary
        };
        self.check(
            software::software_stage(
                role,
                self.stage,
                self.invalidated,
                self.software.initial(),
                SoftwareEvent {
                    thread,
                    creator: self.owner.tid,
                    code,
                    first,
                },
            ),
            "software-stage",
            None,
        )?;
        let mut bytes = self.read()?;
        let result = self.accept_software_context(&bytes);
        let metadata = software_stop_metadata(self.mode, software::value(&bytes, 104)?);
        bytes.fill(0);
        result?;
        (self.emit)(&metadata)?;
        Ok(true)
    }
    pub(super) fn apply(&mut self, before: &[u8], restore: bool) -> Result<()> {
        ensure!(
            self.original.is_some() && self.stopped && self.alive,
            "boundary setter lacks stopped live baseline"
        );
        let mut desired = software::desired(
            before,
            self.original.as_deref().unwrap(),
            &self.addresses,
            &self.enabled,
            restore,
        )?;
        self.changed = true;
        let result = (|| {
            self.io.deadline()?;
            self.io.write(self.owner.thread, &desired)?;
            let mut after = self.read()?;
            let checked = self.check(
                raw_debug_equal(&desired, &after)? && unchanged_control_integer(before, &after)?,
                "setter-readback",
                Some(&after),
            );
            after.fill(0);
            checked?;
            if restore {
                self.changed = false;
                self.restored = true;
            }
            Ok(())
        })();
        desired.fill(0);
        result
    }
    pub(super) fn require_executable(
        &mut self,
        image: &PeImage<'_>,
        rva: u32,
        bytes: u32,
    ) -> Result<()> {
        ensure!(
            bytes != 0 && image.executable(rva, bytes),
            "boundary image execution span differs"
        );
        let address = image
            .base
            .checked_add(u64::from(rva))
            .ok_or_else(|| anyhow::anyhow!("boundary address overflow"))?;
        ensure!(
            executable_region(
                self.io.region(self.owner.process, address)?,
                address,
                bytes,
                image.base
            ),
            "boundary routine is not owned executable image span"
        );
        Ok(())
    }
    /// `actual_path` and `bytes` must come from the native CREATE event's retained
    /// file descriptor; a parsed fixture is not itself a native CREATE receipt.
    pub fn creation(&mut self, bytes: &[u8], base: u64, actual_path: &Path) -> Result<()> {
        ensure!(
            self.stage == 0
                && self.stopped
                && self.alive
                && image::sha256(bytes) == self.binding.digest,
            "boundary creation image identity differs"
        );
        let image = PeImage::parse(bytes, base)?;
        if self.mode == BoundaryMode::Child {
            ensure!(
                self.binding.path.file_name().and_then(|v| v.to_str())
                    == Some("startup-activation.exe")
                    && crate::windows_security::sxs::ordinal_path_equal(
                        actual_path
                            .to_str()
                            .ok_or_else(|| anyhow::anyhow!("child event path is not Unicode"))?,
                        self.binding
                            .path
                            .to_str()
                            .ok_or_else(|| anyhow::anyhow!("child expected path is not Unicode"))?
                    )?,
                "child creation path differs"
            );
            image.qualify_child_activation()?;
        } else {
            image::qualify_module_callback_path(actual_path, &self.binding.path)?;
            image::qualify_module_callback_host(bytes, &self.binding.digest)?;
        }
        self.fixture = Some(ImageSpan {
            base,
            entry: image.entry,
        });
        if self.mode == BoundaryMode::Child {
            self.require_executable(&image, image.entry, 1)?;
        }
        self.original = Some(self.read()?);
        ensure!(
            software::free(self.original.as_deref().unwrap())?,
            "boundary refuses existing debug ownership"
        );
        if self.mode == BoundaryMode::Child {
            self.addresses[0] = base + u64::from(image.entry);
            self.enabled[0] = true;
        }
        self.stage = 1;
        if self.mode == BoundaryMode::Child {
            let mut before = self.original.clone().unwrap();
            let result = self.apply(&before, false);
            before.fill(0);
            result?;
        }
        (self.emit)(if self.mode == BoundaryMode::Child {
            "phase=activation-entry-arm create_identity_qualified=True control_integer_unchanged=True"
        } else {
            "phase=module-callback-create identity_qualified=True baseline_free=True entry_armed=False"
        })
    }
    /// System LOAD bytes must be independently bound to the actual system file
    /// by the native owner. Both exact static same-run and full profile gates run.
    pub fn load_kernel(
        &mut self,
        bytes: Vec<u8>,
        base: u64,
        binding: &SameRunBinding,
    ) -> Result<()> {
        ensure!(
            self.stopped && self.alive && self.stage != 0,
            "boundary LOAD precedes live CREATE"
        );
        let image = KernelImage::with_subject(&bytes, base, "kernel32.dll")?;
        let sites = image.require_activation_boundary_profile()?;
        binding.bind_activation_load(&image)?;
        if self.mode == BoundaryMode::ModuleCallback {
            return self.callback_load(bytes, base, sites);
        }
        ensure!(
            self.kernel.is_none() && self.stage == 1,
            "boundary kernel load is duplicated or late"
        );
        self.kernel = Some(Kernel { bytes, base, sites });
        (self.emit)(
            "phase=activation-load module=kernel32.dll identity_equal=True fixed_profile=True",
        )
    }
    pub fn single_step(
        &mut self,
        thread: u32,
        code: u32,
        first: bool,
        exception: u64,
    ) -> Result<bool> {
        if self.mode == BoundaryMode::ModuleCallback {
            return self.callback_single_step(thread, code, first, exception);
        }
        if code != 0x80000004 {
            return Ok(false);
        }
        self.check(
            !self.invalidated
                && (1..=4).contains(&self.stage)
                && first
                && thread == self.owner.tid
                && self.original.is_some(),
            "hardware-stage",
            None,
        )?;
        let mut before = self.read()?;
        let result = self.child_step(thread, first, exception, &before);
        before.fill(0);
        result?;
        Ok(true)
    }
    fn child_step(
        &mut self,
        thread: u32,
        first: bool,
        exception: u64,
        before: &[u8],
    ) -> Result<()> {
        let status = software::value(before, 104)?;
        let cause = status & 0xe00f;
        let slot = if cause == 1 {
            Some(0)
        } else if cause == 2 {
            Some(1)
        } else {
            None
        };
        self.ownership(before, true)?;
        let accepted = slot.is_some_and(|slot| {
            owned_trap_site(
                thread,
                self.owner.tid,
                first,
                self.enabled[slot],
                software::value(before, 248).unwrap_or(0),
                self.addresses[slot],
            ) && exception == software::value(before, 248).unwrap_or(0)
                && owned_trap_status(
                    status,
                    software::value(before, 112).unwrap_or(0),
                    software::control(self.original.as_deref().unwrap(), &self.enabled)
                        .unwrap_or(u64::MAX),
                    slot as u32,
                )
        });
        self.check(accepted, "hardware-trap", Some(before))?;
        let slot = slot.unwrap();
        let next = next(
            self.stage,
            slot,
            if self.stage == 4 {
                software::value(before, 144)? as u32
            } else {
                0
            },
        )?;
        if self.stage == 1 || self.stage == 2 {
            self.check(
                self.software.initial() && self.kernel.is_some(),
                "entry-prerequisites",
                Some(before),
            )?;
            let kernel = self.kernel.as_ref().unwrap();
            let bytes = kernel.bytes.clone();
            let pe = PeImage::parse(&bytes, kernel.base)?;
            let sites = kernel.sites;
            if self.stage == 1 {
                self.require_executable(&pe, sites.worker, 15)?;
                self.require_executable(&pe, sites.funnel, 2)?;
                self.addresses = [
                    pe.base + u64::from(sites.worker),
                    pe.base + u64::from(sites.funnel),
                ];
                self.enabled = [true, true];
            } else {
                self.require_executable(&pe, sites.registry, 2)?;
                self.addresses[0] = pe.base + u64::from(sites.registry);
            }
            let fixture = self.fixture.as_ref().unwrap();
            let entry = fixture.base + u64::from(fixture.entry);
            ensure!(
                self.addresses[0] != self.addresses[1]
                    && self.addresses[0] != entry
                    && self.addresses[1] != entry,
                "boundary sites alias entry or each other"
            );
            let prior = self.stage;
            self.stage = next;
            self.apply(before, false)?;
            return (self.emit)(&format!(
                "phase={} {} {} control_integer_unchanged=True",
                if prior == 1 {
                    "activation-entry-hit"
                } else {
                    "activation-worker-entry"
                },
                trap_qualifiers(status),
                if prior == 1 {
                    "worker_sites_armed=True"
                } else {
                    "slot_replaced=True registry_result_armed=True scalar_read=False dispatch_route_verified=False"
                }
            ));
        }
        let scalar = if self.stage == 3 {
            Some(registry_result(before)?)
        } else {
            None
        };
        self.addresses[slot] = 0;
        self.enabled[slot] = false;
        self.stage = next;
        if next == 5 {
            self.restore()?;
            (self.emit)(&format!(
                "phase=activation-caller-site site=worker-failure-funnel {} {} caller_local=True producer_verified=False invocation_pair_claimed=False control_integer_unchanged=True",
                raw(software::value(before, 144)?),
                trap_qualifiers(status)
            ))?;
            (self.emit)(
                "phase=activation-sites-complete restored=True worker_entry_observed=True registry_result_observed=True funnel_observed=True branch_claimed=False cause_claimed=False",
            )
        } else {
            self.apply(before, false)?;
            (self.emit)(&format!(
                "phase=activation-registry-result {} {} slot_disabled=True caller_local=True producer_verified=False invocation_pair_claimed=False control_integer_unchanged=True",
                scalar.unwrap(),
                trap_qualifiers(status)
            ))
        }
    }
    pub fn other_thread(&mut self, thread: u32, kind: u32) -> Result<()> {
        if self.mode == BoundaryMode::ModuleCallback {
            return self.callback_other_thread(thread, kind);
        }
        self.invalidate();
        anyhow::bail!("fixed activation diagnostic encountered another thread transition")
    }
    pub fn unload(&mut self, base: u64) -> Result<()> {
        if self
            .fixture
            .as_ref()
            .is_some_and(|value| value.base == base)
            || self.kernel.as_ref().is_some_and(|value| value.base == base)
        {
            self.invalidate();
            anyhow::bail!("fixed activation diagnostic image unloaded");
        }
        Ok(())
    }
    pub fn invalidate(&mut self) {
        self.invalidated = true;
    }
    pub fn require_complete(&self) -> Result<()> {
        ensure!(
            if self.mode == BoundaryMode::ModuleCallback {
                super::module_callback::complete(self.stage, self.restored, self.invalidated)
            } else {
                complete(self.stage, self.restored, self.invalidated)
            },
            "fixed activation caller-site observation is inconclusive"
        );
        Ok(())
    }
    pub fn restoration_allowed(&self) -> bool {
        self.changed && self.alive && self.stopped
    }
    pub fn restore(&mut self) -> Result<()> {
        if !self.restoration_allowed() {
            return Ok(());
        }
        let mut before = self.read()?;
        let result = self.apply(&before, true);
        before.fill(0);
        result
    }
    pub fn destroyed(&mut self) -> Result<()> {
        self.alive = false;
        self.changed = false;
        self.stopped = false;
        if let Some(original) = &mut self.original {
            original.fill(0)
        }
        self.addresses.fill(0);
        self.enabled.fill(false);
        (self.emit)("phase=activation-cleanup state_destroyed=True restored_claimed=False")
    }
}
