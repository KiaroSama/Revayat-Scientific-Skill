//! All-thread debug ownership for the fixed resource/CSR observation. No code or integer writes.
use super::{
    CONTEXT_SIZE, Failures, dispatch::CsrPair, owned_trap_status, raw_debug_equal,
    unchanged_control_integer,
};
use anyhow::{Result, ensure};
use std::sync::Arc;
#[path = "thread_dispatch_capture.rs"]
mod dispatch_capture;
#[path = "thread_metadata.rs"]
mod metadata;
pub use metadata::ObservationState;

pub trait ContextIo {
    fn read(&mut self, handle: usize) -> Result<Vec<u8>>;
    fn write(&mut self, handle: usize, bytes: &[u8]) -> Result<()>;
    fn close(&mut self, handle: usize) -> Result<()>;
    fn deadline(&mut self) -> Result<()>;
}
struct Generation {
    id: u32,
    handle: usize,
    baseline: Option<Vec<u8>>,
    dispatch_state: Option<[u64; 6]>,
    owned: bool,
    dead: bool,
    retired: bool,
    changed: bool,
}
#[derive(Clone)]
pub(crate) struct RetainedFailure(Arc<anyhow::Error>);
impl RetainedFailure {
    pub(crate) fn original(&self) -> &anyhow::Error {
        &self.0
    }
}
impl std::fmt::Debug for RetainedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("retained resource cleanup uncertainty")
    }
}
impl std::fmt::Display for RetainedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for RetainedFailure {}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn context(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() == CONTEXT_SIZE,
        "resource x64 context size differs"
    );
    Ok(())
}
fn free(bytes: &[u8]) -> Result<bool> {
    context(bytes)?;
    Ok((72..=96).step_by(8).all(|at| u64_at(bytes, at) == 0)
        && u64_at(bytes, 112) & 0xffff28ff == 0
        && u64_at(bytes, 104) & 0xe00f == 0)
}
fn peer_configuration(status: u64, control: u64, expected: u64) -> bool {
    status & !(0x10000 | 0x800) == 0xfffe07f0
        && expected & !0x405 == 0
        && (control ^ expected) & !0x400 == 0
}
pub struct ResourceThreads<I: ContextIo> {
    pid: u32,
    creator: u32,
    io: I,
    generations: Vec<Generation>,
    epoch: bool,
    cleanup: bool,
    process_dead: bool,
    failed: bool,
    destroyed: bool,
    event_thread: u32,
    kind: u32,
    pair: Option<CsrPair>,
    site: u64,
    qualified_stop: bool,
    captured: bool,
    restored: bool,
    creator_capture: bool,
    raw_eax: Option<u32>,
    uncertainty: Option<RetainedFailure>,
    initial: bool,
    base_equal: bool,
    capture_trap: Option<[u64; 2]>,
    call_trap: Option<[u64; 2]>,
    peer_trap: Option<[u64; 2]>,
    software_trap: Option<[u64; 2]>,
    dispatch_refusal: Option<String>,
    setter_refusal: Option<String>,
    prior_dead_retired: usize,
}
impl<I: ContextIo> ResourceThreads<I> {
    pub fn new(pid: u32, creator: u32, io: I) -> Result<Self> {
        ensure!(
            pid != 0 && creator != 0,
            "resource owner identity is absent"
        );
        Ok(Self {
            pid,
            creator,
            io,
            generations: Vec::new(),
            epoch: false,
            cleanup: false,
            process_dead: false,
            failed: false,
            destroyed: false,
            event_thread: 0,
            kind: 0,
            pair: None,
            site: 0,
            qualified_stop: false,
            captured: false,
            restored: false,
            creator_capture: false,
            raw_eax: None,
            uncertainty: None,
            initial: false,
            base_equal: false,
            capture_trap: None,
            call_trap: None,
            peer_trap: None,
            software_trap: None,
            dispatch_refusal: None,
            setter_refusal: None,
            prior_dead_retired: 0,
        })
    }
    pub fn io_mut(&mut self) -> &mut I {
        &mut self.io
    }
    pub fn captured(&self) -> bool {
        self.captured
    }
    pub fn failed(&self) -> bool {
        self.failed
    }
    pub fn capture_restored(&self) -> bool {
        self.restored
    }
    pub fn creator_capture(&self) -> bool {
        self.creator_capture
    }
    pub fn raw_eax(&self) -> Option<u32> {
        self.raw_eax
    }
    pub fn enrolled(&self) -> usize {
        self.generations.len()
    }
    fn live(&self, id: u32) -> Result<usize> {
        self.generations
            .iter()
            .position(|v| v.id == id && !v.dead && !v.retired)
            .ok_or_else(|| anyhow::anyhow!("resource event has no live enrolled thread"))
    }
    pub fn stop(&mut self, pid: u32, thread: u32, kind: u32, draining: bool) -> Result<()> {
        self.epoch = false;
        self.qualified_stop = false;
        ensure!(
            pid == self.pid && (!self.destroyed || draining),
            "resource event process differs"
        );
        if !draining {
            ensure!(
                !self.process_dead
                    && ((1..=8).contains(&kind) && kind != 3
                        || self.generations.is_empty() && kind == 3 && thread == self.creator),
                "resource event lifetime/kind differs"
            );
            if kind == 2 {
                ensure!(
                    self.generations.iter().all(|v| v.retired || v.id != thread),
                    "duplicate live resource thread"
                );
            }
            if kind == 1 || !self.captured && kind != 2 && kind != 3 {
                self.live(thread)?;
            }
        }
        self.event_thread = thread;
        self.kind = kind;
        self.cleanup = draining;
        if draining {
            self.failed = true;
        }
        if kind == 5 {
            self.process_dead = true;
            for v in &mut self.generations {
                v.dead = true;
            }
        } else if kind == 4 {
            for v in &mut self.generations {
                if v.id == thread && !v.retired {
                    v.dead = true;
                }
            }
        }
        self.epoch = true;
        Ok(())
    }
    pub fn enroll(&mut self, id: u32, handle: &mut usize, owned: bool) -> Result<()> {
        ensure!(
            self.epoch
                && !self.cleanup
                && !self.captured
                && !self.process_dead
                && matches!(self.kind, 2 | 3)
                && self.event_thread == id
                && self.generations.len() < 128
                && *handle != 0
                && *handle != usize::MAX,
            "resource enrollment state/capacity differs"
        );
        ensure!(
            self.generations
                .iter()
                .all(|v| v.retired || v.id != id && v.handle != *handle),
            "resource generation aliases live ownership"
        );
        let index = self.generations.len();
        self.generations.push(Generation {
            id,
            handle: *handle,
            baseline: None,
            dispatch_state: None,
            owned,
            dead: false,
            retired: false,
            changed: false,
        });
        if owned {
            *handle = 0;
        } // Transfer before the first deadline/query that can fail.
        let result = (|| {
            self.io.deadline()?;
            let mut baseline = self.io.read(self.generations[index].handle)?;
            if !free(&baseline)? {
                baseline.fill(0);
                anyhow::bail!("resource thread baseline has foreign debug ownership");
            }
            self.generations[index].baseline = Some(baseline);
            if self.site != 0 && self.pair.as_ref().is_none_or(|p| !p.started()) {
                self.apply(index, false)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn retire(&mut self, index: usize) -> Result<()> {
        let value = &mut self.generations[index];
        ensure!(
            value.dead && !value.retired,
            "resource retirement lifetime differs"
        );
        value.retired = true;
        if !self.captured && !self.process_dead {
            self.prior_dead_retired += 1;
        }
        if let Some(bytes) = &mut value.baseline {
            bytes.fill(0);
        }
        if let Some(bytes) = &mut value.dispatch_state {
            bytes.fill(0);
        }
        let handle = std::mem::replace(&mut value.handle, 0);
        if value.owned && handle != 0 {
            self.io.close(handle)?;
        }
        Ok(())
    }
    pub fn continued(&mut self) -> Result<()> {
        ensure!(self.epoch, "resource continuation has no pending event");
        self.epoch = false;
        let mut errors = Vec::new();
        if self.kind == 4 {
            for index in 0..self.generations.len() {
                let value = &self.generations[index];
                if value.id == self.event_thread
                    && value.dead
                    && !value.retired
                    && let Err(error) = self.retire(index)
                {
                    errors.push(error);
                }
            }
        }
        self.finish_cleanup(errors)
    }
    fn finish_cleanup(&mut self, errors: Vec<anyhow::Error>) -> Result<()> {
        if errors.is_empty() {
            return Ok(());
        }
        self.failed = true;
        let error = RetainedFailure(Arc::new(Failures { errors }.into()));
        self.uncertainty = Some(error.clone());
        Err(error.into())
    }
    pub fn software(&mut self, id: u32, first: bool) -> Result<()> {
        ensure!(
            self.epoch
                && !self.cleanup
                && id == self.creator
                && first
                && !self.initial
                && !self.process_dead,
            "resource software breakpoint state differs"
        );
        let index = self.live(id)?;
        let mut bytes = self.io.read(self.generations[index].handle)?;
        let result = (|| {
            context(&bytes)?;
            let baseline = self.generations[index].baseline.as_ref().unwrap();
            let sites = self
                .pair
                .as_ref()
                .map(|p| p.sites(index as u32))
                .unwrap_or([
                    if self.generations[index].changed {
                        self.site
                    } else {
                        0
                    },
                    0,
                ]);
            ensure!(
                (0..4).all(|i| u64_at(&bytes, 72 + i * 8)
                    == if i < 2 {
                        sites[i]
                    } else {
                        u64_at(baseline, 72 + i * 8)
                    }),
                "resource software address ownership differs"
            );
            let control =
                u64_at(baseline, 112) | u64::from(sites[0] != 0) | (u64::from(sites[1] != 0) << 2);
            ensure!(
                self.site == 0 && raw_debug_equal(baseline, &bytes)?
                    || self.site != 0
                        && peer_configuration(u64_at(&bytes, 104), u64_at(&bytes, 112), control)
                    || self.captured
                        && self.restored
                        && !self.failed
                        && raw_debug_equal(baseline, &bytes)?,
                "fixed resource observation refused check=software-control-ownership {} raw_dr7=0x{:016X}",
                super::trap_qualifiers(u64_at(&bytes, 104)),
                u64_at(&bytes, 112)
            );
            self.initial = true;
            self.software_trap = Some([u64_at(&bytes, 104), u64_at(&bytes, 112)]);
            Ok(())
        })();
        bytes.fill(0);
        result
    }
    pub fn arm(&mut self, site: u64) -> Result<()> {
        ensure!(
            self.epoch
                && !self.cleanup
                && !self.process_dead
                && !self.failed
                && !self.captured
                && self.site == 0
                && site != 0,
            "fixed resource observation refused check=arm-state"
        );
        self.site = site;
        for index in 0..self.generations.len() {
            if !self.generations[index].dead && !self.generations[index].retired {
                self.apply(index, false)?;
            }
        }
        Ok(())
    }
    pub fn capture_entry(&mut self, id: u32, first: bool, exception: u64) -> Result<()> {
        ensure!(
            id == self.creator,
            "entry observation is not creator-scoped"
        );
        self.capture_one(id, first, exception, None)
    }
    pub fn capture(&mut self, id: u32, first: bool, exception: u64, image_base: u64) -> Result<()> {
        self.capture_one(id, first, exception, Some(image_base))
    }
    fn capture_one(
        &mut self,
        id: u32,
        first: bool,
        exception: u64,
        image_base: Option<u64>,
    ) -> Result<()> {
        ensure!(
            self.epoch
                && !self.cleanup
                && !self.failed
                && !self.captured
                && self.site != 0
                && self.pair.is_none()
                && !self.process_dead,
            "resource capture state differs"
        );
        let index = self.live(id)?;
        self.io.deadline()?;
        let mut bytes = self.io.read(self.generations[index].handle)?;
        let result = (|| {
            context(&bytes)?;
            let baseline = self.generations[index].baseline.as_ref().unwrap();
            ensure!(
                first
                    && self.generations[index].changed
                    && exception == self.site
                    && u64_at(&bytes, 248) == self.site,
                "resource capture site differs"
            );
            ensure!(
                (0..4).all(|i| u64_at(&bytes, 72 + i * 8)
                    == if i == 0 {
                        self.site
                    } else {
                        u64_at(baseline, 72 + i * 8)
                    })
                    && owned_trap_status(
                        u64_at(&bytes, 104),
                        u64_at(&bytes, 112),
                        u64_at(baseline, 112) | 1,
                        0
                    ),
                "resource capture debug ownership differs"
            );
            self.captured = true;
            self.capture_trap = Some([u64_at(&bytes, 104), u64_at(&bytes, 112)]);
            self.creator_capture = id == self.creator;
            self.raw_eax = Some(u64_at(&bytes, 120) as u32);
            self.base_equal = image_base.is_none_or(|base| u64_at(&bytes, 176) == base);
            self.qualified_stop = true;
            self.restore_all()?;
            self.restored = true;
            if let Some(image_base) = image_base {
                ensure!(
                    u64_at(&bytes, 176) == image_base,
                    "fixed resource observation refused check=first-base-equality"
                );
            }
            Ok(())
        })();
        bytes.fill(0);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn arm_dispatch(&mut self, call: u64, post: u64) -> Result<()> {
        ensure!(
            self.epoch
                && !self.cleanup
                && !self.process_dead
                && !self.failed
                && !self.captured
                && self.site == 0,
            "resource dispatch arm state differs"
        );
        self.pair = Some(CsrPair::new(call, post)?);
        self.site = call;
        for index in 0..self.generations.len() {
            if !self.generations[index].dead && !self.generations[index].retired {
                self.apply(index, false)?;
            }
        }
        Ok(())
    }
    pub fn arm_dispatch_at_entry(
        &mut self,
        id: u32,
        first: bool,
        exception: u64,
        call: u64,
        post: u64,
    ) -> Result<()> {
        let valid_state = self.epoch
            && self.kind == 1
            && self.event_thread == id
            && id == self.creator
            && first
            && self.initial
            && !self.cleanup
            && !self.process_dead
            && !self.failed
            && !self.captured
            && self.pair.is_none()
            && self.site != 0
            && exception == self.site;
        ensure!(valid_state, "resource entry-to-dispatch state differs");
        let index = self.live(id)?;
        let mut bytes = self.io.read(self.generations[index].handle)?;
        let checked = (|| {
            context(&bytes)?;
            let baseline = self.generations[index].baseline.as_ref().unwrap();
            let valid_trap = self.generations[index].changed
                && u64_at(&bytes, 248) == self.site
                && u64_at(&bytes, 72) == self.site
                && u64_at(&bytes, 80) == 0
                && u64_at(&bytes, 88) == u64_at(baseline, 88)
                && u64_at(&bytes, 96) == u64_at(baseline, 96)
                && owned_trap_status(
                    u64_at(&bytes, 104),
                    u64_at(&bytes, 112),
                    u64_at(baseline, 112) | 1,
                    0,
                );
            ensure!(valid_trap, "resource entry trap before dispatch differs");
            Ok(())
        })();
        bytes.fill(0);
        if let Err(error) = checked {
            self.failed = true;
            return Err(super::diagnostics::at(
                error,
                super::diagnostics::Stage::DebugCaptureState,
            ));
        }
        self.qualified_stop = true;
        self.pair = Some(CsrPair::new(call, post)?);
        self.site = call;
        for i in 0..self.generations.len() {
            if !self.generations[i].dead && !self.generations[i].retired {
                self.apply(i, false)?;
            }
        }
        Ok(())
    }
    fn transition(&self, index: usize, bytes: &[u8], restore: bool) -> Result<()> {
        let value = &self.generations[index];
        let state = value.dispatch_state.ok_or_else(|| {
            anyhow::anyhow!("fixed resource observation refused check=dispatch-transition-baseline")
        })?;
        ensure!(
            (0..4).all(|i| u64_at(bytes, 72 + i * 8) == state[i]),
            "resource dispatch address changed outside ownership"
        );
        let exact = u64_at(bytes, 104) == state[4] && u64_at(bytes, 112) == state[5];
        let trap = self.kind == 1
            && self.event_thread == value.id
            && (0..2).any(|slot| {
                state[slot] != 0
                    && u64_at(bytes, 248) == state[slot]
                    && owned_trap_status(
                        u64_at(bytes, 104),
                        u64_at(bytes, 112),
                        state[5],
                        slot as u32,
                    )
            });
        let peer = self.qualified_stop
            && self.kind == 1
            && self.event_thread != value.id
            && peer_configuration(u64_at(bytes, 104), u64_at(bytes, 112), state[5]);
        if !(exact || trap || peer) {
            anyhow::bail!("{}", self.transition_refusal(index, bytes, restore));
        }
        Ok(())
    }
    fn apply(&mut self, index: usize, restore: bool) -> Result<()> {
        let value = &self.generations[index];
        ensure!(
            self.epoch && !value.dead && !value.retired && value.baseline.is_some(),
            "resource setter lifetime differs"
        );
        let handle = value.handle;
        self.io.deadline()?;
        let mut before = self.io.read(handle)?;
        let mut desired = Vec::new();
        let mut after = Vec::new();
        let result = (|| {
            context(&before)?;
            let sites = if let Some(pair) = &self.pair {
                let started = pair.started();
                let sites = pair.sites(index as u32);
                if restore || started || self.generations[index].dispatch_state.is_some() {
                    self.transition(index, &before, restore)?;
                    self.remember_peer(index, &before);
                } else {
                    ensure!(
                        raw_debug_equal(
                            self.generations[index].baseline.as_ref().unwrap(),
                            &before
                        )?,
                        "resource arm baseline differs"
                    );
                }
                sites
            } else {
                let baseline = self.generations[index].baseline.as_ref().unwrap();
                if restore {
                    let state = self.generations[index].dispatch_state.ok_or_else(|| {
                        anyhow::anyhow!("resource setter has no confirmed readback")
                    })?;
                    let exact = (0..6).all(|i| u64_at(&before, 72 + i * 8) == state[i]);
                    let selected = self.kind == 1
                        && self.event_thread == self.generations[index].id
                        && u64_at(&before, 248) == self.site
                        && owned_trap_status(
                            u64_at(&before, 104),
                            u64_at(&before, 112),
                            state[5],
                            0,
                        );
                    let peer = self.qualified_stop
                        && self.kind == 1
                        && self.event_thread != self.generations[index].id
                        && peer_configuration(u64_at(&before, 104), u64_at(&before, 112), state[5]);
                    ensure!(
                        (0..4).all(|i| u64_at(&before, 72 + i * 8) == state[i])
                            && (exact || selected || peer),
                        "resource restoration has foreign debug ownership"
                    );
                } else {
                    ensure!(
                        raw_debug_equal(baseline, &before)?,
                        "resource arm baseline differs"
                    );
                }
                [self.site, 0]
            };
            let baseline = self.generations[index].baseline.as_ref().unwrap();
            desired = before.clone();
            let mut control = u64_at(baseline, 112);
            for (i, site) in sites.into_iter().chain([0; 2]).enumerate() {
                let address = if restore || i >= 2 {
                    u64_at(baseline, 72 + i * 8)
                } else {
                    site
                };
                put(&mut desired, 72 + i * 8, address);
                if !restore && i < 2 && site != 0 {
                    control |= 1 << (i * 2);
                }
            }
            put(&mut desired, 104, u64_at(baseline, 104));
            put(&mut desired, 112, control);
            desired[48..52].copy_from_slice(&0x100010u32.to_le_bytes());
            self.generations[index].changed = true;
            self.io.write(handle, &desired)?;
            after = self.io.read(handle)?;
            if !raw_debug_equal(&desired, &after)? || !unchanged_control_integer(&before, &after)? {
                let refusal = self.setter_refusal(index, &before, &desired, &after, restore)?;
                anyhow::bail!("{refusal}");
            }
            self.generations[index].dispatch_state =
                Some(std::array::from_fn(|i| u64_at(&after, 72 + i * 8)));
            if restore {
                self.generations[index].changed = false;
            }
            Ok(())
        })();
        before.fill(0);
        desired.fill(0);
        after.fill(0);
        if let Err(error) = result {
            self.failed = true;
            if self.dispatch_refusal.is_none()
                && error.to_string().starts_with(
                    "fixed resource observation refused check=dispatch-transition-control",
                )
            {
                self.dispatch_refusal = Some(error.to_string());
            }
            let retained = RetainedFailure(Arc::new(error));
            if self.generations[index].changed && self.uncertainty.is_none() {
                self.uncertainty = Some(retained.clone());
            }
            return Err(retained.into());
        }
        Ok(())
    }
    pub fn restore_all(&mut self) -> Result<()> {
        if !self.epoch {
            return Ok(());
        }
        let mut errors = Vec::new();
        for index in 0..self.generations.len() {
            let value = &self.generations[index];
            if value.changed
                && !value.dead
                && !value.retired
                && let Err(error) = self.apply(index, true)
            {
                errors.push(error);
            }
        }
        self.finish_cleanup(errors)
    }
    pub fn destroyed(&mut self) -> Result<()> {
        ensure!(
            self.process_dead && !self.epoch,
            "resource destruction lifetime differs"
        );
        let mut errors = Vec::new();
        for i in 0..self.generations.len() {
            if !self.generations[i].retired
                && let Err(error) = self.retire(i)
            {
                errors.push(error);
            }
        }
        self.destroyed = true;
        if let Some(pair) = &mut self.pair {
            pair.destroy();
        }
        if let Some(error) = self.uncertainty.take() {
            errors.insert(0, error.into());
        }
        self.finish_cleanup(errors)
    }
}
