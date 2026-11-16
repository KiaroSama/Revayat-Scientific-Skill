//! Mode-specific presentation of observations; raw PC/stack values never enter metadata.
use super::*;

fn boolean(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}
#[derive(Clone, Debug)]
pub struct ObservationState {
    pub captured: bool,
    pub base_equal: bool,
    pub restored: bool,
    pub failed: bool,
    pub destroyed: bool,
    pub creator: bool,
    pub raw_eax: Option<u32>,
    pub enrolled: usize,
    pub retired: usize,
    pub prior_dead_retired: usize,
    pub traps: String,
    pub software: String,
}
impl<I: ContextIo> ResourceThreads<I> {
    pub fn dispatch_refusal(&self) -> Option<&str> {
        self.dispatch_refusal.as_deref()
    }
    pub(super) fn setter_refusal(
        &mut self,
        index: usize,
        before: &[u8],
        desired: &[u8],
        after: &[u8],
        restore: bool,
    ) -> Result<String> {
        let Some(pair) = &self.pair else {
            return Ok("fixed resource observation refused check=setter-readback".into());
        };
        if let Some(first) = &self.setter_refusal {
            return Ok(first.clone());
        }
        let phase = if !restore {
            if pair.started() { "call-disarm" } else { "arm" }
        } else if self.cleanup || !pair.paired() {
            "cleanup-restore"
        } else {
            "pair-restore"
        };
        let mut line = format!(
            "fixed resource observation refused check=setter-readback snapshot=first phase={phase} event_kind={} event_thread_equal={} debug_equal={} control_integer_equal={}",
            self.kind,
            boolean(self.event_thread == self.generations[index].id),
            boolean(raw_debug_equal(desired, after)?),
            boolean(unchanged_control_integer(before, after)?)
        );
        for (name, at) in [
            ("dr0", 72),
            ("dr1", 80),
            ("dr2", 88),
            ("dr3", 96),
            ("dr6", 104),
            ("dr7", 112),
        ] {
            line.push_str(&format!(
                " {name}_equal={}",
                boolean(u64_at(desired, at) == u64_at(after, at))
            ));
        }
        line.push_str(&format!(" desired_dr6=0x{:016X} current_dr6=0x{:016X} desired_dr7=0x{:016X} current_dr7=0x{:016X}",u64_at(desired,104),u64_at(after,104),u64_at(desired,112),u64_at(after,112)));
        self.setter_refusal = Some(line.clone());
        Ok(line)
    }
    pub fn invalidate(&mut self) {
        self.failed = true;
    }
    pub fn observation(&self) -> ObservationState {
        let mut traps = String::new();
        if let Some([status, _]) = self.call_trap {
            traps.push_str(&format!(
                " call_{}",
                super::super::trap_qualifiers(status).replace(' ', " call_")
            ));
        }
        if let Some([status, _]) = self.capture_trap {
            let prefix = if self.pair.is_some() { " return_" } else { " " };
            traps.push_str(prefix);
            traps.push_str(&super::super::trap_qualifiers(status).replace(' ', prefix));
        }
        if let Some([status, control]) = self.peer_trap {
            traps.push_str(&format!(" peer_raw_dr6=0x{status:016X} peer_raw_dr7=0x{control:016X} peer_status_attributed=False peer_transaction_context=unknown peer_bld_bit_set={}", boolean(status & 0x800 != 0)));
        }
        let software = self
            .software_trap
            .map(|[status, _]| {
                format!(
                    " software_{} software_origin_verified=False",
                    super::super::trap_qualifiers(status).replace(' ', " software_")
                )
            })
            .unwrap_or_default();
        ObservationState {
            captured: self.captured,
            base_equal: self.base_equal,
            restored: self.restored,
            failed: self.failed,
            destroyed: self.destroyed,
            creator: self.creator_capture,
            raw_eax: self.raw_eax,
            enrolled: self.generations.len(),
            retired: self.generations.iter().filter(|g| g.retired).count(),
            prior_dead_retired: self.prior_dead_retired,
            traps,
            software,
        }
    }
    pub fn dispatch_software(&mut self, id: u32, first: bool) -> Result<()> {
        ensure!(
            self.epoch
                && !self.cleanup
                && !self.failed
                && id == self.creator
                && first
                && !self.initial
                && !self.process_dead,
            "resource dispatch software state differs"
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
                .unwrap_or([0; 2]);
            ensure!(
                (0..4).all(|i| u64_at(&bytes, 72 + i * 8)
                    == if i < 2 {
                        sites[i]
                    } else {
                        u64_at(baseline, 72 + i * 8)
                    }),
                "resource dispatch software address differs"
            );
            let control =
                u64_at(baseline, 112) | u64::from(sites[0] != 0) | (u64::from(sites[1] != 0) << 2);
            ensure!(
                if self.pair.is_none() {
                    raw_debug_equal(baseline, &bytes)?
                } else {
                    peer_configuration(u64_at(&bytes, 104), u64_at(&bytes, 112), control)
                        || self.captured
                            && self.restored
                            && !self.failed
                            && raw_debug_equal(baseline, &bytes)?
                },
                "resource dispatch software control differs"
            );
            self.software_trap = Some([u64_at(&bytes, 104), u64_at(&bytes, 112)]);
            self.initial = true;
            Ok(())
        })();
        bytes.fill(0);
        result
    }
    pub(super) fn remember_peer(&mut self, index: usize, bytes: &[u8]) {
        let value = &self.generations[index];
        if self.peer_trap.is_none()
            && self.qualified_stop
            && self.kind == 1
            && self.event_thread != value.id
            && let Some(state) = value.dispatch_state
            && (u64_at(bytes, 104) != state[4] || u64_at(bytes, 112) != state[5])
            && peer_configuration(u64_at(bytes, 104), u64_at(bytes, 112), state[5])
        {
            self.peer_trap = Some([u64_at(bytes, 104), u64_at(bytes, 112)]);
        }
    }
    pub(super) fn transition_refusal(&self, index: usize, bytes: &[u8], restore: bool) -> String {
        if let Some(first) = &self.dispatch_refusal {
            return first.clone();
        }
        let state = self.generations[index].dispatch_state.unwrap();
        let pair = self.pair.as_ref().unwrap();
        let status = u64_at(bytes, 104);
        let control = u64_at(bytes, 112);
        let phase = if !restore {
            "call-disarm"
        } else if self.cleanup || !pair.paired() {
            "cleanup-restore"
        } else {
            "pair-restore"
        };
        format!(
            "fixed resource observation refused check=dispatch-transition-control snapshot=first phase={phase} event_kind={} pair_started={} paired={} cleanup={} event_thread_equal={} dr6_equal={} dr7_equal={} call_site_match={} post_site_match={} call_status_match={} post_status_match={} stored_dr6=0x{:016X} stored_dr7=0x{:016X} current_dr6=0x{status:016X} current_dr7=0x{control:016X} transaction_context=unknown",
            self.kind,
            boolean(pair.started()),
            boolean(pair.paired()),
            boolean(self.cleanup),
            boolean(self.event_thread == self.generations[index].id),
            boolean(status == state[4]),
            boolean(control == state[5]),
            boolean(state[0] != 0 && u64_at(bytes, 248) == state[0]),
            boolean(state[1] != 0 && u64_at(bytes, 248) == state[1]),
            boolean(owned_trap_status(status, control, state[5], 0)),
            boolean(owned_trap_status(status, control, state[5], 1)),
            state[4],
            state[5]
        )
    }
}
