//! One consumed CSR call/return observation, with bounded native diagnostic stages.
use super::super::diagnostics::{self, Numbers, Stage};
use super::*;
impl<I: ContextIo> ResourceThreads<I> {
    pub fn capture_dispatch(
        &mut self,
        id: u32,
        first: bool,
        exception: u64,
        target: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        ensure!(
            self.epoch
                && self.kind == 1
                && self.event_thread == id
                && !self.cleanup
                && !self.failed
                && !self.captured
                && self.pair.is_some()
                && !self.process_dead,
            "resource dispatch capture state differs"
        );
        let index = self.live(id)?;
        self.io
            .deadline()
            .map_err(|error| diagnostics::at(error, Stage::DebugCaptureRead))?;
        let mut bytes = self
            .io
            .read(self.generations[index].handle)
            .map_err(|error| diagnostics::at(error, Stage::DebugCaptureRead))?;
        let mut stage = Stage::DebugCaptureRead;
        let result = (|| {
            context(&bytes)?;
            let pair = self.pair.as_ref().unwrap();
            let sites = pair.sites(index as u32);
            stage = Stage::DebugCaptureCause;
            let slot = match u64_at(&bytes, 104) & 0xe00f {
                1 => 0usize,
                2 => 1,
                _ => anyhow::bail!("resource dispatch trap cause is foreign"),
            };
            stage = Stage::DebugCaptureSite;
            ensure!(
                first
                    && self.generations[index].changed
                    && sites[slot] != 0
                    && exception == sites[slot]
                    && u64_at(&bytes, 248) == sites[slot],
                "resource dispatch trap site differs"
            );
            let baseline = self.generations[index].baseline.as_ref().unwrap();
            stage = Stage::DebugCaptureOwnership;
            ensure!(
                (0..4).all(|i| u64_at(&bytes, 72 + i * 8)
                    == if i < 2 {
                        sites[i]
                    } else {
                        u64_at(baseline, 72 + i * 8)
                    }),
                "resource dispatch trap address ownership differs"
            );
            let control =
                u64_at(baseline, 112) | u64::from(sites[0] != 0) | (u64::from(sites[1] != 0) << 2);
            stage = Stage::DebugCaptureControl;
            ensure!(
                owned_trap_status(
                    u64_at(&bytes, 104),
                    u64_at(&bytes, 112),
                    control,
                    slot as u32
                ),
                "resource dispatch trap control differs"
            );
            if !pair.started() {
                stage = Stage::DebugPairCall;
                ensure!(slot == 0, "resource dispatch return precedes call");
                self.pair.as_mut().unwrap().begin(index as u32, &bytes)?;
                self.call_trap = Some([u64_at(&bytes, 104), u64_at(&bytes, 112)]);
                stage = Stage::DebugDispatchTarget;
                target()?;
                self.base_equal = true;
                self.qualified_stop = true;
                stage = Stage::DebugCaptureControl;
                for i in 0..self.generations.len() {
                    if !self.generations[i].dead && !self.generations[i].retired {
                        self.apply(i, false)?;
                    }
                }
            } else {
                stage = Stage::DebugPairReturn;
                ensure!(slot == 1, "resource dispatch repeated call");
                self.pair.as_mut().unwrap().end(index as u32, &bytes)?;
                self.qualified_stop = true;
                self.captured = true;
                self.base_equal = true;
                self.capture_trap = Some([u64_at(&bytes, 104), u64_at(&bytes, 112)]);
                self.creator_capture = id == self.creator;
                self.raw_eax = Some(self.pair.as_ref().unwrap().result()?);
                stage = Stage::DebugCaptureControl;
                self.restore_all()?;
                self.restored = true;
            }
            Ok(())
        })();
        let numbers = if bytes.len() == CONTEXT_SIZE {
            Numbers {
                dr6: Some(u64_at(&bytes, 104)),
                dr7: Some(u64_at(&bytes, 112)),
                ..Default::default()
            }
        } else {
            Numbers::default()
        };
        bytes.fill(0);
        if result.is_err() {
            self.failed = true;
        }
        result.map_err(|error| diagnostics::annotate(error, stage, numbers))
    }
}
