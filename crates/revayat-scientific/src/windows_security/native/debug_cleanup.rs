//! Debug observation completion, restoration, retirement and exhaustive owned cleanup.
use super::*;
use crate::windows_security::activation::diagnostics::{self, Numbers, Stage};
impl Owner {
    fn retire(&mut self, observe: &mut impl FnMut(DebugBoundary) -> Result<()>) -> Result<()> {
        if self.retirement_attempted {
            return Ok(());
        }
        self.retirement_attempted = true;
        let mut errors = Vec::new();
        if let Err(error) = observe(DebugBoundary::BeforeRetire) {
            errors.push(error);
        }
        if let Some(generations) = &mut self.generations {
            match generations.destroyed() {
                Ok(()) => {
                    if let Err(error) = observe(DebugBoundary::AfterRetire) {
                        errors.push(error);
                    }
                }
                Err(error) => errors.push(diagnostics::at(error, Stage::DebugEvent)),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Failures { errors }.into())
        }
    }
    pub(super) fn run(
        &mut self,
        observe: &mut impl FnMut(DebugBoundary) -> Result<()>,
    ) -> Result<EntryProof> {
        while !self.exited {
            ensure!(
                self.started.elapsed() < Duration::from_secs(10) && self.events < 128,
                "debug event/time budget exceeded"
            );
            if !self.receive(100)? {
                continue;
            }
            let event = self.pending.unwrap();
            let mut errors = Vec::new();
            let mut status = if event.kind == 1 { 0x80010001 } else { 0x10002 };
            match self.event(event) {
                Ok(value) => status = value,
                Err(error) => errors.push(error),
            }
            if !errors.is_empty()
                && let Some(generations) = &mut self.generations
                && let Err(error) = generations.restore_all()
            {
                errors.push(error);
            }
            if let Err(error) = self.release_event_file(event) {
                errors.push(error);
            }
            if let Err(error) = self.release_creation_aliases(event) {
                errors.push(error);
            }
            if let Err(error) = self.continue_event(status) {
                errors.push(error);
            }
            if !errors.is_empty() {
                return Err(Failures { errors }.into());
            }
        }
        observe(DebugBoundary::BeforeExitWait)
            .map_err(|error| diagnostics::at(error, Stage::DebugExitWait))?;
        let wait = unsafe { WaitForSingleObject(self.process, 2000) };
        if wait != 0 {
            let error = if wait == u32::MAX {
                unsafe { GetLastError() }
            } else {
                0
            };
            return Err(diagnostics::native(
                Stage::DebugExitWait,
                Numbers {
                    native_error: Some(error),
                    result: Some(wait),
                    ..Default::default()
                },
            ));
        }
        self.retire(observe)
            .map_err(|error| diagnostics::at(error, Stage::DebugRetire))?;
        if let Some(transport) = &mut self.transport {
            transport
                .finish()
                .map_err(|error| diagnostics::at(error, Stage::DebugTransport))?;
        }
        let generations = self.generations.as_mut().unwrap();
        self.files.require_clean()?;
        Ok(EntryProof {
            creation_bound: self.creation,
            entry_captured: generations.captured(),
            live_restored: generations.capture_restored(),
            natural_exit: self.exited,
            reaped: false,
            creator_capture: generations.creator_capture(),
            events: self.events,
            dispatch_target_equal: self
                .dispatch
                .as_ref()
                .is_some_and(|value| value.target_equal),
            dispatch_return: if self.dispatch.is_some() {
                generations.raw_eax()
            } else {
                None
            },
        })
    }
    pub(super) fn cleanup(
        &mut self,
        observe: &mut impl FnMut(DebugBoundary) -> Result<()>,
    ) -> Result<()> {
        let mut errors = Vec::new();
        if let Some(generations) = &mut self.generations {
            generations.io_mut().cleanup = true;
            generations.io_mut().started = Instant::now();
            if let Err(error) = generations.restore_all() {
                errors.push(error);
            }
        }
        let pending_exit = self.pending.is_some_and(|event| event.kind == 5);
        let wait = unsafe { WaitForSingleObject(self.process, 0) };
        if wait == 258 {
            if let Err(error) = crate::windows_security::diagnostic_validation::request_termination(
                &mut self.termination_requested,
                || {
                    let success = unsafe { api::TerminateProcess(self.process, 125) };
                    let error = if success == 0 {
                        Some(unsafe { GetLastError() })
                    } else {
                        None
                    };
                    ensure!(
                        success != 0,
                        "debug child termination failed winerror={error:?}"
                    );
                    Ok(())
                },
            ) {
                errors.push(error);
            }
        } else if wait != 0 {
            errors.push(anyhow::anyhow!("debug child cleanup wait failed"));
        }
        if let Some(event) = self.pending {
            if let Err(error) = self.release_event_file(event) {
                errors.push(error);
            }
            if let Err(error) = self.release_creation_aliases(event) {
                errors.push(error);
            }
            if let Err(error) =
                self.continue_event(if event.kind == 1 { 0x80010001 } else { 0x10002 })
            {
                errors.push(error);
            }
        }
        let cleanup = Instant::now();
        let mut received_exit = self.exit_seen || pending_exit;
        for _ in 0..128 {
            if received_exit {
                break;
            }
            if cleanup.elapsed() >= Duration::from_secs(5) {
                break;
            }
            match self.receive(25) {
                Ok(false) => continue,
                Err(error) => {
                    errors.push(error);
                    break;
                }
                Ok(true) => {}
            }
            let event = self.pending.unwrap();
            if let Some(generations) = &mut self.generations
                && let Err(error) = generations.stop(event.pid, event.tid, event.kind, true)
            {
                errors.push(error);
            }
            if event.kind == 5 {
                received_exit = true;
            }
            if let Err(error) = self.release_event_file(event) {
                errors.push(error);
            }
            if let Err(error) = self.release_creation_aliases(event) {
                errors.push(error);
            }
            if let Err(error) =
                self.continue_event(if event.kind == 1 { 0x80010001 } else { 0x10002 })
            {
                errors.push(error);
                break;
            }
        }
        if !received_exit {
            errors.push(anyhow::anyhow!(
                "debug exit event was not reaped within cleanup budget"
            ));
        }
        if unsafe { WaitForSingleObject(self.process, 2000) } != 0 {
            errors.push(anyhow::anyhow!("debug process cleanup wait is unsignaled"));
        }
        if !self.retirement_attempted
            && let Err(error) = self.retire(observe)
        {
            errors.push(error);
        }
        if let Err(error) = self.job.finish() {
            errors.push(error);
        }
        if let Some(transport) = &mut self.transport
            && let Err(error) = transport.close()
        {
            errors.push(error);
        }
        for handle in [&mut self.thread, &mut self.process] {
            let value = std::mem::replace(handle, null_mut());
            if let Err(error) = close(value) {
                errors.push(error);
            }
        }
        if let Err(error) = self.files.require_clean() {
            errors.push(error);
        }
        if !self.original_thread.is_null() || !self.original_process.is_null() {
            errors.push(anyhow::anyhow!(
                "debug original aliases lack a creation-event ownership witness"
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Failures { errors }.into())
        }
    }
}
