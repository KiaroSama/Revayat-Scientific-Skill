//! Expected wall termination is qualified by the concrete owner, never by natural-exit flags.
use super::*;
use std::time::{Duration, Instant};

/// A separate native observation. It conveys no outer-worker recovery authority.
pub(in crate::windows_security::native) struct WallTreeRetired {
    retired: Retired,
}
impl WallTreeRetired {
    pub(in crate::windows_security::native) fn begin_restore(
        self,
        profile: &super::super::NativeProfileBinding<'_>,
    ) -> Result<RestoreTransaction> {
        self.retired.begin_restore(profile)
    }
}
pub(in crate::windows_security::native) struct ExpectedWallCompleted {
    /// This is the observed exit after forced termination, not an asserted zero or requested125.
    pub result: Result<u32>,
    pub retired: Option<WallTreeRetired>,
}

/// Fields stay private to the concrete completion module; a parsed marker is insufficient.
struct VerifiedWallTrigger {
    process: usize,
    job: usize,
}
impl NativeCompletion<'_> {
    fn wall_active(&self) -> Result<u32> {
        let mut value: super::super::super::Accounting = unsafe { zeroed() };
        let mut returned = 0;
        ensure!(
            unsafe {
                QueryInformationJobObject(
                    self.job.handle,
                    1,
                    (&mut value as *mut super::super::super::Accounting).cast(),
                    size_of_val(&value) as u32,
                    &mut returned,
                )
            } != 0
                && returned as usize == size_of_val(&value),
            "expected wall job accounting query failed"
        );
        Ok(value.active)
    }
    fn wait_wall(&mut self) -> Result<VerifiedWallTrigger> {
        ensure!(
            self.started
                && self.assigned
                && self.creation_valid
                && self.resumed
                && !self.signaled
                && self.job.state == Lifecycle::Running,
            "expected wall owner is not the actual running subject"
        );
        let started = Instant::now();
        let mut progress = started;
        let mut previous = 0;
        let mut verified = None;
        loop {
            drain(&self.stdout, &mut self.output, OUTPUT_LIMIT)?;
            drain(&self.stderr, &mut self.error, ERROR_LIMIT)?;
            let size = self.output.pending().len() + self.error.pending().len();
            ensure!(
                size <= OUTPUT_LIMIT,
                "expected wall combined capture exceeds bound"
            );
            let now = Instant::now();
            if size != previous {
                progress = now;
                previous = size;
            }
            ensure!(
                now.duration_since(started) <= Duration::from_secs(60)
                    && now.duration_since(progress) <= Duration::from_secs(20),
                "expected wall prerequisite or transport deadline exceeded"
            );
            let signal = unsafe { WaitForSingleObject(self.process.0, 100) };
            ensure!(
                signal == 258,
                "expected wall primary exited before its verified deadline"
            );
            if verified.is_none()
                && self
                    .output
                    .pending()
                    .windows(crate::windows_security::kernel_controls::WALL_MARKER.len())
                    .any(|bytes| bytes == crate::windows_security::kernel_controls::WALL_MARKER)
                && self.wall_active()? >= 2
            {
                verified = Some(Instant::now());
            }
            if verified.is_some_and(|at| at.elapsed() > Duration::from_secs(2)) {
                // Recheck the primary at the exact capability mint, after the clock and job witness.
                ensure!(
                    unsafe { WaitForSingleObject(self.process.0, 0) } == 258
                        && self.wall_active()? >= 2,
                    "expected wall primary or descendant exited during final qualification"
                );
                return Ok(VerifiedWallTrigger {
                    process: self.process.0 as usize,
                    job: self.job.handle as usize,
                });
            }
        }
    }
    /// Always retires the real owner. Failure, absent marker, or unrelated timeout yields no proof.
    pub(in crate::windows_security::native) fn finish_expected_wall(
        mut self,
        preparation: Result<()>,
        ticket: Ticket,
    ) -> ExpectedWallCompleted {
        let trigger = preparation.and_then(|()| self.wait_wall());
        let (qualified, primary) = match trigger {
            Ok(trigger) => (
                trigger.process == self.process.0 as usize
                    && trigger.job == self.job.handle as usize,
                None,
            ),
            Err(error) => (false, Some(error)),
        };
        self.expected_wall = qualified;
        // Ordinary cleanup preserves the original failure and makes no undebugged/natural-exit claim.
        let cleanup = completion::complete_run(primary, Flags::default(), &mut self).into_error();
        let result = match cleanup {
            Some(error) => Err(error),
            None => self
                .wall_exit
                .ok_or_else(|| anyhow::anyhow!("expected wall did not retain its actual exit")),
        };
        let retired = if qualified && result.is_ok() && self.resources_retired() && !self.signaled {
            match ticket.retired_expected_wall() {
                Ok(retired) => Some(WallTreeRetired { retired }),
                Err(error) => {
                    return ExpectedWallCompleted {
                        result: Err(error),
                        retired: None,
                    };
                }
            }
        } else {
            None
        };
        ExpectedWallCompleted { result, retired }
    }
}
