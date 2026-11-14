//! Concrete native resource completion. Only this owner can issue observation retirement.
use super::registry_scope::{
    LeaseBinding, LeaseKind, LeaseScope, Restore, RestoreTransaction, Retired, Ticket,
};
use super::*;
use crate::windows_security::{
    activation::Failures,
    policy::registry_comparison::completion::{self, CompletionIo, Flags, ReceiptRetainer},
};
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
#[path = "authority_wall.rs"]
mod wall;
pub(super) use wall::ExpectedWallCompleted;

/// Distinct from runtime::ReapedProcessTree: one bound native observation only.
pub(in crate::windows_security::native) struct NativeTreeRetired {
    retired: Retired,
}
impl NativeTreeRetired {
    pub(super) fn advance_intermediate(self) -> Result<()> {
        self.retired.advance_intermediate()
    }
    pub(super) fn begin_restore(
        self,
        profile: &super::NativeProfileBinding<'_>,
    ) -> Result<RestoreTransaction> {
        self.retired.begin_restore(profile)
    }
    pub(super) fn complete(self) -> Result<()> {
        self.retired.complete()
    }
    pub(in crate::windows_security::native) fn restore(
        self,
        lease: &LeaseScope,
    ) -> Result<Restore> {
        self.retired.restore(lease)
    }
}
pub(super) struct Observation {
    pub code: u32,
    pub output: String,
    pub errors: String,
}
pub(super) struct Completed {
    pub result: Result<Observation>,
    pub retired: Option<NativeTreeRetired>,
}
pub(super) struct NativeCompletion<'a> {
    pub job: WindowsJob,
    pub process: Owned,
    pub thread: Owned,
    pub stdin: Owned,
    pub stdout: Owned,
    pub stdout_writer: Owned,
    pub stderr: Owned,
    pub stderr_writer: Owned,
    pub restricted: Owned,
    pub descriptor: Descriptor,
    pub attributes: Option<Attributes>,
    pub source: Option<authority_image::AuthorityImage>,
    pub target: Option<authority_image::AuthorityImage>,
    pub prepared: Option<tempfile::TempDir>,
    pub profile_registry: profile_registry::ProfileRegistry,
    pub output: Capture,
    pub error: Capture,
    pub observer: &'a mut dyn AuthorityObserver,
    pub started: bool,
    pub signaled: bool,
    pub assigned: bool,
    resumed: bool,
    creation_attempted: bool,
    creation_valid: bool,
    direct_reaped: bool,
    job_reaped: bool,
    failed: bool,
    releases: usize,
    observer_finished: bool,
    expected_wall: bool,
    wall_exit: Option<u32>,
}
/// Borrow of this actual created/assigned, still-suspended owner. No caller can construct it.
pub(in crate::windows_security::native) struct SuspendedWorker<'a> {
    process: &'a Owned,
    job: &'a WindowsJob,
    resumed: &'a bool,
    profile: &'a super::NativeProfileBinding<'a>,
    ticket: &'a Ticket,
    registry: &'a profile_registry::ProfileRegistry,
}
impl SuspendedWorker<'_> {
    pub(in crate::windows_security::native) fn require_profile(
        &self,
        profile: &super::NativeProfileBinding<'_>,
    ) -> Result<()> {
        self.ticket.require_profile(profile)?;
        ensure!(
            !*self.resumed && self.job.state == Lifecycle::Qualified,
            "native suspended view was consumed by resume"
        );
        let mut member = 0;
        let mut value: super::super::Accounting = unsafe { zeroed() };
        let mut returned = 0;
        ensure!(
            unsafe { WaitForSingleObject(self.process.0, 0) } == 258
                && unsafe { IsProcessInJob(self.process.0, self.job.handle, &mut member) } != 0
                && member == 1,
            "native suspended process/job binding differs"
        );
        ensure!(
            unsafe {
                QueryInformationJobObject(
                    self.job.handle,
                    1,
                    (&mut value as *mut super::super::Accounting).cast(),
                    size_of::<super::super::Accounting>() as u32,
                    &mut returned,
                )
            } != 0
                && returned as usize == size_of::<super::super::Accounting>()
                && value.active == 1
                && value.total == 1,
            "native suspended owner is not the one primary job"
        );
        Ok(())
    }
    pub(in crate::windows_security::native) fn process(&self) -> BorrowedHandle<'_> {
        // SAFETY: the non-null process slot is borrowed from its live actual owner;
        // this view prevents mutable owner resume/close for the borrow's duration.
        unsafe { BorrowedHandle::borrow_raw(self.process.0) }
    }
    pub(in crate::windows_security::native) fn job(&self) -> &WindowsJob {
        self.job
    }
    pub(in crate::windows_security::native) fn reserve_lease(
        &self,
        kind: LeaseKind,
        resource: &str,
    ) -> Result<LeaseBinding> {
        self.require_profile(self.profile)?;
        self.ticket.reserve_lease(kind, resource)
    }
    pub(in crate::windows_security::native) fn require_readonly_registry(&self) -> Result<()> {
        self.require_profile(self.profile)?;
        self.registry.require_readonly(
            self.process().as_raw_handle(),
            self.profile.view().package_sid(),
        )
    }
}
fn combined(results: impl IntoIterator<Item = Result<()>>) -> Result<()> {
    let mut errors = results
        .into_iter()
        .filter_map(Result::err)
        .collect::<Vec<_>>();
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.remove(0)),
        _ => Err(Failures { errors }.into()),
    }
}
impl<'a> NativeCompletion<'a> {
    pub fn new(observer: &'a mut dyn AuthorityObserver) -> Result<Self> {
        Ok(Self {
            job: WindowsJob::create(JobLimits::default())?,
            process: Owned(null_mut()),
            thread: Owned(null_mut()),
            stdin: Owned(null_mut()),
            stdout: Owned(null_mut()),
            stdout_writer: Owned(null_mut()),
            stderr: Owned(null_mut()),
            stderr_writer: Owned(null_mut()),
            restricted: Owned(null_mut()),
            descriptor: Descriptor(null_mut()),
            attributes: None,
            source: None,
            target: None,
            prepared: None,
            profile_registry: profile_registry::ProfileRegistry::default(),
            output: Capture::default(),
            error: Capture::default(),
            observer,
            started: false,
            signaled: false,
            assigned: false,
            resumed: false,
            creation_attempted: false,
            creation_valid: false,
            direct_reaped: false,
            job_reaped: false,
            failed: false,
            releases: 0,
            observer_finished: false,
            expected_wall: false,
            wall_exit: None,
        })
    }
    pub(super) fn suspended<'b>(
        &'b self,
        profile: &'b super::NativeProfileBinding<'_>,
        ticket: &'b Ticket,
    ) -> Result<SuspendedWorker<'b>> {
        ensure!(
            self.started
                && self.assigned
                && self.creation_valid
                && !self.resumed
                && !self.signaled
                && self.job.state == Lifecycle::Qualified,
            "native owner is not created/assigned/qualified and suspended"
        );
        let worker = SuspendedWorker {
            process: &self.process,
            job: &self.job,
            resumed: &self.resumed,
            profile,
            ticket,
            registry: &self.profile_registry,
        };
        worker.require_profile(profile)?;
        crate::windows_security::sxs::with_authority(
            self.process.0,
            profile.view().package_sid(),
            || Ok(()),
            |require| require(),
        )?;
        Ok(worker)
    }
    pub(super) fn resume(&mut self) -> Result<()> {
        ensure!(
            self.started
                && self.assigned
                && self.creation_valid
                && !self.resumed
                && !self.signaled
                && self.job.state == Lifecycle::Qualified,
            "native resume state differs or attempt already consumed"
        );
        self.resumed = true;
        ensure!(
            unsafe { NtResumeProcess(self.process.0) } == 0,
            "resume native owned child failed"
        );
        self.job.state.advance(Lifecycle::Running)
    }
    fn note(&mut self, result: Result<()>) -> Result<()> {
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn creation(&mut self, info: ProcessInfo, created: i32) {
        self.creation_attempted = true;
        self.started = created != 0;
        self.process = Owned::creation_output(info.process);
        self.thread = Owned::creation_output(info.thread);
        self.creation_valid =
            created == 0 || (!self.process.0.is_null() && !self.thread.0.is_null());
    }
    pub fn close_inputs(&mut self) -> Result<()> {
        let result = combined([
            self.restricted.close(),
            self.descriptor.close(),
            self.stdout_writer.close(),
            self.stderr_writer.close(),
            self.stdin.close(),
        ]);
        self.note(result)
    }
    pub fn finish(mut self, operation: Result<Observation>, ticket: Ticket) -> Completed {
        let flags = Flags {
            authority: true,
            undebugged: true,
            started: self.started,
            signaled: self.signaled,
            ..Flags::default()
        };
        let (value, primary) = match operation {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error)),
        };
        let result = completion::complete_run(primary, flags, &mut self)
            .into_error()
            .map_or_else(
                || {
                    value.ok_or_else(|| {
                        anyhow::anyhow!("native authority lost its operation failure")
                    })
                },
                Err,
            );
        let ready = self.signaled && self.resources_retired();
        let retired = if ready {
            match ticket.retired() {
                Ok(retired) => Some(NativeTreeRetired { retired }),
                Err(error) => {
                    return Completed {
                        result: Err(match result {
                            Ok(_) => error,
                            Err(primary) => Failures {
                                errors: vec![primary, error],
                            }
                            .into(),
                        }),
                        retired: None,
                    };
                }
            }
        } else {
            None
        };
        Completed { result, retired }
    }
    fn resources_retired(&self) -> bool {
        !self.failed
            && self.started
            && self.resumed
            && self.direct_reaped
            && self.job_reaped
            && self.creation_attempted
            && self.creation_valid
            && self.observer_finished
            && self.releases == 11
            && self.job.handle.is_null()
            && [
                self.process.0,
                self.thread.0,
                self.stdin.0,
                self.stdout.0,
                self.stdout_writer.0,
                self.stderr.0,
                self.stderr_writer.0,
                self.restricted.0,
                self.descriptor.0,
            ]
            .iter()
            .all(|handle| handle.is_null())
            && self.attributes.is_none()
            && self.source.is_none()
            && self.target.is_none()
            && self.prepared.is_none()
    }
    fn close_capture(&mut self, error: bool, mut retain: ReceiptRetainer<'_>) -> Result<()> {
        let (reader, writer, capture, limit) = if error {
            (
                &mut self.stderr,
                &mut self.stderr_writer,
                &mut self.error,
                ERROR_LIMIT,
            )
        } else {
            (
                &mut self.stdout,
                &mut self.stdout_writer,
                &mut self.output,
                OUTPUT_LIMIT,
            )
        };
        let mut failures = Vec::new();
        if reader.0.is_null() {
            capture.end();
        } else if let Err(error) = drain(reader, capture, limit) {
            failures.push(error);
        }
        if let Some(retain) = retain.as_mut() {
            let (mut prefix, truncated) =
                crate::windows_security::activation::capture::prefix(&capture.bytes);
            retain(&prefix, truncated);
            prefix.fill(0);
        }
        if let Err(error) = writer.close() {
            failures.push(error);
        }
        if let Err(error) = reader.close() {
            failures.push(error);
        }
        // Reads are synchronous and only performed by this owner: no pending async read or thread exists.
        if let Some(retain) = retain.as_mut() {
            let (mut prefix, truncated) =
                crate::windows_security::activation::capture::prefix(&capture.bytes);
            retain(&prefix, truncated);
            prefix.fill(0);
        }
        if !capture.eof {
            failures.push(anyhow::anyhow!(
                "native authority capture did not reach EOF"
            ));
        }
        capture.clear();
        let result = combined(failures.into_iter().map(Err));
        self.note(result)
    }
}
impl CompletionIo for NativeCompletion<'_> {
    fn terminate(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        if !self.process.0.is_null() && !self.assigned {
            let signal = unsafe { WaitForSingleObject(self.process.0, 0) };
            if signal == 258 && unsafe { TerminateProcess(self.process.0, 125) } == 0 {
                failures.push(anyhow::anyhow!(
                    "terminate unassigned native authority failed"
                ));
            } else if signal != 0 && signal != 258 {
                failures.push(anyhow::anyhow!(
                    "query unassigned native authority signal failed"
                ));
            }
        }
        if let Err(error) = self.job.request_termination() {
            failures.push(error);
        }
        let result = combined(failures.into_iter().map(Err));
        self.note(result)
    }
    fn reap(&mut self) -> Result<()> {
        let direct = if self.process.0.is_null() {
            !self.started
        } else {
            (unsafe { WaitForSingleObject(self.process.0, 2000) }) == 0
        };
        self.direct_reaped = direct;
        let job = self.job.reap();
        self.job_reaped = job.is_ok();
        let observed = self.observer.after_reap(direct && self.job_reaped);
        self.observer_finished = observed.is_ok();
        let exit = if self.expected_wall && direct && self.job_reaped {
            let mut code = 0;
            if unsafe { GetExitCodeProcess(self.process.0, &mut code) } != 0 {
                self.wall_exit = Some(code);
                Ok(())
            } else {
                Err(anyhow::anyhow!("expected wall actual exit query failed"))
            }
        } else {
            Ok(())
        };
        let result = combined([
            if direct {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "native authority direct child was not reaped"
                ))
            },
            job,
            observed,
            exit,
        ]);
        self.note(result)
    }
    fn confirm_destroyed(&mut self) -> Option<Result<()>> {
        None
    }
    fn query_exit(&mut self) -> Result<Option<u32>> {
        completion::actual_exit(
            self.started,
            || Ok(unsafe { WaitForSingleObject(self.process.0, 0) }),
            || {
                let mut code = 0;
                ensure!(
                    unsafe { GetExitCodeProcess(self.process.0, &mut code) } != 0,
                    "query actual native authority exit failed"
                );
                Ok(code)
            },
        )
    }
    fn close_output(&mut self) -> Result<()> {
        self.close_capture(false, None)
    }
    fn close_error(&mut self, retain: ReceiptRetainer<'_>) -> Result<()> {
        self.close_capture(true, retain)
    }
    fn release_count(&self) -> usize {
        11
    }
    fn release(&mut self, index: usize) -> Result<()> {
        let result = match index {
            0 => self.thread.close(),
            1 => self.process.close(),
            2 => self.stdin.close(),
            3 => self.restricted.close(),
            4 => self.descriptor.close(),
            5 => {
                if let Some(mut attributes) = self.attributes.take() {
                    attributes.close();
                }
                Ok(())
            }
            6 => self.source.take().map_or(Ok(()), |mut image| image.close()),
            7 => self.target.take().map_or(Ok(()), |mut image| image.close()),
            8 => self.profile_registry.close(),
            9 => self
                .prepared
                .take()
                .map_or(Ok(()), |directory| directory.close().map_err(Into::into)),
            10 => self.job.close_retired(),
            _ => Err(anyhow::anyhow!("foreign native completion release index")),
        };
        self.releases += 1;
        self.note(result)
    }
    fn metadata(&mut self) -> Result<String> {
        anyhow::bail!("machine authority does not issue trace metadata")
    }
    fn emit(&mut self, _: &str) -> Result<()> {
        anyhow::bail!("machine authority does not issue trace records")
    }
}
