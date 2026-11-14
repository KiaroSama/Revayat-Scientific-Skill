//! One fixed quota actor, prepared and retired by the concrete native job owner.
use super::*;
use super::{
    authority_completion::{Completed, NativeCompletion, Observation},
    authority_launch::{self, LaunchKind},
    registry_scope::Ticket,
    registry_session::NativeProfileBinding,
};
use crate::windows_security::native::{ScratchVolume, native_quota, scratch_lease::VolumeLease};
use crate::{identity, windows_security::quota_controls};

pub(super) struct QuotaCompleted<'a> {
    pub completed: Completed,
    pub lease: Option<VolumeLease<'a>>,
}
pub(super) struct QuotaLaunch<'a> {
    pub image: &'a Path,
    pub expected: &'a identity::Fingerprint,
    pub profile: &'a Profile,
    pub binding: &'a NativeProfileBinding<'a>,
    pub plan: &'a quota_controls::WorkerPlan,
    pub directory: tempfile::TempDir,
    pub ticket: Ticket,
}
pub(super) fn run<'a>(
    launch: QuotaLaunch<'a>,
    volume: &mut ScratchVolume,
) -> Result<QuotaCompleted<'a>> {
    let QuotaLaunch {
        image,
        expected,
        profile,
        binding,
        plan,
        directory,
        ticket,
    } = launch;
    if let Err(primary) = binding.require().and_then(|()| volume.require()) {
        return crate::runtime::with_cleanup(Err(primary), directory.close().map_err(Into::into));
    }
    let mut observer = NoObserver;
    let mut owner = match NativeCompletion::new(&mut observer) {
        Ok(owner) => owner,
        Err(primary) => {
            return crate::runtime::with_cleanup(
                Err(primary),
                directory.close().map_err(Into::into),
            );
        }
    };
    let mut lease = None;
    let operation = (|| {
        let target = authority_launch::prepare(
            &mut owner,
            image,
            expected,
            profile,
            LaunchKind::Quota { plan, directory },
        )?;
        let inventory = {
            let worker = owner.suspended(binding, &ticket)?;
            worker.require_profile(binding)?;
            let inventory = native_quota::prepare_token(worker.process(), &plan.package, |sid| {
                volume.quota_owner(sid)
            })?;
            worker.require_readonly_registry()?;
            volume.private_use(&worker, binding)?;
            super::super::scratch_diagnostic::compare(volume, binding, &worker, |frames| {
                use std::io::Write;
                let mut output = std::io::stdout().lock();
                for frame in frames {
                    writeln!(output, "{frame}")?;
                }
                output.flush()?;
                Ok(())
            })?;
            lease = Some(VolumeLease::begin(volume, binding, &worker)?);
            lease.as_mut().unwrap().install(&worker)?;
            lease.as_ref().unwrap().require_resume(&worker)?;
            inventory
        };
        owner.source.as_mut().unwrap().require(image)?;
        owner.target.as_mut().unwrap().require(&target)?;
        owner
            .observer
            .before_resume(owner.process.0, &plan.package, &target)?;
        owner.close_inputs()?;
        owner.resume()?;
        let started = Instant::now();
        loop {
            drain(&owner.stdout, &mut owner.output, OUTPUT_LIMIT)?;
            drain(&owner.stderr, &mut owner.error, ERROR_LIMIT)?;
            let wait = unsafe { WaitForSingleObject(owner.process.0, 10) };
            ensure!(wait == 0 || wait == 258, "native quota primary wait failed");
            if wait == 0 {
                owner.signaled = true;
                break;
            }
            ensure!(
                started.elapsed() < Duration::from_secs(20),
                "native quota primary wall deadline exceeded"
            );
        }
        let mut code = 0;
        ensure!(
            unsafe { GetExitCodeProcess(owner.process.0, &mut code) } != 0,
            "native quota exit query failed"
        );
        owner.job.terminate()?;
        drain(&owner.stdout, &mut owner.output, OUTPUT_LIMIT)?;
        drain(&owner.stderr, &mut owner.error, ERROR_LIMIT)?;
        let output = owner.output.finish(OUTPUT_LIMIT)?.to_owned();
        let errors = owner.error.finish(ERROR_LIMIT)?.to_owned();
        ensure!(
            code == 0 && errors.is_empty(),
            "native quota primary refused its closed control plan exit={code:08X}"
        );
        quota_controls::require_primary_record(output.as_bytes(), plan, &inventory)?;
        owner.source.as_mut().unwrap().require(image)?;
        owner.target.as_mut().unwrap().require(&target)?;
        Ok(Observation {
            code,
            output,
            errors,
        })
    })();
    Ok(QuotaCompleted {
        completed: owner.finish(operation, ticket),
        lease,
    })
}
