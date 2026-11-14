//! Actual full-kernel natural subject and distinct expected-wall subject under one profile.
use super::*;
use super::{
    authority_completion::{Completed, ExpectedWallCompleted, NativeCompletion, Observation},
    authority_launch::{self, LaunchKind},
    registry_scope::Ticket,
};
use crate::{
    identity,
    windows_security::{
        kernel_controls::{self, KernelPlan, Role},
        native::{ScratchVolume, native_quota, scratch_lease::VolumeLease},
    },
};

pub(super) struct KernelLaunch<'a> {
    pub image: &'a Path,
    pub expected: &'a identity::Fingerprint,
    pub profile: &'a Profile,
    pub binding: &'a NativeProfileBinding<'a>,
    pub plan: &'a KernelPlan,
    pub directory: tempfile::TempDir,
    pub ticket: Ticket,
}
pub(super) struct KernelCompleted<'a> {
    pub completed: Completed,
    pub lease: Option<VolumeLease<'a>>,
    pub inventory_digest: Option<String>,
}
fn refuse<T>(primary: anyhow::Error, directory: tempfile::TempDir) -> Result<T> {
    crate::runtime::with_cleanup(Err(primary), directory.close().map_err(Into::into))
}
pub(super) fn primary<'a>(
    launch: KernelLaunch<'a>,
    volume: &mut ScratchVolume,
) -> Result<KernelCompleted<'a>> {
    let KernelLaunch {
        image,
        expected,
        profile,
        binding,
        plan,
        directory,
        ticket,
    } = launch;
    if plan.role != Role::KernelPrimary {
        return refuse(
            anyhow::anyhow!("kernel primary plan role differs"),
            directory,
        );
    }
    if let Err(primary) = binding.require().and_then(|()| volume.require()) {
        return refuse(primary, directory);
    }
    let mut observer = NoObserver;
    let mut owner = match NativeCompletion::new(&mut observer) {
        Ok(value) => value,
        Err(primary) => return refuse(primary, directory),
    };
    let mut lease = None;
    let mut provisioned_path = None;
    let mut inventory_digest = None;
    let operation = (|| {
        let target = authority_launch::prepare(
            &mut owner,
            image,
            expected,
            profile,
            LaunchKind::Kernel { plan, directory },
        )?;
        let inventory = {
            let worker = owner.suspended(binding, &ticket)?;
            let inventory =
                native_quota::prepare_token(worker.process(), &plan.quota.package, |sid| {
                    volume.quota_owner(sid)
                })?;
            worker.require_readonly_registry()?;
            super::super::scratch_diagnostic::compare(volume, binding, &worker, |frames| {
                use std::io::Write;
                let mut output = std::io::stdout().lock();
                for frame in frames {
                    writeln!(output, "{frame}")?;
                }
                output.flush()?;
                Ok(())
            })?;
            volume.private_use(&worker, binding)?;
            lease = Some(VolumeLease::begin(volume, binding, &worker)?);
            lease.as_mut().unwrap().install(&worker)?;
            lease.as_ref().unwrap().require_resume(&worker)?;
            provisioned_path = Some(
                Path::new(&plan.quota.scratch)
                    .join("private-creator")
                    .join("authority-protected"),
            );
            native_quota::provision_private_creator_file(
                worker.process(),
                &plan.quota.scratch,
                &inventory,
            )?;
            inventory
        };
        inventory_digest = Some(inventory.digest());
        owner.source.as_mut().unwrap().require(image)?;
        owner.target.as_mut().unwrap().require(&target)?;
        owner
            .observer
            .before_resume(owner.process.0, &plan.quota.package, &target)?;
        owner.close_inputs()?;
        native_quota::require_host_afd_positive()?;
        owner.resume()?;
        let started = Instant::now();
        let mut progress = started;
        let mut count = 0;
        loop {
            drain(&owner.stdout, &mut owner.output, OUTPUT_LIMIT)?;
            drain(&owner.stderr, &mut owner.error, ERROR_LIMIT)?;
            let captured = owner.output.pending().len() + owner.error.pending().len();
            ensure!(
                captured <= OUTPUT_LIMIT,
                "kernel combined capture exceeds bound"
            );
            if captured != count {
                count = captured;
                progress = Instant::now();
            }
            let wait = unsafe { WaitForSingleObject(owner.process.0, 10) };
            ensure!(wait == 0 || wait == 258, "kernel primary wait failed");
            if wait == 0 {
                owner.signaled = true;
                break;
            }
            ensure!(
                started.elapsed() <= Duration::from_secs(60)
                    && progress.elapsed() <= Duration::from_secs(20),
                "kernel primary wall or progress deadline exceeded"
            );
        }
        let mut code = 0;
        ensure!(
            unsafe { GetExitCodeProcess(owner.process.0, &mut code) } != 0,
            "kernel primary actual exit query failed"
        );
        owner.job.terminate()?;
        drain(&owner.stdout, &mut owner.output, OUTPUT_LIMIT)?;
        drain(&owner.stderr, &mut owner.error, ERROR_LIMIT)?;
        let output = owner.output.finish(OUTPUT_LIMIT)?.to_owned();
        let errors = owner.error.finish(ERROR_LIMIT)?.to_owned();
        ensure!(
            code == 0 && errors.is_empty(),
            "kernel primary refused its actual fixed controls exit={code:08X}"
        );
        kernel_controls::require_primary_record(output.as_bytes(), plan, &inventory)?;
        owner.source.as_mut().unwrap().require(image)?;
        owner.target.as_mut().unwrap().require(&target)?;
        Ok(Observation {
            code,
            output,
            errors,
        })
    })();
    let mut completed = owner.finish(operation, ticket);
    if let Some(path) = provisioned_path {
        let cleanup = native_quota::cleanup_provisioned_private_file(&path);
        completed.result = crate::runtime::with_cleanup(completed.result, cleanup);
    }
    Ok(KernelCompleted {
        completed,
        lease,
        inventory_digest,
    })
}
pub(super) fn wall(
    launch: KernelLaunch<'_>,
    volume: &mut ScratchVolume,
    lease: &VolumeLease<'_>,
    inventory_digest: &str,
) -> Result<ExpectedWallCompleted> {
    let KernelLaunch {
        image,
        expected,
        profile,
        binding,
        plan,
        directory,
        ticket,
    } = launch;
    if plan.role != Role::KernelWall {
        return refuse(anyhow::anyhow!("kernel wall plan role differs"), directory);
    }
    if let Err(primary) = binding.require().and_then(|()| volume.require()) {
        return refuse(primary, directory);
    }
    let mut observer = NoObserver;
    let mut owner = match NativeCompletion::new(&mut observer) {
        Ok(value) => value,
        Err(primary) => return refuse(primary, directory),
    };
    let preparation = (|| {
        let target = authority_launch::prepare(
            &mut owner,
            image,
            expected,
            profile,
            LaunchKind::Kernel { plan, directory },
        )?;
        {
            let worker = owner.suspended(binding, &ticket)?;
            let inventory =
                native_quota::prepare_token(worker.process(), &plan.quota.package, |sid| {
                    volume.quota_owner(sid)
                })?;
            ensure!(
                inventory.digest() == inventory_digest,
                "kernel wall finite token inventory differs from primary"
            );
            worker.require_readonly_registry()?;
            lease.require_resume(&worker)?;
        }
        owner.source.as_mut().unwrap().require(image)?;
        owner.target.as_mut().unwrap().require(&target)?;
        owner
            .observer
            .before_resume(owner.process.0, &plan.quota.package, &target)?;
        owner.close_inputs()?;
        owner.resume()
    })();
    Ok(owner.finish_expected_wall(preparation, ticket))
}
