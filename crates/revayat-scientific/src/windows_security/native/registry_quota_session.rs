//! Same-profile machine/quota observations with one consumed final restoration transaction.
use super::super::{authority_quota_run, quota_plan::PreparedQuota, registry_scope::LeaseKind};
use super::*;
use crate::windows_security::native::{ScratchVolume, scratch_lease::VolumeLease};

fn experiment(
    image: &Path,
    machine_identity: &crate::identity::Fingerprint,
    quota_image: &Path,
    quota_identity: &crate::identity::Fingerprint,
    profile: &Profile,
    view: &NativeRunView,
    volume: &mut ScratchVolume,
) -> Result<String> {
    let PreparedQuota {
        plan,
        directory,
        arguments_sha256,
    } = PreparedQuota::new(view, volume)?;
    let prepared = (|| {
        let binding = NativeProfileBinding::machine_quota(
            view,
            profile,
            &machine_identity.sha256,
            &quota_identity.sha256,
            &arguments_sha256,
        )?;
        let original = read_surface()?;
        finish_negative(observe(
            image,
            machine_identity,
            profile,
            &binding,
            Plan::Original,
        )?)?;
        original.require_equal(&read_surface()?)?;
        let machine = MachineLease::begin_session(&binding)?;
        Ok((binding, original, machine))
    })();
    let (binding, original, mut machine) = match prepared {
        Ok(value) => value,
        Err(primary) => {
            return crate::runtime::with_cleanup(
                Err(primary),
                directory.close().map_err(Into::into),
            );
        }
    };
    let mut directory = Some(directory);
    let mut volume_lease: Option<VolumeLease<'_>> = None;
    let result = (|| {
        let modified = observe(image, machine_identity, profile, &binding, Plan::Modified)?;
        let retired = match modified.retired {
            Some(retired) => retired,
            None => {
                return Err(modified.result.err().unwrap_or_else(|| {
                    anyhow::anyhow!("modified machine actor did not retire its owned tree")
                }));
            }
        };
        let modified = modified.result?;
        wire::require_root_only(&modified.output)?;
        retired.advance_intermediate()?;
        let ticket =
            binding
                .scope
                .begin_quota(view.run_id(), &quota_identity.sha256, &arguments_sha256)?;
        let quota = authority_quota_run::run(
            authority_quota_run::QuotaLaunch {
                image: quota_image,
                expected: quota_identity,
                profile,
                binding: &binding,
                plan: &plan,
                directory: directory
                    .take()
                    .expect("quota preparation transferred once"),
                ticket,
            },
            volume,
        )?;
        volume_lease = quota.lease;
        let retired = match quota.completed.retired {
            Some(retired) => retired,
            None => {
                return Err(quota.completed.result.err().unwrap_or_else(|| {
                    anyhow::anyhow!("quota actor lacks actual complete native retirement")
                }));
            }
        };
        let mut restoring: super::super::RestoreTransaction = retired.begin_restore(&binding)?;
        restoring.attempt(LeaseKind::Machine, |authorization| {
            authorization.require_profile(&binding)?;
            machine.restore_authorized(authorization)
        });
        restoring.attempt(LeaseKind::Volume, |authorization| {
            volume_lease
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("quota volume policy owner missing"))?
                .restore_authorized(volume, authorization)
        });
        let restored = restoring.finish();
        let quota = crate::runtime::with_cleanup(quota.completed.result, restored)?;
        ensure!(
            quota.code == 0 && quota.errors.is_empty(),
            "quota actor transport remains unqualified"
        );
        original.require_equal(&read_surface()?)?;
        finish_negative(observe(
            image,
            machine_identity,
            profile,
            &binding,
            Plan::Restored,
        )?)?;
        binding.scope.close()?;
        Ok(format!(
            "{}{}WINDOWS_MACHINE_QUOTA original_access_denied=True restored_access_denied=True host_surface_restored=True volume_policy_restored=True quota_subset_only=True target_admitted=False production_grant=False\n",
            modified.output, quota.output
        ))
    })();
    let result = crate::runtime::with_cleanup(
        result,
        directory.map_or(Ok(()), |directory| directory.close().map_err(Into::into)),
    );
    match result {
        Ok(output) => Ok(output),
        Err(primary) => {
            let machine_cleanup = machine.defer();
            let volume_cleanup = volume_lease.as_mut().map_or(Ok(()), VolumeLease::defer);
            Err(primary_first(
                primary,
                crate::runtime::with_cleanup(machine_cleanup, volume_cleanup),
            ))
        }
    }
}

/// Disposable-host diagnostic; quota controls remain a separate subset of the full kernel suite.
pub fn run_machine_quota_session(image: &Path, view: &NativeRunView) -> Result<String> {
    crate::windows_security::activation::native::require_host()?;
    view.require()?;
    plain_path(image)?;
    let executable = std::env::current_exe()?;
    let directory = crate::executable_paths::binary_directory(&executable)?;
    let machine_image = directory.join("registry-authority.exe");
    let quota_image = directory.join("revayat-quota-worker.exe");
    ensure!(
        image.file_name() == machine_image.file_name()
            && crate::identity::path_object_id(image)?
                == crate::identity::path_object_id(&machine_image)?,
        "machine quota controller requires its fixed same-profile sibling"
    );
    let machine_identity = crate::identity::file_identity(&machine_image, Some(8 * 1024 * 1024))?;
    let quota_identity = crate::identity::file_identity(&quota_image, Some(8 * 1024 * 1024))?;
    let mut held_machine =
        authority_image::AuthorityImage::open(&machine_image, &machine_identity)?;
    let mut held_quota =
        match authority_image::AuthorityImage::open_quota(&quota_image, &quota_identity) {
            Ok(held) => held,
            Err(primary) => return Err(primary_first(primary, held_machine.close())),
        };
    let mut profile = match Profile::new_owned(view) {
        Ok(profile) => profile,
        Err(primary) => {
            return Err(primary_first(
                primary,
                crate::runtime::with_cleanup(held_machine.close(), held_quota.close()),
            ));
        }
    };
    let mut volume = None;
    let operation = (|| {
        volume = Some(ScratchVolume::prepare(view)?);
        let output = experiment(
            &machine_image,
            &machine_identity,
            &quota_image,
            &quota_identity,
            &profile,
            view,
            volume.as_mut().unwrap(),
        )?;
        held_machine.require(&machine_image)?;
        held_quota.require(&quota_image)?;
        Ok(output)
    })();
    let closing = crate::runtime::with_cleanup(
        volume.as_mut().map_or(Ok(()), ScratchVolume::close),
        crate::runtime::with_cleanup(held_machine.close(), held_quota.close()),
    );
    let profile_cleanup = if operation.is_ok() && closing.is_ok() {
        profile.close()
    } else {
        profile.retain()
    };
    crate::runtime::with_cleanup(
        crate::runtime::with_cleanup(operation, closing),
        profile_cleanup,
    )
    .map_err(wire::sanitize)
}
