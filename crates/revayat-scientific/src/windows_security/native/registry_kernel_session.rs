//! Same-run kernel controls followed by a genuinely forced wall-tree and final policy restoration.
use super::super::{
    authority_kernel_run::{self, KernelLaunch},
    kernel_plan::PreparedKernel,
    registry_scope::LeaseKind,
};
use super::*;
use crate::windows_security::{
    kernel_controls::Role,
    native::{ScratchVolume, network::NetworkControls, scratch_lease::VolumeLease},
};
struct KernelImages<'a> {
    image: &'a Path,
    machine_identity: &'a crate::identity::Fingerprint,
    worker_image: &'a Path,
    worker_identity: &'a crate::identity::Fingerprint,
}
/// Fixed progress locates a refusal; it is never an operation outcome or cleanup proof.
fn progress(phase: &'static str) -> Result<()> {
    ensure!(
        matches!(
            phase,
            "plan"
                | "volume"
                | "session"
                | "original"
                | "modified"
                | "primary"
                | "wall"
                | "restore"
                | "restored"
                | "complete"
        ),
        "unsupported kernel controller phase"
    );
    use std::io::Write;
    let mut output = std::io::stderr().lock();
    writeln!(output, "WINDOWS_KERNEL_CONTROLLER phase={phase}")?;
    output.flush()?;
    Ok(())
}

fn experiment(
    image: &Path,
    machine_identity: &crate::identity::Fingerprint,
    worker_image: &Path,
    worker_identity: &crate::identity::Fingerprint,
    profile: &Profile,
    view: &NativeRunView,
    volume: &mut ScratchVolume,
) -> Result<String> {
    progress("plan")?;
    let mut canary = view.bound_quota_canary()?;
    let operation = experiment_with_canary(
        KernelImages {
            image,
            machine_identity,
            worker_image,
            worker_identity,
        },
        profile,
        view,
        volume,
        &canary,
    );
    crate::runtime::with_cleanup(operation, canary.close())
}
fn experiment_with_canary(
    images: KernelImages<'_>,
    profile: &Profile,
    view: &NativeRunView,
    volume: &mut ScratchVolume,
    canary: &super::super::super::state::QuotaCanary,
) -> Result<String> {
    let KernelImages {
        image,
        machine_identity,
        worker_image,
        worker_identity,
    } = images;
    let (_network, tcp, udp) = NetworkControls::paired()?;
    let primary = PreparedKernel::new(view, volume, canary, Role::KernelPrimary, tcp, udp)?;
    let wall = match PreparedKernel::new(view, volume, canary, Role::KernelWall, tcp, udp) {
        Ok(wall) => wall,
        Err(error) => {
            return crate::runtime::with_cleanup(
                Err(error),
                primary.directory.close().map_err(Into::into),
            );
        }
    };
    let PreparedKernel {
        plan: primary_plan,
        directory: primary_directory,
        arguments_sha256: primary_arguments,
    } = primary;
    let PreparedKernel {
        plan: wall_plan,
        directory: wall_directory,
        arguments_sha256: wall_arguments,
    } = wall;
    let prepared = (|| {
        let binding = NativeProfileBinding::kernel(
            view,
            profile,
            &machine_identity.sha256,
            &worker_identity.sha256,
            &primary_arguments,
            &wall_arguments,
        )?;
        let original = read_surface()?;
        original.require_equal(&read_surface()?)?;
        progress("original")?;
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
        Err(error) => {
            return crate::runtime::with_cleanup(
                Err(error),
                crate::runtime::with_cleanup(
                    primary_directory.close().map_err(Into::into),
                    wall_directory.close().map_err(Into::into),
                ),
            );
        }
    };
    let mut primary_directory = Some(primary_directory);
    let mut wall_directory = Some(wall_directory);
    let mut volume_lease: Option<VolumeLease<'_>> = None;
    let operation = (|| {
        progress("modified")?;
        canary.require(view)?;
        let modified = observe(image, machine_identity, profile, &binding, Plan::Modified)?;
        let retired = match modified.retired {
            Some(value) => value,
            None => {
                return Err(modified.result.err().unwrap_or_else(|| {
                    anyhow::anyhow!("kernel machine observation did not retire")
                }));
            }
        };
        let modified = modified.result?;
        wire::require_root_only(&modified.output)?;
        retired.advance_intermediate()?;
        progress("primary")?;
        let primary_ticket = binding.scope.begin_kernel(
            Plan::KernelPrimary,
            view.run_id(),
            &worker_identity.sha256,
            &primary_arguments,
        )?;
        let primary = authority_kernel_run::primary(
            KernelLaunch {
                image: worker_image,
                expected: worker_identity,
                profile,
                binding: &binding,
                plan: &primary_plan,
                directory: primary_directory
                    .take()
                    .expect("primary directory transfers once"),
                ticket: primary_ticket,
            },
            volume,
        )?;
        volume_lease = primary.lease;
        let retired = match primary.completed.retired {
            Some(value) => value,
            None => {
                return Err(primary.completed.result.err().unwrap_or_else(|| {
                    anyhow::anyhow!("kernel primary lacks complete natural retirement")
                }));
            }
        };
        let primary_output = primary.completed.result?;
        let inventory = primary
            .inventory_digest
            .ok_or_else(|| anyhow::anyhow!("kernel primary inventory binding is absent"))?;
        retired.advance_intermediate()?;
        progress("wall")?;
        let wall_ticket = binding.scope.begin_kernel(
            Plan::KernelWall,
            view.run_id(),
            &worker_identity.sha256,
            &wall_arguments,
        )?;
        let wall = authority_kernel_run::wall(
            KernelLaunch {
                image: worker_image,
                expected: worker_identity,
                profile,
                binding: &binding,
                plan: &wall_plan,
                directory: wall_directory
                    .take()
                    .expect("wall directory transfers once"),
                ticket: wall_ticket,
            },
            volume,
            volume_lease
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("kernel supported volume lease is absent"))?,
            &inventory,
        )?;
        let retired = match wall.retired {
            Some(value) => value,
            None => {
                return Err(wall.result.err().unwrap_or_else(|| {
                    anyhow::anyhow!("kernel wall lacks verified forced retirement")
                }));
            }
        };
        progress("restore")?;
        let mut restoring = retired.begin_restore(&binding)?;
        restoring.attempt(LeaseKind::Machine, |authorization| {
            authorization.require_profile(&binding)?;
            machine.restore_authorized(authorization)
        });
        restoring.attempt(LeaseKind::Volume, |authorization| {
            volume_lease
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("kernel volume restoration owner is absent"))?
                .restore_authorized(volume, authorization)
        });
        let actual_wall_exit = crate::runtime::with_cleanup(wall.result, restoring.finish())?;
        original.require_equal(&read_surface()?)?;
        progress("restored")?;
        finish_negative(observe(
            image,
            machine_identity,
            profile,
            &binding,
            Plan::Restored,
        )?)?;
        binding.scope.close()?;
        canary.require(view)?;
        progress("complete")?;
        Ok(format!(
            "{}{}WINDOWS_KERNEL_SESSION original_access_denied=True restored_access_denied=True host_surface_restored=True volume_policy_restored=True wall_tree_terminated=True wall_actual_exit={actual_wall_exit:08X} target_admitted=False\n",
            modified.output, primary_output.output
        ))
    })();
    let cleanup = crate::runtime::with_cleanup(
        primary_directory.map_or(Ok(()), |directory| directory.close().map_err(Into::into)),
        wall_directory.map_or(Ok(()), |directory| directory.close().map_err(Into::into)),
    );
    let result = crate::runtime::with_cleanup(operation, cleanup);
    match result {
        Ok(output) => Ok(output),
        Err(primary) => Err(primary_first(
            primary,
            crate::runtime::with_cleanup(
                machine.defer(),
                volume_lease.as_mut().map_or(Ok(()), VolumeLease::defer),
            ),
        )),
    }
}

/// The fixed Rust kernel subject retains the original kernel controls and distinct wall cleanup.
/// Genuine Python/activation observations remain separate required orchestration obligations.
pub fn run_machine_kernel_session(image: &Path, view: &NativeRunView) -> Result<String> {
    crate::windows_security::activation::native::require_host()?;
    view.require()?;
    plain_path(image)?;
    let executable = std::env::current_exe()?;
    let directory = crate::executable_paths::binary_directory(&executable)?;
    let machine_image = directory.join("registry-authority.exe");
    let worker_image = directory.join("revayat-quota-worker.exe");
    ensure!(
        image.file_name() == machine_image.file_name()
            && crate::identity::path_object_id(image)?
                == crate::identity::path_object_id(&machine_image)?,
        "kernel controller requires its fixed same-profile sibling"
    );
    let machine_identity = crate::identity::file_identity(&machine_image, Some(8 * 1024 * 1024))?;
    let worker_identity = crate::identity::file_identity(&worker_image, Some(8 * 1024 * 1024))?;
    let mut held_machine =
        authority_image::AuthorityImage::open(&machine_image, &machine_identity)?;
    let mut held_worker =
        match authority_image::AuthorityImage::open_quota(&worker_image, &worker_identity) {
            Ok(value) => value,
            Err(primary) => return Err(primary_first(primary, held_machine.close())),
        };
    let mut profile = match Profile::new_owned(view) {
        Ok(value) => value,
        Err(primary) => {
            return Err(primary_first(
                primary,
                crate::runtime::with_cleanup(held_machine.close(), held_worker.close()),
            ));
        }
    };
    let mut volume = None;
    let operation = (|| {
        progress("volume")?;
        volume = Some(ScratchVolume::prepare(view)?);
        progress("session")?;
        let output = experiment(
            &machine_image,
            &machine_identity,
            &worker_image,
            &worker_identity,
            &profile,
            view,
            volume.as_mut().unwrap(),
        )?;
        held_machine.require(&machine_image)?;
        held_worker.require(&worker_image)?;
        Ok(output)
    })();
    let closing = crate::runtime::with_cleanup(
        volume.as_mut().map_or(Ok(()), ScratchVolume::close),
        crate::runtime::with_cleanup(held_machine.close(), held_worker.close()),
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
