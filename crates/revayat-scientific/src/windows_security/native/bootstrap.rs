//! Exact original bootstrap validation order. Native actor evidence is collected separately.
use super::{
    NativeRunView,
    io::{self as state_io, Pin},
};
use crate::windows_security::{
    activation as a, diagnostic_validation as d, image, policy as p, preparation, scratch, sxs,
};
use anyhow::{Result, ensure};
use std::{cell::Cell, fmt, io::Write, path::Path};

struct ValidationFailure {
    index: i32,
    original: anyhow::Error,
}
impl fmt::Display for ValidationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let category = if self
            .original
            .downcast_ref::<crate::runtime::DeadlineExceeded>()
            .is_some()
        {
            "deadline"
        } else {
            "validation-or-cleanup"
        };
        write!(
            f,
            "native bootstrap failed index={} category={category} private_cause_retained=True",
            self.index
        )
    }
}
impl fmt::Debug for ValidationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for ValidationFailure {}

fn direct(index: i32, operation: impl FnOnce() -> Result<()>) -> Result<()> {
    let marker = |state| -> Result<()> {
        let mut output = std::io::stderr().lock();
        let line = String::from("WINDOWS_BOOTSTRAP_DIRECT state=")
            + state
            + " index="
            + &index.to_string()
            + "\n";
        output.write_all(line.as_bytes())?;
        output.flush()?;
        Ok(())
    };
    marker("before")?;
    operation()?;
    marker("after")
}

fn managed(index: i32, work: &Path) -> Result<()> {
    match index {
        1 => p::profile_validation::check_seal_comparison(),
        2 => p::profile_validation::check_registry_masks(),
        3 => d::check_loader_snaps_validation(),
        4 => p::token_validation::check_default_metadata_validation(),
        5 => p::default_control::check_child_validation(),
        6 => p::default_control::check_control_validation(),
        7 => p::default_control::comparison::check_validation(),
        8 => image::check_validation(),
        9 => image::check_checkpoint_validation(),
        10 => image::check_import_validation(),
        11 => image::check_manifest_validation(),
        12 => image::check_activation_worker_validation(),
        13 => a::check_startup_activation_validation(),
        14 => a::check_fixed_dll_validation(),
        15 => crate::windows_security::startup_registry::check_validation(),
        16 => crate::windows_security::loader_comparison::check_validation(),
        17 => p::registry_lease::check_validation(),
        18 => p::registry_comparison::check_causal_validation(),
        19 => a::check_manual_activation_validation(),
        20 => a::automatic::check_validation(),
        21 => a::csr::check_validation(),
        22 => a::csr::check_module_validation(),
        23 => a::native_pass::check_validation(work),
        24 => a::preparation::check_validation(),
        25 => p::registry_comparison::check_startup_validation(),
        26 => p::registry_comparison::check_authority_validation(),
        27 => p::registry_comparison::check_supported_validation(),
        28 => a::check_policy_result_validation(),
        29 => sxs::check_startup_events_validation(),
        30 => a::native::check_assembly_validation(work),
        31 => p::token_validation::check_startup_token_validation(),
        32 => a::fixtures::child::check_child_validation(work),
        33 => a::fixtures::dll_request::check_dll_request_validation(),
        34 => image::check_default_activation_validation(),
        35 => a::fixtures::default::check_default_validation(work),
        36 => a::fixtures::self_host::check_self_validation(work),
        37 => a::fixtures::source::check_self_source_validation(),
        38 => image::check_module_activation_validation(),
        39 => a::fixtures::module::check_module_validation(work),
        40 => a::boundary::check_validation(),
        41 => a::module_callback::check_validation(),
        42 => scratch::check_access_validation(),
        43 => scratch::check_supported_validation(),
        44 => scratch::check_file_creation_validation(),
        45 => scratch::check_volume_access_validation(),
        46 => scratch::check_attachment_validation(),
        47 => scratch::check_volume_policy_validation(),
        48 => d::check_startup_image_access_validation(),
        49 => d::check_trusted_setup_validation(),
        50 => d::check_static_kernel_inspection_validation(),
        51 => d::check_hardware_trace_validation(),
        52 => d::check_debug_control_validation(),
        53 => scratch::check_private_creator_validation(),
        _ => anyhow::bail!("unknown native bootstrap validator"),
    }
}

/// This executes the source-backed validation bodies in their original order.
/// It does not stand in for any subsequent native experiment or full preflight.
pub fn run_bootstrap_checks(view: &NativeRunView) -> Result<()> {
    let stage = Cell::new(0);
    let result = (|| {
        a::native::require_host()?;
        view.require()?;
        let work = view.state_path().join("bootstrap-validation");
        state_io::create_private(&work, &sxs::current_user_sid()?)?;
        let mut pin = Pin::open(&work, true)?;
        let operation = (|| {
            let dos_work = crate::windows_security::native::dos_path::existing(&work)?;
            pin.require()?;
            for index in 1..=53 {
                stage.set(index);
                preparation::invoke_bootstrap_stage(
                    "managed",
                    index,
                    preparation::bootstrap_progress,
                    || {
                        view.require()?;
                        pin.require()?;
                        managed(index, &dos_work)?;
                        ensure!(
                            std::fs::read_dir(&work)?.next().is_none(),
                            "bootstrap fixture cleanup remains incomplete"
                        );
                        view.require()?;
                        pin.require()
                    },
                )?;
            }
            stage.set(54);
            direct(0, || {
                a::fixtures::python_startup::check_validation(&dos_work)
            })?;
            ensure!(
                std::fs::read_dir(&work)?.next().is_none(),
                "bootstrap clone fixture cleanup remains incomplete"
            );
            pin.require()?;
            stage.set(55);
            direct(1, a::fixtures::registry_loader::check_validation)?;
            stage.set(56);
            direct(2, sxs::check_capture_validation)?;
            stage.set(57);
            direct(3, a::control::check_trace_control_validation)?;
            stage.set(58);
            Ok(())
        })();
        let closing = pin.close();
        crate::runtime::with_cleanup(operation, closing)?;
        ensure!(
            crate::identity::path_object_id(&work)? == pin.id,
            "bootstrap validation directory changed"
        );
        std::fs::remove_dir(&work)?;
        Ok(())
    })();
    result.map_err(|original| {
        ValidationFailure {
            index: stage.get(),
            original,
        }
        .into()
    })
}
