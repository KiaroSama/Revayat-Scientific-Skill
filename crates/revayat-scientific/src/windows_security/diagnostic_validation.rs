//! Source-derived diagnostic control operations and callable validation roots.
//! Portable validation never attests an actual debug event, token or image-section open.
use super::activation;
use anyhow::{Result, ensure};
#[path = "diagnostic_validation/capture.rs"]
pub mod capture;
#[path = "diagnostic_validation/hardware.rs"]
pub mod hardware;
#[path = "diagnostic_validation/loader_snaps.rs"]
pub mod loader_snaps;
#[path = "diagnostic_validation/static_kernel.rs"]
pub mod static_kernel;
#[path = "diagnostic_validation/trusted_setup.rs"]
pub mod trusted_setup;
pub use hardware::check_hardware_trace_validation;
pub use loader_snaps::check_loader_snaps_validation;
pub use static_kernel::check_static_kernel_inspection_validation;
pub use trusted_setup::check_trusted_setup_validation;

#[path = "diagnostic_validation/debug_control.rs"]
mod debug_control;
#[path = "diagnostic_validation/native_fixture.rs"]
mod native_fixture;
#[path = "diagnostic_validation/startup_image.rs"]
pub mod startup_image;
#[path = "diagnostic_validation/trap.rs"]
mod trap;
pub use debug_control::{
    check_debug_control_core_validation, debug_control_status, request_termination,
};
pub use native_fixture::{FixedNativeImage, check_native_debug_control_validation};
pub use startup_image::check_startup_image_access_validation;
pub use trap::check_trap_validation;

/// Complete original DebugControl.CheckValidation dependency order and direct body.
pub fn check_debug_control_validation() -> Result<()> {
    check_trap_validation()?;
    check_native_debug_control_validation()?;
    super::scratch::check_cleanup_validation()?;
    check_debug_control_core_validation()
}

fn value(context: &[u8], offset: usize) -> Result<u64> {
    ensure!(
        context.len() == activation::CONTEXT_SIZE,
        "fixed diagnostic x64 context width differs"
    );
    Ok(u64::from_le_bytes(context[offset..offset + 8].try_into()?))
}
fn put(context: &mut [u8], offset: usize, value: u64) {
    context[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn boolean(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}
