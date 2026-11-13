//! Profile-only recovery after the trusted runtime's actual outer-tree finalization.
use super::state::NativeRunOwner;
use super::*;
use crate::runtime::ReapedProcessTree;
#[link(name = "userenv")]
unsafe extern "system" {
    fn DeleteAppContainerProfile(name: *const u16) -> i32;
}

/// The proof binds the trusted fixed controller invocation, not an arbitrary command or gate pass.
/// Other lease/session/volume recovery must finish separately before any state-directory removal.
pub fn recover_profile(owner: &mut NativeRunOwner, proof: &ReapedProcessTree) -> Result<()> {
    use crate::windows_security::preparation::{bootstrap_progress, invoke_bootstrap_recovery};
    // Rust links the recovery code ahead of execution. The legacy recovery-compile
    // phase now validates the real bound durable recovery context before deletion.
    let owner = std::cell::RefCell::new(owner);
    let created = std::cell::Cell::new(false);
    invoke_bootstrap_recovery(
        bootstrap_progress,
        || {
            let owner = owner.borrow();
            proof.require_binding(owner.recovery_binding())?;
            ensure!(!owner.recovered, "profile recovery already completed");
            owner.view.require()?;
            created.set(owner.view.recovery_disposition()?);
            Ok(())
        },
        || {
            let mut owner = owner.borrow_mut();
            if created.get() {
                let name = authority::wide(owner.view.profile_name());
                // SAFETY: the validated fixed owned profile name is live and NUL terminated.
                let status = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
                ensure!(
                    status == 0,
                    "owned profile recovery deletion failed hresult={:08X}; durable state retained",
                    status as u32
                );
            }
            owner.view.require()?;
            owner.recovered = true;
            // Only handles close here. Immutable receipts remain for other required recovery owners.
            owner.close()
        },
    )
    .map_err(anyhow::Error::new)
}
