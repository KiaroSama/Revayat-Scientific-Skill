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
    proof.require_binding(owner.recovery_binding())?;
    ensure!(!owner.recovered, "profile recovery already completed");
    owner.view.require()?;
    let created = owner.view.recovery_disposition()?;
    if created {
        let name = authority::wide(owner.view.profile_name());
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
}
