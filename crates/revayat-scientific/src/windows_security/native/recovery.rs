//! Durable policy and profile recovery after actual outer-tree finalization.
use super::state::NativeRunOwner;
use super::*;
use crate::runtime::ReapedProcessTree;
#[link(name = "userenv")]
unsafe extern "system" {
    fn DeleteAppContainerProfile(name: *const u16) -> i32;
}

/// Whole-worker recovery restores durable machine intent before profile deletion.
pub fn recover_run(owner: &mut NativeRunOwner, proof: &ReapedProcessTree) -> Result<()> {
    proof.require_binding(owner.recovery_binding())?;
    if owner.recovered {
        return reject_repeated_recovery();
    }
    let restored = crate::windows_security::sxs::recover_owned_session(owner, proof)
        .and_then(|()| super::registry_machine::MachineLease::recover(owner, proof))
        .and_then(|()| super::scratch_recovery::recover_scratch(owner, proof));
    match restored {
        Ok(()) => finish_profile_recovery(owner, proof),
        Err(primary) => crate::runtime::with_cleanup(Err(primary), owner.close()),
    }
}

/// Repeated recovery retains the legacy typed operation/reporting failure without touching pins.
fn reject_repeated_recovery() -> Result<()> {
    use crate::windows_security::preparation::{bootstrap_progress, invoke_bootstrap_recovery};
    invoke_bootstrap_recovery(
        bootstrap_progress,
        || Err(anyhow::anyhow!("profile recovery already completed")),
        || Ok(()),
    )
    .map_err(anyhow::Error::new)
}

/// Compatibility entry point; durable policy recovery always precedes profile deletion.
pub fn recover_profile(owner: &mut NativeRunOwner, proof: &ReapedProcessTree) -> Result<()> {
    recover_run(owner, proof)
}

/// The proof binds the trusted fixed controller invocation, not an arbitrary command or gate pass.
/// Other lease/session/volume recovery must finish separately before any state-directory removal.
fn finish_profile_recovery(owner: &mut NativeRunOwner, proof: &ReapedProcessTree) -> Result<()> {
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

#[path = "sxs_journal.rs"]
mod sxs_journal;
pub(crate) use sxs_journal::SxsJournal;
