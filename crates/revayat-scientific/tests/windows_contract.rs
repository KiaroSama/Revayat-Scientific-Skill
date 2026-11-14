//! Portable adversarial tests for the native Windows controller contracts.
//! These do not attest a kernel sandbox. windows_native is a separate CI gate.
use registry_authority::protocol as authority;
use revayat_scientific::windows_security::*;
use std::path::Path;
#[cfg(windows)]
#[path = "support/windows_junction.rs"]
mod windows_junction;

/// Resolve only a newly created, empty fixture root, before any adversarial paths exist.
fn owned_fixture_directory() -> (tempfile::TempDir, std::path::PathBuf) {
    let owner = tempfile::tempdir().unwrap();
    let original = owner.path();
    let metadata = std::fs::symlink_metadata(original).unwrap();
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert!(std::fs::read_dir(original).unwrap().next().is_none());
    let identity = revayat_scientific::identity::path_object_id(original).unwrap();
    // macOS's system temporary directory may be spelled through /var -> /private/var.
    // Preserve Windows's DOS spelling for the validators that deliberately require it.
    #[cfg(unix)]
    let physical = original.canonicalize().unwrap();
    #[cfg(not(unix))]
    let physical = original.to_path_buf();
    assert_eq!(
        revayat_scientific::identity::path_object_id(&physical).unwrap(),
        identity
    );
    assert_eq!(
        revayat_scientific::identity::path_object_id(original).unwrap(),
        identity
    );
    plain_path(&physical).unwrap();
    (owner, physical)
}

fn frame() -> Receipt {
    Receipt::new(Phase::Capture, Fault::Timeout)
}
fn privileges(entries: &[(u64, u32)]) -> Vec<u8> {
    let mut data = (entries.len() as u32).to_le_bytes().to_vec();
    for (luid, flags) in entries {
        data.extend(luid.to_le_bytes());
        data.extend(flags.to_le_bytes());
    }
    data
}
fn identity(units: &[u16]) -> Vec<u8> {
    let mut data = ((units.len() * 2) as u32).to_le_bytes().to_vec();
    for unit in units {
        data.extend(unit.to_le_bytes());
    }
    data
}
fn complete() -> Capture {
    let mut value = Capture::default();
    value.append(b"fixed\n", OUTPUT_LIMIT).unwrap();
    value.end();
    value
}

#[path = "windows_contract/activation_assembly.rs"]
mod activation_assembly;
#[path = "windows_contract/activation_parity.rs"]
mod activation_parity;
#[path = "windows_contract/bootstrap.rs"]
mod bootstrap;
#[path = "windows_contract/debug_native.rs"]
mod debug_native;
#[path = "windows_contract/dispatch_parity.rs"]
mod dispatch_parity;
#[path = "windows_contract/image_parity.rs"]
mod image_parity;
#[path = "windows_contract/kernel_descendants.rs"]
mod kernel_descendants;
#[path = "windows_contract/loader_parity.rs"]
mod loader_parity;
#[path = "windows_contract/policy_parity.rs"]
mod policy_parity;
#[path = "windows_contract/private_creator.rs"]
mod private_creator;
#[path = "windows_contract/registry_descendant.rs"]
mod registry_descendant;
#[path = "windows_contract/registry_loader.rs"]
mod registry_loader;
#[path = "windows_contract/resource_threads.rs"]
mod resource_threads;
#[path = "windows_contract/runtime_preparation.rs"]
mod runtime_preparation;
#[path = "windows_contract/scratch_attachment.rs"]
mod scratch_attachment;
#[path = "windows_contract/sxs_native.rs"]
mod sxs_native;
#[path = "windows_contract/sxs_parity.rs"]
mod sxs_parity;
#[path = "windows_contract/sxs_recovery.rs"]
mod sxs_recovery;
#[path = "windows_contract/sxs_storage.rs"]
mod sxs_storage;
#[path = "windows_contract/token.rs"]
mod token;
