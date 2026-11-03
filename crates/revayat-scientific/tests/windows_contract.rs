//! Portable adversarial tests for the native Windows controller contracts.
//! These do not attest a kernel sandbox. windows_native is a separate CI gate.
use registry_authority::protocol as authority;
use revayat_scientific::windows_security::*;
use std::path::Path;
#[cfg(windows)]
#[path = "support/windows_junction.rs"]
mod windows_junction;

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

#[path = "windows_contract/bootstrap.rs"]
mod bootstrap;
#[path = "windows_contract/kernel_descendants.rs"]
mod kernel_descendants;
#[path = "windows_contract/private_creator.rs"]
mod private_creator;
#[path = "windows_contract/registry_descendant.rs"]
mod registry_descendant;
#[path = "windows_contract/registry_loader.rs"]
mod registry_loader;
#[path = "windows_contract/runtime_preparation.rs"]
mod runtime_preparation;
#[path = "windows_contract/scratch_attachment.rs"]
mod scratch_attachment;
#[path = "windows_contract/token.rs"]
mod token;
