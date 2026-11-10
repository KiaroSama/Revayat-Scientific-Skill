//! Exact private SxS storage predicates and fixed synchronous creation result.
use crate::windows_security::policy::{Acl, Descriptor};
use anyhow::{Result, ensure};

/// Four rules only: concrete package deny, OWNER RIGHTS deny, actual user allow, SYSTEM allow.
pub fn require_policy(bytes: &[u8], directory: bool, owner: &[u8], package: &[u8]) -> Result<()> {
    let descriptor = Descriptor::parse(bytes)?;
    ensure!(
        descriptor.owner == Some(owner),
        "fixed SxS storage policy rejected predicate=owner"
    );
    ensure!(
        descriptor.control & 4 != 0,
        "fixed SxS storage policy rejected predicate=rules"
    );
    let acl = Acl::parse(
        descriptor
            .dacl
            .ok_or_else(|| anyhow::anyhow!("fixed SxS storage DACL absent"))?,
    )?;
    ensure!(
        acl.aces.len() == 4,
        "fixed SxS storage policy rejected predicate=rules"
    );
    ensure!(
        !directory || descriptor.control & 0x1000 != 0,
        "fixed SxS storage policy rejected predicate=protected"
    );
    let owner_rights = [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
    let system = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    ensure!(
        owner != package
            && owner != system
            && owner != owner_rights
            && package != system
            && package != owner_rights,
        "fixed SxS storage policy rejected predicate=distinct"
    );
    let expected = [
        (package, 1, 0x1f01ff),
        (&owner_rights[..], 1, 0xc0000),
        (owner, 0, 0x1f01ff),
        (&system[..], 0, 0x1f01ff),
    ];
    let mut seen = [false; 4];
    let mut allow = false;
    for ace in &acl.aces {
        ensure!(
            matches!(ace.kind, 0 | 1) && !(allow && ace.kind == 1),
            "fixed SxS storage policy rejected predicate=canonical"
        );
        allow |= ace.kind == 0;
        ensure!(
            ace.flags == if directory { 3 } else { 16 },
            "fixed SxS storage policy rejected predicate=inheritance"
        );
        let index = expected
            .iter()
            .position(|(sid, _, _)| ace.sid().is_ok_and(|actual| actual == *sid))
            .ok_or_else(|| {
                anyhow::anyhow!("fixed SxS storage policy rejected predicate=distinct")
            })?;
        ensure!(
            !seen[index] && ace.kind == expected[index].1 && ace.mask()? == expected[index].2,
            "fixed SxS storage policy rejected predicate=rules"
        );
        seen[index] = true;
    }
    ensure!(
        seen.iter().all(|value| *value),
        "fixed SxS storage policy rejected predicate=distinct"
    );
    Ok(())
}
/// No drive aliases, alternate mappings, system volume or arbitrary path components are accepted.
pub fn native_path(folder: &str, mapping: &[u16]) -> Result<String> {
    let bytes = folder.as_bytes();
    ensure!(
        bytes.len() == 45
            && (b'D'..=b'Z').contains(&bytes[0])
            && &bytes[1..13] == b":\\sxs-trace-"
            && bytes[13..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
        "invalid fixed SxS storage folder"
    );
    ensure!(
        (3..=512).contains(&mapping.len())
            && mapping.ends_with(&[0, 0])
            && !mapping[..mapping.len() - 2].contains(&0),
        "invalid fixed SxS device mapping"
    );
    let device = String::from_utf16(&mapping[..mapping.len() - 2])?;
    let suffix = device
        .strip_prefix("\\Device\\HarddiskVolume")
        .ok_or_else(|| anyhow::anyhow!("unsupported fixed SxS device family"))?;
    ensure!(
        !suffix.is_empty() && suffix.len() <= 20 && suffix.bytes().all(|b| b.is_ascii_digit()),
        "invalid fixed SxS device identity"
    );
    let path = format!("{device}\\{}", &folder[3..]);
    ensure!(
        path.encode_utf16().count() * 2 <= 512,
        "fixed SxS native path exceeds bound"
    );
    Ok(path)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    Created,
    Pending,
}
pub fn creation_completion(
    returned: i32,
    completed: i32,
    information: u64,
    handle: usize,
) -> Result<Completion> {
    if returned == 0x103 || completed == 0x103 {
        return Ok(Completion::Pending);
    }
    ensure!(
        returned == 0,
        "fixed SxS native creation failed ntstatus={:08X}",
        returned as u32
    );
    ensure!(
        completed == 0 && information == 2 && handle != 0 && handle != usize::MAX,
        "fixed SxS native creation output differs"
    );
    Ok(Completion::Created)
}
