//! Original Profile/RegistrySeal portable validators, calling the production binary policies.
use super::{
    REGISTRY_DENY, REGISTRY_READ, access_matches, allow_ace, encode_acl,
    require_registry_preserved, serialized_acl_equal, validate_registry_seal,
};
use anyhow::{Result, ensure};

#[path = "registry_context.rs"]
pub mod registry_context;

pub(super) fn sid(authority: u8, parts: &[u32]) -> Vec<u8> {
    let mut bytes = vec![1, parts.len() as u8, 0, 0, 0, 0, 0, authority];
    for value in parts {
        bytes.extend(value.to_le_bytes());
    }
    bytes
}
pub(super) fn ace(kind: u8, flags: u8, mask: u32, identity: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = allow_ace(identity, mask)?;
    bytes[0] = kind;
    bytes[1] = flags;
    Ok(bytes)
}
fn descriptor(
    dacl: Option<&[u8]>,
    owner: Option<&[u8]>,
    group: Option<&[u8]>,
    sacl: Option<&[u8]>,
    control: u16,
) -> Vec<u8> {
    let mut bytes = vec![1, 0];
    bytes.extend(control.to_le_bytes());
    bytes.resize(20, 0);
    for (offset, component) in [(4, owner), (8, group), (12, sacl), (16, dacl)] {
        if let Some(value) = component {
            let at = bytes.len() as u32;
            bytes[offset..offset + 4].copy_from_slice(&at.to_le_bytes());
            bytes.extend(value);
        }
    }
    bytes
}

fn padded(acl: &[u8]) -> Vec<u8> {
    let mut bytes = acl.to_vec();
    bytes.extend([0xde, 0xad, 0xbe, 0xef]);
    let length = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&length.to_le_bytes());
    bytes
}

/// Complete Profile.CheckSealComparison: ignore only DACL auto-inherited bookkeeping.
pub fn check_seal_comparison() -> Result<()> {
    let owner = sid(3, &[4]);
    let world = sid(1, &[0]);
    let system = sid(5, &[18]);
    let entries = [ace(1, 0, 0xc0000, &owner)?, ace(0, 0, 0x120089, &world)?];
    let dacl = encode_acl(2, &entries)?;
    let expected = descriptor(Some(&dacl), None, None, None, 0x9004);
    let mut bookkeeping = expected.clone();
    bookkeeping[3] |= 4;
    ensure!(
        access_matches(&expected, &bookkeeping)?,
        "DACL bookkeeping check failed"
    );
    // RawAcl.GetBinaryForm drops unused final ACL allocation, not any ordered ACE bytes.
    // https://github.com/dotnet/runtime/blob/50a0c6423336dfa9f887e9aac74686070cfe6775/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/ACL.cs#L309
    let padding = padded(&dacl);
    ensure!(
        access_matches(
            &expected,
            &descriptor(Some(&padding), None, None, None, 0x9004)
        )?,
        "DACL unused allocation padding changed serialization"
    );
    let mut revision = dacl.clone();
    revision[0] = 4;
    ensure!(
        !access_matches(
            &expected,
            &descriptor(Some(&revision), None, None, None, 0x9004)
        )?,
        "DACL revision difference accepted"
    );
    let empty = encode_acl(2, &[])?;
    ensure!(
        serialized_acl_equal(None, None)?
            && !serialized_acl_equal(None, Some(&empty))?
            && serialized_acl_equal(Some(&empty), Some(&padded(&empty)))?
            && !access_matches(&expected, &descriptor(None, None, None, None, 0x9004))?,
        "null/empty ACL distinction or padding changed"
    );
    for flag in [0x1000u16, 4, 0x100, 0x800] {
        let mut changed = expected.clone();
        changed[2..4].copy_from_slice(&(0x9004 ^ flag).to_le_bytes());
        ensure!(
            !access_matches(&expected, &changed)?,
            "DACL control difference accepted"
        );
    }
    let variants = [
        vec![entries[1].clone()],
        vec![ace(1, 0, 0x40000, &owner)?, entries[1].clone()],
        vec![ace(1, 0, 0xc0000, &system)?, entries[1].clone()],
        vec![ace(1, 1, 0xc0000, &owner)?, entries[1].clone()],
        vec![entries[1].clone(), entries[0].clone()],
        vec![entries[0].clone(), ace(0, 0, 0x1f01ff, &world)?],
    ];
    for entries in variants {
        let dacl = encode_acl(2, &entries)?;
        ensure!(
            !access_matches(
                &expected,
                &descriptor(Some(&dacl), None, None, None, 0x9004)
            )?,
            "DACL ordered bytes difference accepted"
        );
    }
    Ok(())
}

/// RegistrySeal.CheckValidation: all serialized shape, source-byte and identity-label cases.
pub fn check_registry_seal_validation() -> Result<()> {
    let entries = [
        sid(5, &[18]),
        sid(5, &[32, 544]),
        sid(5, &[32, 545]),
        sid(1, &[0]),
        sid(5, &[12]),
        sid(15, &[2, 1]),
    ]
    .iter()
    .map(|identity| ace(0, 2, REGISTRY_READ, identity))
    .collect::<Result<Vec<_>>>()?;
    let dacl = encode_acl(2, &entries)?;
    let valid = descriptor(Some(&dacl), None, None, None, 0x9004);
    let original = valid.clone();
    validate_registry_seal(&valid)?;
    ensure!(
        valid == original,
        "registry validation altered source bytes"
    );
    let mut reordered = entries.clone();
    reordered[5] = ace(1, 2, 2, &sid(15, &[2, 1]))?;
    ensure!(
        validate_registry_seal(&descriptor(
            Some(&encode_acl(2, &reordered)?),
            None,
            None,
            None,
            0x9004
        ))
        .is_err(),
        "noncanonical registry DACL accepted"
    );
    let system = sid(5, &[18]);
    let admin = sid(5, &[32, 544]);
    let label = encode_acl(2, &[ace(17, 0, 1, &sid(16, &[4096]))?])?;
    let empty = encode_acl(2, &[])?;
    let mut invalid = vec![
        descriptor(Some(&dacl), None, None, None, 0x8004),
        descriptor(Some(&dacl), None, None, None, 0x9000),
        descriptor(None, None, None, None, 0x9004),
        descriptor(Some(&empty), None, None, None, 0x9004),
        descriptor(Some(&dacl), Some(&system), None, None, 0x9004),
        descriptor(Some(&dacl), None, Some(&admin), None, 0x9004),
        descriptor(Some(&dacl), None, None, Some(&label), 0x9014),
    ];
    ensure!(
        u16::from_le_bytes(invalid[6][2..4].try_into()?) & 0x10 != 0
            && u32::from_le_bytes(invalid[6][12..16].try_into()?) != 0,
        "registry SACL negative fixture was not serialized as intended"
    );
    for flags in [2 | 16, 2 | 8] {
        let mut changed = entries.clone();
        changed[0][1] = flags;
        invalid.push(descriptor(
            Some(&encode_acl(2, &changed)?),
            None,
            None,
            None,
            0x9004,
        ));
    }
    let mut callback = entries.clone();
    callback[0] = ace(9, 2, REGISTRY_READ, &system)?;
    callback[0].extend([0; 4]);
    let length = callback[0].len() as u16;
    callback[0][2..4].copy_from_slice(&length.to_le_bytes());
    invalid.push(descriptor(
        Some(&encode_acl(2, &callback)?),
        None,
        None,
        None,
        0x9004,
    ));
    for flag in [4u16, 0x1000] {
        let mut raw = valid.clone();
        raw[2..4].copy_from_slice(&(0x9004 & !flag).to_le_bytes());
        invalid.push(raw);
    }
    for (index, bytes) in invalid.iter().enumerate() {
        ensure!(
            validate_registry_seal(bytes).is_err(),
            "malformed registry seal descriptor accepted fixture={index}"
        );
    }
    let package = sid(15, &[2, 3]);
    let user = sid(5, &[21, 1, 2, 3, 500]);
    let mut policy = vec![
        ace(1, 2, 0xc0000, &sid(3, &[4]))?,
        ace(1, 2, 0xc0000, &package)?,
    ];
    for identity in [&package, &user, &system, &admin] {
        policy.push(ace(0, 2, REGISTRY_READ, identity)?);
    }
    validate_registry_seal(&descriptor(
        Some(&encode_acl(2, &policy)?),
        None,
        None,
        None,
        0x9004,
    ))?;
    for bytes in [
        descriptor(Some(&empty), None, None, None, 0x8004),
        descriptor(None, None, None, None, 0x9004),
        descriptor(
            Some(&encode_acl(2, &[ace(0, 2, REGISTRY_READ, &system)?])?),
            None,
            None,
            None,
            0x8004,
        ),
        descriptor(
            Some(&encode_acl(2, &[ace(0, 2, REGISTRY_READ, &system)?])?),
            Some(&system),
            None,
            None,
            0x9004,
        ),
    ] {
        ensure!(
            validate_registry_seal(&bytes).is_err(),
            "malformed registry seal descriptor accepted"
        );
    }
    let access = encode_acl(2, &[ace(0, 0, REGISTRY_READ, &system)?])?;
    let before = descriptor(
        Some(&access),
        Some(&system),
        Some(&admin),
        Some(&label),
        0x9014,
    );
    require_registry_preserved(&before, &before)?;
    require_registry_preserved(
        &before,
        &descriptor(
            Some(&access),
            Some(&system),
            Some(&admin),
            Some(&padded(&label)),
            0x9014,
        ),
    )?;
    let mut different_revision = label.clone();
    different_revision[0] = 4;
    ensure!(
        require_registry_preserved(
            &before,
            &descriptor(
                Some(&access),
                Some(&system),
                Some(&admin),
                Some(&different_revision),
                0x9014
            )
        )
        .is_err(),
        "registry integrity ACL revision difference accepted"
    );
    let null_label = descriptor(Some(&access), Some(&system), Some(&admin), None, 0x9014);
    let empty_label = descriptor(
        Some(&access),
        Some(&system),
        Some(&admin),
        Some(&empty),
        0x9014,
    );
    ensure!(
        require_registry_preserved(&null_label, &empty_label).is_err(),
        "registry null and empty integrity ACLs conflated"
    );
    let medium = encode_acl(2, &[ace(17, 0, 1, &sid(16, &[8192]))?])?;
    for changed in [
        descriptor(
            Some(&access),
            Some(&admin),
            Some(&admin),
            Some(&label),
            0x9014,
        ),
        descriptor(
            Some(&access),
            Some(&system),
            Some(&system),
            Some(&label),
            0x9014,
        ),
        descriptor(
            Some(&access),
            Some(&system),
            Some(&admin),
            Some(&medium),
            0x9014,
        ),
    ] {
        ensure!(
            require_registry_preserved(&before, &changed).is_err(),
            "registry identity/label mutation accepted"
        );
    }
    Ok(())
}

/// Complete Profile.CheckRegistryMasks, including both reachable helper validators.
pub fn check_registry_masks() -> Result<()> {
    registry_context::check_validation()?;
    check_registry_seal_validation()?;
    let write = 0x20006u32;
    let legacy_allow = REGISTRY_READ & !0x20000;
    ensure!(
        write & REGISTRY_READ == 0x20000
            && REGISTRY_DENY & REGISTRY_READ == 0
            && legacy_allow == 0x19
            && legacy_allow & 0x20000 == 0,
        "registry read-only mask must preserve READ_CONTROL"
    );
    for right in [2u32, 4, 0x10000, 0x40000, 0x80000] {
        ensure!(
            REGISTRY_DENY & right == right,
            "registry read-only mask omitted mutation/authority deny"
        );
    }
    ensure!(
        REGISTRY_DENY & (1 | 8 | 16) == 0,
        "registry read-only mask denies advertised read operations"
    );
    Ok(())
}
