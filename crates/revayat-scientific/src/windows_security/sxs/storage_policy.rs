//! Exact original first predicate and four-rule private storage policy.
use crate::windows_security::policy::{Acl, Descriptor};
use anyhow::{Result, ensure};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Predicate {
    Owner,
    Rules,
    Canonical,
    Protected,
    Propagation,
    Inherited,
    Inheritance,
    Package,
    OwnerRights,
    Allow,
    Distinct,
}
impl Predicate {
    pub fn label(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Rules => "rules",
            Self::Canonical => "canonical",
            Self::Protected => "protected",
            Self::Propagation => "propagation",
            Self::Inherited => "inherited",
            Self::Inheritance => "inheritance",
            Self::Package => "package",
            Self::OwnerRights => "owner-rights",
            Self::Allow => "allow",
            Self::Distinct => "distinct",
        }
    }
}
impl TryFrom<i32> for Predicate {
    type Error = anyhow::Error;
    fn try_from(value: i32) -> Result<Self> {
        Ok(match value {
            0 => Self::Owner,
            1 => Self::Rules,
            2 => Self::Canonical,
            3 => Self::Protected,
            4 => Self::Propagation,
            5 => Self::Inherited,
            6 => Self::Inheritance,
            7 => Self::Package,
            8 => Self::OwnerRights,
            9 => Self::Allow,
            10 => Self::Distinct,
            _ => anyhow::bail!("unsupported fixed SxS policy predicate"),
        })
    }
}
#[derive(Debug)]
pub struct PolicyFailure {
    pub predicate: Predicate,
}
impl std::fmt::Display for PolicyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fixed SxS storage policy rejected predicate={}",
            self.predicate.label()
        )
    }
}
impl std::error::Error for PolicyFailure {}
pub fn need(value: bool, predicate: Predicate) -> Result<()> {
    if !value {
        return Err(PolicyFailure { predicate }.into());
    }
    Ok(())
}
pub fn require(bytes: &[u8], directory: bool, owner: &[u8], package: &[u8]) -> Result<()> {
    let descriptor = Descriptor::parse(bytes)?;
    need(descriptor.owner == Some(owner), Predicate::Owner)?;
    // A retained DACL offset is not authority when SE_DACL_PRESENT is clear.
    need(descriptor.control & 4 != 0, Predicate::Rules)?;
    let acl = descriptor
        .dacl
        .ok_or_else(|| {
            anyhow::Error::from(PolicyFailure {
                predicate: Predicate::Rules,
            })
        })
        .and_then(Acl::parse)?;
    need(acl.aces.len() == 4, Predicate::Rules)?;
    let mut phase = 0;
    let mut canonical = true;
    for ace in &acl.aces {
        let current = if ace.flags & 16 != 0 {
            2
        } else if ace.kind == 1 {
            0
        } else {
            1
        };
        canonical &= matches!(ace.kind, 0 | 1) && current >= phase;
        phase = current;
    }
    need(canonical, Predicate::Canonical)?;
    need(
        !directory || descriptor.control & 0x1000 != 0,
        Predicate::Protected,
    )?;
    let owner_rights = [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
    let system = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let mut identities = std::collections::BTreeSet::new();
    for ace in &acl.aces {
        let sid = ace.sid()?;
        need(ace.flags & 12 == 0, Predicate::Propagation)?;
        need((ace.flags & 16 != 0) != directory, Predicate::Inherited)?;
        need(
            ace.flags & !0x1f == 0 && ace.flags & 3 == if directory { 3 } else { 0 },
            Predicate::Inheritance,
        )?;
        if sid == package {
            need(ace.kind == 1 && ace.mask()? == 0x1f01ff, Predicate::Package)?;
        } else if sid == owner_rights {
            need(
                ace.kind == 1 && ace.mask()? == 0xc0000,
                Predicate::OwnerRights,
            )?;
        } else {
            need(
                (sid == owner || sid == system) && ace.kind == 0 && ace.mask()? == 0x1f01ff,
                Predicate::Allow,
            )?;
        }
        identities.insert(sid);
    }
    need(identities.len() == 4, Predicate::Distinct)
}
pub fn create_sealed<T>(
    bytes: &mut [u8],
    owner: &[u8],
    package: &[u8],
    create: impl FnOnce(&mut [u8]) -> Result<T>,
) -> Result<T> {
    require(bytes, true, owner, package)?;
    create(bytes)
}
pub(crate) fn sid(authority: u8, parts: &[u32]) -> Vec<u8> {
    let mut value = vec![1, parts.len() as u8, 0, 0, 0, 0, 0, authority];
    for part in parts {
        value.extend(part.to_le_bytes());
    }
    value
}
pub(crate) fn fixture(directory: bool, corruption: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let owner = sid(5, &[21, 1, 2, 3, 1001]);
    let package = sid(15, &[2, 1, 2, 3, 4, 5, 6, 7]);
    let flags = if directory { 3 } else { 16 };
    let rows = [
        (1, 0x1f01ff, package.clone()),
        (1, 0xc0000, sid(3, &[4])),
        (0, 0x1f01ff, owner.clone()),
        (0, 0x1f01ff, sid(5, &[18])),
    ];
    let mut acl = vec![2, 0, 0, 0, 0, 0, 0, 0];
    let mut count = 0u16;
    for (index, (kind, mask, identity)) in rows.into_iter().enumerate() {
        if matches!(corruption, 3 | 5) && index == 1 {
            continue;
        }
        count += 1;
        acl.extend([
            kind,
            flags | if corruption == 4 && index == 1 { 16 } else { 0 },
        ]);
        acl.extend(((8 + identity.len()) as u16).to_le_bytes());
        acl.extend((mask as u32).to_le_bytes());
        acl.extend(identity);
    }
    if corruption == 5 {
        let identity = sid(3, &[4]);
        count += 1;
        acl.extend([1, flags | 16]);
        acl.extend(((8 + identity.len()) as u16).to_le_bytes());
        acl.extend(0xc0000u32.to_le_bytes());
        acl.extend(identity);
    }
    let length = acl.len() as u16;
    acl[2..4].copy_from_slice(&length.to_le_bytes());
    acl[4..6].copy_from_slice(&count.to_le_bytes());
    let actual_owner = if corruption == 1 {
        sid(5, &[18])
    } else {
        owner.clone()
    };
    let mut bytes = vec![
        1,
        0,
        4,
        if directory && corruption != 2 {
            0x90
        } else {
            0x80
        },
    ];
    for offset in [
        20,
        20 + actual_owner.len(),
        0,
        20 + actual_owner.len() + owner.len(),
    ] {
        bytes.extend((offset as u32).to_le_bytes());
    }
    bytes.extend(actual_owner);
    bytes.extend(&owner);
    bytes.extend(acl);
    (bytes, owner, package)
}
pub fn check_validation() -> Result<()> {
    let (mut policy, owner, package) = fixture(true, 0);
    let mut calls = 0;
    create_sealed(&mut policy, &owner, &package, |_| {
        calls += 1;
        Ok(())
    })?;
    ensure!(calls == 1, "valid sealed policy suppressed creation");
    for corruption in 1..=4 {
        let (mut bad, _, _) = fixture(true, corruption);
        ensure!(
            create_sealed(&mut bad, &owner, &package, |_| {
                calls += 1;
                Ok(())
            })
            .is_err()
                && calls == 1,
            "invalid sealed policy reached native creation"
        );
    }
    require(&fixture(false, 0).0, false, &owner, &package)?;
    ensure!(
        require(&fixture(false, 1).0, false, &owner, &package).is_err(),
        "file owner drift accepted"
    );
    for (corruption, first) in [
        (1, Predicate::Owner),
        (2, Predicate::Protected),
        (3, Predicate::Rules),
        (4, Predicate::Canonical),
        (5, Predicate::Inherited),
    ] {
        let error = require(&fixture(true, corruption).0, true, &owner, &package).unwrap_err();
        ensure!(
            error
                .downcast_ref::<PolicyFailure>()
                .is_some_and(|error| error.predicate == first)
                && error.to_string()
                    == format!(
                        "fixed SxS storage policy rejected predicate={}",
                        first.label()
                    ),
            "storage first predicate differs"
        );
    }
    for value in 0..11 {
        let predicate = Predicate::try_from(value)?;
        need(true, predicate)?;
        ensure!(
            need(false, predicate)
                .unwrap_err()
                .downcast_ref::<PolicyFailure>()
                .is_some_and(|error| error.predicate == predicate),
            "policy predicate kind changed"
        );
    }
    Ok(())
}
