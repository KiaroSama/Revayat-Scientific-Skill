//! Exact profile-registry six-rule DACLs; no owner/group/integrity mutation or setter fallback.
use super::*;
use crate::windows_security::policy::{
    Acl, Descriptor as RelativeDescriptor, validate_registry_seal,
};
#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetSecurityDescriptorLength(descriptor: Handle) -> u32;
    fn GetSecurityInfo(
        key: Handle,
        kind: i32,
        information: u32,
        owner: *mut Handle,
        group: *mut Handle,
        dacl: *mut Handle,
        sacl: *mut Handle,
        descriptor: *mut Handle,
    ) -> u32;
    fn RegSetKeySecurity(key: Handle, information: u32, descriptor: Handle) -> i32;
}
fn sid_key(text: &str) -> Result<(u64, usize, Vec<i32>)> {
    let fields = text.split('-').collect::<Vec<_>>();
    ensure!(
        fields.len() >= 4 && fields[..2] == ["S", "1"],
        "invalid profile policy SID"
    );
    let authority = fields[2]
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid profile policy SID"))?;
    let parts = fields[3..]
        .iter()
        .map(|part| {
            part.parse::<u32>()
                .map_err(|_| anyhow::anyhow!("invalid profile policy SID"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        authority <= 0xffffffffffff
            && parts.len() <= 15
            && fields[2..].iter().all(|part| !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))),
        "noncanonical profile policy SID"
    );
    Ok((
        authority,
        parts.len(),
        parts.into_iter().map(|part| part as i32).collect(),
    ))
}
pub(super) fn sddl(user: &str, package: &str, read_only: bool) -> Result<String> {
    crate::windows_security::package_sid(package)?;
    sid_key(user)?;
    ensure!(
        !["S-1-3-4", "S-1-5-18", "S-1-5-32-544", package].contains(&user),
        "profile policy requires six distinct identities"
    );
    let mut allowed = vec!["S-1-5-18", "S-1-5-32-544", user, package];
    // Match CommonAcl's explicit allow ordering: identifier authority, count, subauthorities.
    allowed.sort_by_key(|sid| sid_key(sid).expect("validated fixed policy SID"));
    let mut result = format!(
        "D:P(D;CI;0x000C0000;;;S-1-3-4)(D;CI;0x{:08X};;;{package})",
        if read_only { 0xd0006 } else { 0xe0006 }
    );
    for sid in allowed {
        use std::fmt::Write;
        write!(
            &mut result,
            "(A;CI;0x{:08X};;;{sid})",
            if sid == package {
                if read_only { 0x20019 } else { 0x19 }
            } else {
                0xf003f
            }
        )?;
    }
    Ok(result)
}
pub(super) fn bytes(descriptor: &Descriptor) -> Result<Vec<u8>> {
    let length = unsafe { GetSecurityDescriptorLength(descriptor.0) };
    ensure!(
        (20..=65536).contains(&length),
        "profile registry descriptor exceeds bound"
    );
    Ok(unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), length as usize) }.to_vec())
}
pub(super) fn matches_access(expected: &[u8], actual: &[u8]) -> Result<bool> {
    let (expected, actual) = (
        RelativeDescriptor::parse(expected)?,
        RelativeDescriptor::parse(actual)?,
    );
    if expected.control & !0x400 != actual.control & !0x400
        || expected.control & 0x1000 == 0
        || actual.control & 0x1000 == 0
    {
        return Ok(false);
    }
    let (Some(expected), Some(actual)) = (expected.dacl, actual.dacl) else {
        return Ok(false);
    };
    let (expected, actual) = (Acl::parse(expected)?, Acl::parse(actual)?);
    Ok(expected.revision == actual.revision
        && expected.aces.len() == actual.aces.len()
        && expected
            .aces
            .iter()
            .zip(actual.aces.iter())
            .all(|(a, b)| a.bytes == b.bytes))
}
fn read_access(key: Handle) -> Result<Vec<u8>> {
    let (mut owner, mut group, mut dacl, mut sacl, mut descriptor) =
        (null_mut(), null_mut(), null_mut(), null_mut(), null_mut());
    let status = unsafe {
        GetSecurityInfo(
            key,
            4,
            4,
            &mut owner,
            &mut group,
            &mut dacl,
            &mut sacl,
            &mut descriptor,
        )
    };
    let result = (|| {
        ensure!(
            status == 0 && !descriptor.is_null() && !dacl.is_null(),
            "profile registry access readback failed winerror={status}"
        );
        let length = unsafe { GetSecurityDescriptorLength(descriptor) };
        ensure!(
            (20..=65536).contains(&length),
            "profile registry access descriptor exceeds bound"
        );
        Ok(
            unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), length as usize) }
                .to_vec(),
        )
    })();
    let cleanup = if descriptor.is_null() || unsafe { LocalFree(descriptor) }.is_null() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "profile registry readback allocation cleanup failed"
        ))
    };
    combine(result, cleanup)
}
pub(super) fn apply(key: Handle, user: &str, package: &str, read_only: bool) -> Result<()> {
    let mut expected = Descriptor::new(&sddl(user, package, read_only)?)?;
    let mut source = bytes(&expected)?;
    let result = (|| {
        validate_registry_seal(&source)?;
        let mut before = super::super::super::fixture::registry_identity(key)?;
        let status = unsafe { RegSetKeySecurity(key, 0x80000004, expected.0) };
        let persisted = if status == 0 {
            super::super::super::fixture::registry_preserved(&before, key)
        } else {
            Err(anyhow::anyhow!(
                "persist protected profile registry DACL failed winerror={status}"
            ))
        };
        before.fill(0);
        persisted?;
        let mut actual = read_access(key)?;
        let compared = matches_access(&source, &actual);
        actual.fill(0);
        ensure!(compared?, "owned profile registry seal readback differs");
        Ok(())
    })();
    source.fill(0);
    combine(result, expected.close())
}
