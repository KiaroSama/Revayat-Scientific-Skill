//! Original six-rule filesystem policy. Only this owned object's protected DACL is changed.
use super::*;
use crate::windows_security::policy::{Acl, Descriptor as Relative};
#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetSecurityDescriptorLength(descriptor: Handle) -> u32;
    fn IsValidSecurityDescriptor(descriptor: Handle) -> i32;
    fn GetSecurityDescriptorDacl(
        descriptor: Handle,
        present: *mut i32,
        dacl: *mut Handle,
        defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityInfo(
        object: Handle,
        kind: i32,
        information: u32,
        owner: *mut Handle,
        group: *mut Handle,
        dacl: *mut Handle,
        sacl: *mut Handle,
        descriptor: *mut Handle,
    ) -> u32;
    fn SetSecurityInfo(
        object: Handle,
        kind: i32,
        information: u32,
        owner: Handle,
        group: Handle,
        dacl: Handle,
        sacl: Handle,
    ) -> u32;
}
fn sid_key(text: &str) -> Result<(u64, usize, Vec<i32>)> {
    let fields = text.split('-').collect::<Vec<_>>();
    ensure!(
        fields.len() >= 4 && fields[..2] == ["S", "1"],
        "invalid filesystem policy SID"
    );
    let authority = fields[2].parse::<u64>()?;
    let parts = fields[3..]
        .iter()
        .map(|part| part.parse::<u32>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        authority <= 0xffffffffffff
            && parts.len() <= 15
            && fields[2..].iter().all(|part| !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))),
        "noncanonical filesystem policy SID"
    );
    Ok((
        authority,
        parts.len(),
        parts.into_iter().map(|part| part as i32).collect(),
    ))
}
pub(super) fn sddl(user: &str, package: &str, directory: bool) -> Result<String> {
    crate::windows_security::package_sid(package)?;
    sid_key(user)?;
    ensure!(
        !["S-1-3-4", "S-1-5-18", "S-1-5-32-544", package].contains(&user),
        "filesystem seal requires six distinct identities"
    );
    let flags = if directory { "OICI" } else { "" };
    let mut allowed = vec!["S-1-5-18", "S-1-5-32-544", user, package];
    // Match Framework CommonAcl SID ordering, including signed subauthorities.
    allowed.sort_by_key(|sid| sid_key(sid).expect("validated filesystem policy SID"));
    let mut result =
        format!("D:P(D;{flags};0x000C0000;;;S-1-3-4)(D;{flags};0x000D0116;;;{package})");
    for sid in allowed {
        use std::fmt::Write;
        // FileSystemAccessRule adds SYNCHRONIZE to allows, but not these denies.
        write!(
            &mut result,
            "(A;{flags};0x{:08X};;;{sid})",
            if sid == package { 0x1200a9 } else { 0x1f01ff }
        )?;
    }
    Ok(result)
}
fn raw_bytes(raw: Handle) -> Result<Vec<u8>> {
    ensure!(
        !raw.is_null() && unsafe { IsValidSecurityDescriptor(raw) } != 0,
        "filesystem descriptor is invalid"
    );
    let length = unsafe { GetSecurityDescriptorLength(raw) };
    ensure!(
        (20..=65536).contains(&length),
        "filesystem descriptor exceeds bound"
    );
    Ok(unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), length as usize) }.to_vec())
}
pub(super) fn bytes(descriptor: &Descriptor) -> Result<Vec<u8>> {
    raw_bytes(descriptor.0)
}
pub(super) fn matches_access(expected: &[u8], actual: &[u8]) -> Result<bool> {
    let (left, right) = (Relative::parse(expected)?, Relative::parse(actual)?);
    if left.control & !0x400 != right.control & !0x400
        || left.control & 0x1000 == 0
        || right.control & 0x1000 == 0
    {
        return Ok(false);
    }
    let (Some(left), Some(right)) = (left.dacl, right.dacl) else {
        return Ok(false);
    };
    let (left, right) = (Acl::parse(left)?, Acl::parse(right)?);
    // RawAcl serialization omits unused final allocation padding. The shared byte comparator does not.
    Ok(left.revision == right.revision
        && left.aces.len() == right.aces.len()
        && left
            .aces
            .iter()
            .zip(&right.aces)
            .all(|(a, b)| a.bytes == b.bytes))
}
fn read(object: Handle, information: u32) -> Result<Vec<u8>> {
    let (mut owner, mut group, mut dacl, mut sacl, mut raw) =
        (null_mut(), null_mut(), null_mut(), null_mut(), null_mut());
    let status = unsafe {
        GetSecurityInfo(
            object,
            1,
            information,
            &mut owner,
            &mut group,
            &mut dacl,
            &mut sacl,
            &mut raw,
        )
    };
    let result = (|| {
        ensure!(
            status == 0 && !raw.is_null() && !dacl.is_null(),
            "owned profile filesystem readback failed winerror={status}"
        );
        raw_bytes(raw)
    })();
    let cleanup = if raw.is_null() || unsafe { LocalFree(raw) }.is_null() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "filesystem readback allocation cleanup failed"
        ))
    };
    combine(result, cleanup)
}
pub(super) fn apply(object: Handle, user: &str, package: &str, directory: bool) -> Result<()> {
    let mut expected = Descriptor::new(&sddl(user, package, directory)?)?;
    let mut source = bytes(&expected)?;
    let result = (|| {
        let parsed = Relative::parse(&source)?;
        let acl = Acl::parse(
            parsed
                .dacl
                .ok_or_else(|| anyhow::anyhow!("filesystem seal DACL absent"))?,
        )?;
        ensure!(
            parsed.control & 0x9004 == 0x9004
                && parsed.owner.is_none()
                && parsed.group.is_none()
                && parsed.sacl.is_none()
                && acl.aces.len() == 6
                && acl
                    .aces
                    .iter()
                    .enumerate()
                    .all(|(index, ace)| ace.kind == if index < 2 { 1 } else { 0 }
                        && ace.flags == if directory { 3 } else { 0 }),
            "filesystem seal is not the exact protected six-rule form"
        );
        let mut before = read(object, 0x17)?; // owner, group, DACL and integrity label, without SeSecurityPrivilege.
        let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut());
        ensure!(
            unsafe {
                GetSecurityDescriptorDacl(expected.0, &mut present, &mut dacl, &mut defaulted)
            } != 0
                && present != 0
                && !dacl.is_null()
                && defaulted == 0,
            "filesystem seal DACL extraction failed"
        );
        let status = unsafe {
            SetSecurityInfo(
                object,
                1,
                0x80000004,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        let persisted = (|| {
            ensure!(
                status == 0,
                "persist protected filesystem seal failed winerror={status}"
            );
            let mut after = read(object, 0x17)?;
            let preserved =
                crate::windows_security::policy::require_registry_preserved(&before, &after);
            after.fill(0);
            preserved.map_err(|_| {
                anyhow::anyhow!(
                    "filesystem seal changed owner/group/integrity or unrelated control"
                )
            })?;
            let mut actual = read(object, 4)?;
            let matches = matches_access(&source, &actual);
            actual.fill(0);
            ensure!(matches?, "owned profile filesystem seal readback differs");
            Ok(())
        })();
        before.fill(0);
        persisted
    })();
    source.fill(0);
    combine(result, expected.close())
}
