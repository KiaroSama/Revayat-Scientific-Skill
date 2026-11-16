//! Retained-key owner/group/MIC readback. Never requests audit-SACL privilege or changes rights.
use super::*;
use crate::windows_security::policy::{
    Descriptor as RelativeDescriptor, require_registry_preserved,
};
#[link(name = "advapi32")]
unsafe extern "system" {
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
    fn IsValidSecurityDescriptor(descriptor: Handle) -> i32;
    fn GetSecurityDescriptorLength(descriptor: Handle) -> u32;
}
fn rights(key: Handle) -> Result<()> {
    ensure!(
        !key.is_null()
            && key as isize > 0
            && !((0x80000000..=0x800000ff).contains(&(key as usize))),
        "registry policy requires one retained non-predefined key"
    );
    let mut data = [0u64; 7];
    let mut returned = 0;
    // SAFETY: borrowed live key, aligned 56-byte OBJECT_BASIC_INFORMATION output.
    let status = unsafe {
        registry_authority::native::NtQueryObject(
            key,
            0,
            data.as_mut_ptr().cast(),
            56,
            &mut returned,
        )
    };
    ensure!(
        status == 0 && returned == 56,
        "retained registry rights query failed status={:08X} bytes={returned}",
        status as u32
    );
    let granted = (data[0] >> 32) as u32;
    ensure!(
        granted & 0x60000 == 0x60000,
        "retained registry key lacks READ_CONTROL/WRITE_DAC"
    );
    Ok(())
}
pub(in super::super) fn identity_label(key: Handle) -> Result<Vec<u8>> {
    rights(key)?;
    let (mut owner, mut group, mut dacl, mut label, mut descriptor) =
        (null_mut(), null_mut(), null_mut(), null_mut(), null_mut());
    // OWNER|GROUP|LABEL only. LABEL_SECURITY_INFORMATION uses READ_CONTROL, not SeSecurityPrivilege.
    let status = unsafe {
        GetSecurityInfo(
            key,
            4,
            0x13,
            &mut owner,
            &mut group,
            &mut dacl,
            &mut label,
            &mut descriptor,
        )
    };
    let result = (|| {
        ensure!(
            status == 0 && !descriptor.is_null() && !owner.is_null() && !group.is_null(),
            "retained registry identity query failed winerror={status}"
        );
        // SAFETY: native returned descriptor owns all associated components until LocalFree below.
        ensure!(
            unsafe { IsValidSecurityDescriptor(descriptor) } != 0,
            "registry identity descriptor is invalid"
        );
        let length = unsafe { GetSecurityDescriptorLength(descriptor) };
        ensure!(
            (20..=65536).contains(&length),
            "registry identity descriptor exceeds fixed bounds"
        );
        let bytes = unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), length as usize) }
            .to_vec();
        let parsed = RelativeDescriptor::parse(&bytes)?;
        ensure!(
            parsed.owner.is_some() && parsed.group.is_some(),
            "registry identity descriptor omitted owner/group"
        );
        Ok(bytes)
    })();
    let freed = descriptor.is_null() || unsafe { LocalFree(descriptor) }.is_null();
    match (result, freed) {
        (result, true) => result,
        (Err(primary), false) => Err(crate::windows_security::activation::Failures {
            errors: vec![
                primary,
                anyhow::anyhow!("registry identity allocation cleanup failed"),
            ],
        }
        .into()),
        (Ok(_), false) => anyhow::bail!("registry identity allocation cleanup failed"),
    }
}
pub(in super::super) fn preserved(before: &[u8], key: Handle) -> Result<()> {
    let mut after = identity_label(key)?;
    let result = require_registry_preserved(before, &after);
    after.fill(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_owned_registry_dacl_write_preserves_owner_group_and_integrity() {
        let package = "S-1-15-2-1-2-3-4-5-6-7";
        let user = crate::windows_security::sxs::current_user_sid().unwrap();
        let mut fixture = RegistryFixture::new(package).unwrap();
        let mut before = identity_label(fixture.root).unwrap();
        let text = controls::root_policy(&user, package).unwrap();
        let mut descriptor = Descriptor::new(&text).unwrap();
        let bytes = unsafe {
            std::slice::from_raw_parts(
                descriptor.0.cast::<u8>(),
                GetSecurityDescriptorLength(descriptor.0) as usize,
            )
        };
        let parsed = RelativeDescriptor::parse(bytes).unwrap();
        let acl = crate::windows_security::policy::Acl::parse(parsed.dacl.unwrap()).unwrap();
        assert_eq!(acl.aces.len(), 5);
        assert!(acl.aces.iter().all(|ace| ace.flags == 0));
        assert_eq!(acl.aces[0].kind, 1);
        assert_eq!(acl.aces[0].mask().unwrap(), 0xd0006);
        assert_eq!(acl.aces[3].kind, 0);
        assert_eq!(acl.aces[3].mask().unwrap(), 0x20019);
        assert_eq!(
            acl.aces[3].sid().unwrap(),
            crate::windows_security::scratch::sid(&user).unwrap()
        );
        assert_eq!(acl.aces[4].mask().unwrap(), 0x20019);
        assert_eq!(
            acl.aces[4].sid().unwrap(),
            crate::windows_security::scratch::sid(package).unwrap()
        );
        descriptor.close().unwrap();
        apply_registry_acl(fixture.root, &text).unwrap();
        controls::require_policy(fixture.root, &user, package).unwrap();
        preserved(&before, fixture.root).unwrap();
        before.fill(0);
        fixture.close().unwrap();
    }
}
