//! Scratch-root security writes, scoped privileges, handle binding and closed failure evidence.
use super::super::{
    Handle,
    authority::{Descriptor, wide},
    scratch_access::{self as access, Owned},
};
use crate::windows_security::activation::diagnostics::{self, Stage};
use anyhow::{Context, Result, ensure};
use std::{path::Path, ptr::null_mut};

#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetSecurityDescriptorOwner(
        descriptor: Handle,
        owner: *mut Handle,
        defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        descriptor: Handle,
        present: *mut i32,
        dacl: *mut Handle,
        defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityDescriptorSacl(
        descriptor: Handle,
        present: *mut i32,
        sacl: *mut Handle,
        defaulted: *mut i32,
    ) -> i32;
    fn SetNamedSecurityInfoW(
        path: *mut u16,
        kind: i32,
        fields: u32,
        owner: Handle,
        group: Handle,
        dacl: Handle,
        sacl: Handle,
    ) -> u32;
    fn SetSecurityInfo(
        object: Handle,
        kind: i32,
        fields: u32,
        owner: Handle,
        group: Handle,
        dacl: Handle,
        sacl: Handle,
    ) -> u32;
}

fn set_dacl(path: &Path, root: Handle, dacl: Handle) -> Result<()> {
    // Restore privilege is applied at the backup-intent open, not merely enabled around a
    // pathname setter. READ_CONTROL also permits the filesystem ACL inheritance machinery.
    let mut target = Owned::open(path, 0x00060000, 7, 0x02200000)?;
    let result = (|| {
        ensure!(
            access::identity(target.0, true)? == access::identity(root, true)?,
            "scratch seal pathname changed from its held root"
        );
        // SAFETY: exact bound directory handle with WRITE_DAC; descriptor stays live. The
        // protected private creator keeps its own ACL; subsequent folders inherit this root.
        let status = unsafe {
            SetSecurityInfo(
                target.0,
                1,
                0x80000004,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(status as i32)).context("set scratch DACL")
        }
    })();
    access::combine(result, target.close())
}

pub(super) fn set_root_security(
    path: &Path,
    root: Handle,
    sddl: &str,
    fields: u32,
    stage: Stage,
) -> Result<()> {
    let mut descriptor = Descriptor::new(sddl)?;
    let mut wide_path = wide(path);
    let mut take = access::ManageVolume::acquire_optional("SeTakeOwnershipPrivilege")?;
    let mut numbers = diagnostics::Numbers {
        properties: Some(fields),
        ..Default::default()
    };
    let result = (|| {
        let mut restore = access::ManageVolume::acquire_optional("SeRestorePrivilege")?;
        let result = (|| {
            let (mut owner, mut dacl, mut sacl) = (null_mut(), null_mut(), null_mut());
            let (mut present, mut defaulted) = (0, 0);
            let extracted = (fields & 1 == 0
                || unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) }
                    != 0)
                && (fields & 4 == 0
                    || unsafe {
                        GetSecurityDescriptorDacl(
                            descriptor.0,
                            &mut present,
                            &mut dacl,
                            &mut defaulted,
                        )
                    } != 0
                        && present != 0)
                && (fields & 0x18 == 0
                    || unsafe {
                        GetSecurityDescriptorSacl(
                            descriptor.0,
                            &mut present,
                            &mut sacl,
                            &mut defaulted,
                        )
                    } != 0
                        && present != 0);
            ensure!(extracted, "scratch security component extraction failed");
            let result = if fields == 0x80000004 {
                set_dacl(path, root, dacl)
            } else {
                // Owner and integrity-label writes retain the established named-object path.
                let status = unsafe {
                    SetNamedSecurityInfoW(
                        wide_path.as_mut_ptr(),
                        1,
                        fields,
                        owner,
                        null_mut(),
                        dacl,
                        sacl,
                    )
                };
                if status == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::from_raw_os_error(status as i32))
                        .context("set scratch policy")
                }
            };
            if result.is_err() && fields & 4 != 0 {
                // Diagnostic only: readback cannot replace the failed setter/open or admit a run.
                let readback = access::dacl_matches(root, descriptor.0).ok();
                numbers.count = Some(
                    u32::from(take.is_some())
                        | (u32::from(restore.is_some()) << 1)
                        | (u32::from(readback.is_some()) << 2)
                        | (u32::from(readback == Some(true)) << 3),
                );
            }
            result
        })();
        access::combine(
            result,
            restore.as_mut().map_or(Ok(()), access::ManageVolume::close),
        )
    })();
    let result = access::combine(
        result,
        take.as_mut().map_or(Ok(()), access::ManageVolume::close),
    );
    access::combine(result, descriptor.close()).map_err(|error| {
        numbers.native_error = diagnostics::find::<std::io::Error>(&error)
            .and_then(std::io::Error::raw_os_error)
            .map(|code| code as u32);
        diagnostics::annotate(error, stage, numbers)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_dacl_write_keeps_protected_child_and_refuses_a_different_directory() {
        let work = tempfile::tempdir().unwrap();
        let child = work.path().join("private");
        std::fs::create_dir(&child).unwrap();
        let other = work.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let host = crate::windows_security::sxs::current_user_sid().unwrap();
        let policy = format!("D:P(A;OICI;FA;;;{host})(A;OICI;FA;;;SY)");
        let mut expected = Descriptor::new(&policy).unwrap();
        let mut root = Owned::open(work.path(), 0x20080, 7, 0x02200000).unwrap();
        let mut child_pin = Owned::open(&child, 0x20080, 7, 0x02200000).unwrap();
        set_root_security(
            &child,
            child_pin.0,
            &policy,
            0x80000004,
            Stage::ScratchSealDacl,
        )
        .unwrap();
        let before = access::security(child_pin.0, 4).unwrap();
        let result = (|| -> Result<()> {
            set_root_security(
                work.path(),
                root.0,
                &policy,
                0x80000004,
                Stage::ScratchSealDacl,
            )?;
            ensure!(
                access::dacl_matches(root.0, expected.0)?,
                "root DACL differs"
            );
            ensure!(
                access::security(child_pin.0, 4)? == before,
                "protected child DACL changed"
            );
            let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut());
            ensure!(
                unsafe {
                    GetSecurityDescriptorDacl(expected.0, &mut present, &mut dacl, &mut defaulted)
                } != 0,
                "test DACL extraction failed"
            );
            ensure!(
                set_dacl(&other, root.0, dacl).is_err(),
                "foreign directory accepted"
            );
            Ok(())
        })();
        let result = access::combine(result, expected.close());
        let result = access::combine(result, child_pin.close());
        access::combine(result, root.close()).unwrap();
        work.close().unwrap();
    }
}
