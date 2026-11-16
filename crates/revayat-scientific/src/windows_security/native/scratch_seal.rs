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
    fn GetSecurityDescriptorLength(descriptor: Handle) -> u32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSetSecurityObject(handle: Handle, fields: u32, data: *const std::ffi::c_void) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn ReOpenFile(original: Handle, access: u32, share: u32, flags: u32) -> Handle;
}

/// Opens the exact held root for the DACL write. A pathname open is tried first; when it is
/// refused, the held root object is reopened (no pathname rebind) and each candidate access is
/// probed so a hosted refusal reports which right was denied, never raw text.
fn open_writer(path: &Path, root: Handle, progress: &mut u32) -> Result<Owned> {
    let primary = match Owned::open(path, 0x00060080, 7, 0x02200000) {
        Ok(handle) => return Ok(handle),
        Err(error) => error,
    };
    for (bit, access, flags) in [
        (0x100, 0x00040000, 0x02200000),
        (0x200, 0x00040000, 0x00200000),
        (0x400, 0x00080000, 0x02200000),
        (0x800, 0x00020000, 0x02200000),
    ] {
        if let Ok(mut probe) = Owned::open(path, access, 7, flags) {
            *progress |= bit;
            probe.close()?;
        }
    }
    // SAFETY: `root` is the live held directory handle; the result is owned or invalid.
    let handle = unsafe { ReOpenFile(root, 0x00060080, 7, 0x02000000) };
    if handle.is_null() || handle as isize == -1 {
        return Err(primary);
    }
    *progress |= 0x1000;
    Ok(Owned(handle))
}

/// `progress` bits: 0x10 opened, 0x20 identity bound, 0x40 native setter invoked; open probes
/// 0x100 WRITE_DAC backup, 0x200 WRITE_DAC plain, 0x400 WRITE_OWNER, 0x800 READ_CONTROL,
/// 0x1000 held-root reopen.
fn set_dacl(
    path: &Path,
    root: Handle,
    descriptor: Handle,
    progress: &mut u32,
    ntstatus: &mut Option<u32>,
) -> Result<()> {
    // Restore privilege is applied at the backup-intent open, not merely enabled around a
    // pathname setter. FILE_READ_ATTRIBUTES is requested explicitly for the identity bind.
    let mut target = open_writer(path, root, progress)?;
    *progress |= 0x10;
    let result = (|| {
        ensure!(
            access::identity(target.0, true)? == access::identity(root, true)?,
            "scratch seal pathname changed from its held root"
        );
        *progress |= 0x20;
        let length = unsafe { GetSecurityDescriptorLength(descriptor) };
        ensure!(
            (20..=65536).contains(&length),
            "scratch seal descriptor exceeds bound"
        );
        // SAFETY: exact bound directory handle with WRITE_DAC; the self-relative descriptor
        // stays live. Unlike SetSecurityInfo/SetNamedSecurityInfoW, the native setter does not
        // walk existing children. The protected private creator keeps its own ACL and folders
        // created after the seal inherit this root in the kernel.
        *progress |= 0x40;
        let status = unsafe { NtSetSecurityObject(target.0, 4, descriptor.cast_const()) };
        if status >= 0 {
            Ok(())
        } else {
            *ntstatus = Some(status as u32);
            let code = unsafe { RtlNtStatusToDosError(status) };
            Err(std::io::Error::from_raw_os_error(code as i32))
                .with_context(|| format!("set scratch DACL ntstatus=0x{:08X}", status as u32))
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
            let mut progress = 0;
            let result = if fields == 0x80000004 {
                set_dacl(path, root, descriptor.0, &mut progress, &mut numbers.result)
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
                        | (u32::from(readback == Some(true)) << 3)
                        | progress,
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
        let host = crate::windows_security::sxs::current_user_sid().unwrap();
        let other = work.path().join("other");
        std::fs::create_dir(&other).unwrap();
        // Mirrors `System Volume Information`: a protected child the caller cannot open for
        // READ_CONTROL/WRITE_DAC, which a user-mode propagating setter fails on.
        let locked = work.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let mut locked_pin = Owned::open(&locked, 0x20080, 7, 0x02200000).unwrap();
        // The owner keeps only delete/list so the fixture stays removable.
        let locked_policy = format!("D:P(D;;0x000C0000;;;OW)(A;;FA;;;SY)(A;;0x00110081;;;{host})");
        set_root_security(
            &locked,
            locked_pin.0,
            &locked_policy,
            0x80000004,
            Stage::ScratchSealDacl,
        )
        .unwrap();
        let locked_before = access::security(locked_pin.0, 4).unwrap();
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
            ensure!(
                access::security(locked_pin.0, 4)? == locked_before,
                "inaccessible protected child DACL changed"
            );
            ensure!(
                set_dacl(&other, root.0, expected.0, &mut 0, &mut None).is_err(),
                "foreign directory accepted"
            );
            Ok(())
        })();
        let result = access::combine(result, expected.close());
        let result = access::combine(result, child_pin.close());
        let result = access::combine(result, locked_pin.close());
        let result = access::combine(result, std::fs::remove_dir(&locked).map_err(Into::into));
        access::combine(result, root.close()).unwrap();
        work.close().unwrap();
    }
}
