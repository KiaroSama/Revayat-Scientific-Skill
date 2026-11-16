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
    fn GetCurrentThread() -> Handle;
    fn GetCurrentProcess() -> Handle;
    fn GetVolumeInformationByHandleW(
        handle: Handle,
        name: *mut u16,
        name_size: u32,
        serial: *mut u32,
        component: *mut u32,
        flags: *mut u32,
        system: *mut u16,
        system_size: u32,
    ) -> i32;
}
#[link(name = "fltlib")]
unsafe extern "system" {
    fn FilterVolumeInstanceFindFirst(
        volume: *const u16,
        class: i32,
        buffer: *mut std::ffi::c_void,
        size: u32,
        returned: *mut u32,
        find: *mut Handle,
    ) -> i32;
    fn FilterVolumeInstanceFindNext(
        find: Handle,
        class: i32,
        buffer: *mut std::ffi::c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
    fn FilterVolumeInstanceFindClose(find: Handle) -> i32;
}

/// Known minifilter names reported as bits 32-39 of `dr6`; total instances in bits 40-47.
const FILTERS: [&str; 8] = [
    "WdFilter",
    "bindflt",
    "wcifs",
    "luafv",
    "Wof",
    "FileCrypt",
    "storqosflt",
    "CldFlt",
];

/// Volume evidence: file-system flags into `result` when no NTSTATUS was recorded, and the
/// attached minifilter census into `dr6` bits 32-47 (closed name set, never raw names).
fn volume_evidence(path: &Path, root: Handle, numbers: &mut diagnostics::Numbers) {
    let mut flags = 0u32;
    // SAFETY: query-only call on the live held root; null buffers are allowed with size 0.
    let queried = unsafe {
        GetVolumeInformationByHandleW(
            root,
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            null_mut(),
            0,
        )
    } != 0;
    if numbers.result.is_none() {
        numbers.result = Some(if queried { flags } else { 0xFFFF_FFFF });
    }
    let name = wide(path);
    let mut buffer = vec![0u64; 512];
    let (mut known, mut total, mut find) = (0u64, 0u64, null_mut());
    let mut returned = 0u32;
    // SAFETY: bounded 4 KiB aligned buffer, InstanceFullInformation (2); the find handle is
    // closed below. Each entry's name offsets are bounds-checked before slicing.
    let mut status = unsafe {
        FilterVolumeInstanceFindFirst(
            name.as_ptr(),
            2,
            buffer.as_mut_ptr().cast(),
            4096,
            &mut returned,
            &mut find,
        )
    };
    while status >= 0 && total < 0xFF {
        total += 1;
        let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast(), 4096) };
        let field = |at: usize| usize::from(u16::from_le_bytes([bytes[at], bytes[at + 1]]));
        let (length, offset) = (field(16), field(18));
        if length % 2 == 0 && offset + length <= 4096 {
            let units: Vec<u16> = bytes[offset..offset + length]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            let filter = String::from_utf16_lossy(&units);
            if let Some(index) = FILTERS
                .iter()
                .position(|known| known.eq_ignore_ascii_case(&filter))
            {
                known |= 1 << index;
            }
        }
        status = unsafe {
            FilterVolumeInstanceFindNext(find, 2, buffer.as_mut_ptr().cast(), 4096, &mut returned)
        };
    }
    if !find.is_null() && find as isize != -1 {
        unsafe { FilterVolumeInstanceFindClose(find) };
    }
    let census = if total == 0 && status < 0 && status as u32 != 0x80070103 {
        0xFFFF
    } else {
        known | (total << 8)
    };
    numbers.dr6 = Some((numbers.dr6.unwrap_or(0) & !(0xFFFF << 32)) | (census << 32));
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenThreadToken(thread: Handle, access: u32, as_self: i32, token: *mut Handle) -> i32;
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: i32,
        data: *mut std::ffi::c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut u32) -> i32;
}

/// Closed well-known SID class for refusal evidence: 0 SY, 1 BA, 2 OWNER RIGHTS, 3 CREATOR
/// OWNER, 4 AU, 5 BU, 6 WD, 7 any other (user, package or domain) SID. Never a raw SID.
fn sid_class(sid: &[u8]) -> u64 {
    const KNOWN: [&[u8]; 7] = [
        &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
        &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0],
        &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0],
        &[1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0],
        &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0],
        &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0],
        &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
    ];
    KNOWN.iter().position(|known| *known == sid).unwrap_or(7) as u64
}

/// Summarizes the held root's current descriptor without printing SIDs or raw bytes.
/// `bytes` = OR of deny ACE masks; `stdout_bytes` = ACE count | deny count << 8 | control << 16;
/// `dr6` = owner class << 48 | label RID << 16 | label policy (all ones when unreadable);
/// `dr7` = up to eight ACEs, one byte each: kind(2) | class << 2 | WRITE_DAC << 5 |
/// inherited << 6 | inherit-only << 7.
fn root_evidence(root: Handle, numbers: &mut diagnostics::Numbers) {
    use crate::windows_security::policy::{Acl, Descriptor as Parsed};
    let Ok(raw) = access::security(root, 0x15) else {
        numbers.dr6 = Some(u64::MAX);
        return;
    };
    let Ok(parsed) = Parsed::parse(&raw) else {
        numbers.dr6 = Some(u64::MAX - 1);
        return;
    };
    let mut label = (0u64, 0u64);
    if let Some(Ok(sacl)) = parsed.sacl.map(Acl::parse)
        && let Some(ace) = sacl.aces.iter().find(|ace| ace.kind == 17)
    {
        let rid = ace
            .sid()
            .ok()
            .and_then(|sid| sid.get(sid.len().saturating_sub(4)..))
            .and_then(|tail| tail.try_into().ok())
            .map_or(0xFFFF, |tail: [u8; 4]| {
                u64::from(u32::from_le_bytes(tail)) & 0xFFFF
            });
        label = (rid, u64::from(ace.mask().unwrap_or(0) & 0xFFFF));
    }
    let owner = parsed.owner.map_or(0xF, sid_class);
    numbers.dr6 = Some((owner << 48) | (label.0 << 16) | label.1);
    let (mut count, mut denies, mut deny_mask, mut packed) = (0u32, 0u32, 0u32, 0u64);
    if let Some(Ok(dacl)) = parsed.dacl.map(Acl::parse) {
        for (index, ace) in dacl.aces.iter().enumerate() {
            count += 1;
            let mask = ace.mask().unwrap_or(0);
            if ace.kind == 1 {
                denies += 1;
                deny_mask |= mask;
            }
            if index < 8 {
                let kind = u64::from(ace.kind.min(2));
                let class = ace.sid().map_or(7, sid_class);
                let byte = kind
                    | (class << 2)
                    | (u64::from(mask & 0x40000 != 0) << 5)
                    | (u64::from(ace.flags & 0x10 != 0) << 6)
                    | (u64::from(ace.flags & 0x08 != 0) << 7);
                packed |= byte << (index * 8);
            }
        }
    }
    numbers.bytes = Some(deny_mask);
    numbers.stdout_bytes =
        Some(count.min(0xFF) | (denies.min(0xFF) << 8) | (u32::from(parsed.control) << 16));
    numbers.dr7 = Some(packed);
}

/// Effective-token evidence: bit0 thread impersonating, bit1/2 restore present/enabled,
/// bit3/4 take-ownership present/enabled, bits 8-15 elevation type, bits 16-31 integrity RID.
fn token_evidence() -> u32 {
    let mut token = null_mut();
    let mut value = 0u32;
    // SAFETY: query-only token opens; every opened handle is owned and closed below.
    if unsafe { OpenThreadToken(GetCurrentThread(), 8, 1, &mut token) } != 0 {
        value |= 1;
    } else if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) } == 0 {
        return 0xFFFF_FFFF;
    }
    let mut token = Owned(token);
    let mut buffer = vec![0u64; 512];
    let mut returned = 0u32;
    let mut query = |class: i32, buffer: &mut [u64]| {
        // SAFETY: bounded 4 KiB aligned buffer for a fixed information class.
        unsafe {
            GetTokenInformation(
                token.0,
                class,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
                &mut returned,
            ) != 0
        }
    };
    if query(3, &mut buffer) {
        let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast(), 4096) };
        let entries = u32::from_le_bytes(bytes[..4].try_into().unwrap()).min(340) as usize;
        for (name, present) in [
            ("SeRestorePrivilege", 2u32),
            ("SeTakeOwnershipPrivilege", 8),
        ] {
            let mut parts = [0u32; 2];
            let name = wide(name);
            // SAFETY: LUID is two DWORDs; `parts` provides exactly that storage.
            if unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), parts.as_mut_ptr()) }
                == 0
            {
                continue;
            }
            let luid = u64::from(parts[0]) | (u64::from(parts[1]) << 32);
            for index in 0..entries {
                let at = 4 + index * 12;
                let entry = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
                let attributes = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap());
                if entry == luid {
                    value |= present | (u32::from(attributes & 2 != 0) * (present << 1));
                }
            }
        }
    }
    if query(18, &mut buffer) {
        value |= ((buffer[0] as u32) & 0xFF) << 8;
    }
    if query(25, &mut buffer) {
        // TOKEN_MANDATORY_LABEL: SID pointer then attributes; the SID follows in the buffer.
        let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast(), 4096) };
        let sid = bytes[16..].as_ptr();
        let pointer = buffer[0] as *const u8;
        if pointer == sid {
            let rid = u32::from_le_bytes(bytes[16 + 8..16 + 12].try_into().unwrap());
            value |= (rid & 0xFFFF) << 16;
        }
    }
    let _ = token.close();
    value
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
    // The same root through its volume GUID name bypasses the drive-letter mount point; the
    // later identity bind still requires it to be the held root object.
    if let Some(volume) = path
        .to_str()
        .and_then(|text| super::layout::mounted(text).ok().flatten())
        && let Ok(handle) = Owned::open(&volume, 0x00060080, 7, 0x02200000)
    {
        *progress |= 0x2000;
        return Ok(handle);
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
/// 0x1000 held-root reopen, 0x2000 volume GUID path open.
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
                root_evidence(root, &mut numbers);
                volume_evidence(path, root, &mut numbers);
                numbers.stderr_bytes = Some(token_evidence());
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
