//! Fixed x64 ABI used only by the closed native quota worker.
#![allow(non_snake_case)]
use anyhow::{Result, ensure};
pub(super) use registry_authority::native::{
    CloseHandle, GetCurrentProcess, GetLastError, GetTokenInformation, OpenProcessToken,
    ProcessInfo, Raw, Security, SetLastError, StartupEx,
};
use std::{
    ffi::c_void,
    ptr::null_mut,
    sync::atomic::{AtomicBool, Ordering},
};
// LocalFree is declared below; registry-authority deliberately does not own local allocations.
static CLEANUP_FAILED: AtomicBool = AtomicBool::new(false);
pub(super) fn cleanup_ok() -> bool {
    !CLEANUP_FAILED.load(Ordering::SeqCst)
}
pub(super) fn note_cleanup_failure() {
    CLEANUP_FAILED.store(true, Ordering::SeqCst);
}
pub(super) fn combine<T>(operation: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(crate::windows_security::activation::Failures {
            errors: vec![primary, cleanup],
        }
        .into()),
    }
}
pub(super) fn all(results: impl IntoIterator<Item = Result<()>>) -> Result<()> {
    let errors = results
        .into_iter()
        .filter_map(Result::err)
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(crate::windows_security::activation::Failures { errors }.into())
    }
}
pub(super) struct Owned(pub Raw);
impl Owned {
    pub(super) fn new(raw: Raw) -> Result<Self> {
        ensure!(
            !raw.is_null() && raw as isize != -1,
            "native quota handle acquisition failed"
        );
        Ok(Self(raw))
    }
    pub(super) fn empty() -> Self {
        Self(null_mut())
    }
    pub(super) fn close(&mut self) -> Result<()> {
        if self.0.is_null() {
            return Ok(());
        }
        let raw = std::mem::replace(&mut self.0, null_mut());
        // SAFETY: exclusively owned valid API-returned handle, invalidated before one close attempt.
        ensure!(
            unsafe { CloseHandle(raw) } != 0,
            "native quota handle close failed"
        );
        Ok(())
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        if self.close().is_err() {
            CLEANUP_FAILED.store(true, Ordering::SeqCst);
        }
    }
}
pub(super) struct Descriptor(pub Raw);
impl Descriptor {
    pub(super) fn new(text: &str) -> Result<Self> {
        let text = wide(text);
        let mut raw = null_mut();
        let mut bytes = 0;
        // SAFETY: live NUL-terminated text and writable allocation output.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut raw,
                &mut bytes,
            )
        };
        let mut value = Self(raw);
        let checked = (|| {
            ensure!(
                ok != 0 && !raw.is_null() && (20..=65536).contains(&bytes),
                "native quota descriptor acquisition failed"
            );
            Ok(())
        })();
        if let Err(error) = checked {
            return combine(Err(error), value.close());
        }
        Ok(value)
    }
    pub(super) fn dacl(&self) -> Result<Raw> {
        let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut());
        // SAFETY: live converted descriptor and scalar output fields.
        ensure!(
            unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) }
                != 0
                && present != 0
                && !dacl.is_null(),
            "native quota DACL is absent"
        );
        Ok(dacl)
    }
    pub(super) fn close(&mut self) -> Result<()> {
        if self.0.is_null() {
            return Ok(());
        }
        let raw = std::mem::replace(&mut self.0, null_mut());
        // SAFETY: ConvertStringSecurityDescriptor allocated this buffer with LocalAlloc.
        ensure!(
            unsafe { LocalFree(raw) }.is_null(),
            "native quota descriptor close failed"
        );
        Ok(())
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        if self.close().is_err() {
            CLEANUP_FAILED.store(true, Ordering::SeqCst);
        }
    }
}
pub(super) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
pub(super) fn open(
    path: &str,
    access: u32,
    share: u32,
    creation: u32,
    flags: u32,
    security: *const Security,
) -> Result<Owned> {
    let path = wide(path);
    // SAFETY: bounded fixed plan path, live optional security and no template handle.
    Owned::new(unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            security,
            creation,
            flags,
            null_mut(),
        )
    })
}
#[link(name = "kernel32")]
unsafe extern "system" {
    pub(super) fn LocalFree(memory: Raw) -> Raw;
    pub(super) fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *const Security,
        creation: u32,
        flags: u32,
        template: Raw,
    ) -> Raw;
    pub(super) fn GetFileType(handle: Raw) -> u32;
    pub(super) fn GetFileInformationByHandleEx(
        handle: Raw,
        class: i32,
        data: Raw,
        bytes: u32,
    ) -> i32;
    pub(super) fn SetFileInformationByHandle(
        handle: Raw,
        class: u32,
        data: *const c_void,
        bytes: u32,
    ) -> i32;
    pub(super) fn GetFinalPathNameByHandleW(
        handle: Raw,
        name: *mut u16,
        chars: u32,
        flags: u32,
    ) -> u32;
    pub(super) fn GetFileAttributesW(path: *const u16) -> u32;
    pub(super) fn GetDiskFreeSpaceExW(
        root: *const u16,
        available: *mut u64,
        total: *mut u64,
        free: *mut u64,
    ) -> i32;
    pub(super) fn GetVolumeInformationW(
        root: *const u16,
        name: *mut u16,
        name_chars: u32,
        serial: *mut u32,
        component: *mut u32,
        flags: *mut u32,
        filesystem: *mut u16,
        filesystem_chars: u32,
    ) -> i32;
    pub(super) fn SetFilePointerEx(
        file: Raw,
        distance: i64,
        position: *mut i64,
        method: u32,
    ) -> i32;
    pub(super) fn SetEndOfFile(file: Raw) -> i32;
    pub(super) fn DeviceIoControl(
        file: Raw,
        code: u32,
        input: *const c_void,
        input_bytes: u32,
        output: Raw,
        output_bytes: u32,
        returned: *mut u32,
        overlapped: Raw,
    ) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    pub(super) fn SetTokenInformation(token: Raw, class: i32, data: Raw, bytes: u32) -> i32;
    pub(super) fn AdjustTokenPrivileges(
        token: Raw,
        disable: i32,
        state: *const c_void,
        bytes: u32,
        previous: Raw,
        returned: *mut u32,
    ) -> i32;
    pub(super) fn LookupPrivilegeValueW(
        system: *const u16,
        name: *const u16,
        luid: *mut u32,
    ) -> i32;
    pub(super) fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut Raw,
        bytes: *mut u32,
    ) -> i32;
    pub(super) fn GetSecurityDescriptorDacl(
        descriptor: Raw,
        present: *mut i32,
        dacl: *mut Raw,
        defaulted: *mut i32,
    ) -> i32;
    pub(super) fn SetNamedSecurityInfoW(
        path: *mut u16,
        kind: i32,
        info: u32,
        owner: Raw,
        group: Raw,
        dacl: Raw,
        sacl: Raw,
    ) -> u32;
    pub(super) fn SetSecurityInfo(
        object: Raw,
        kind: i32,
        info: u32,
        owner: Raw,
        group: Raw,
        dacl: Raw,
        sacl: Raw,
    ) -> u32;
    pub(super) fn GetSecurityInfo(
        object: Raw,
        kind: i32,
        info: u32,
        owner: *mut Raw,
        group: *mut Raw,
        dacl: *mut Raw,
        sacl: *mut Raw,
        descriptor: *mut Raw,
    ) -> u32;
    pub(super) fn GetSecurityDescriptorLength(descriptor: Raw) -> u32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    pub(super) fn NtQueryObject(
        object: Raw,
        class: i32,
        data: Raw,
        bytes: u32,
        returned: *mut u32,
    ) -> i32;
}
