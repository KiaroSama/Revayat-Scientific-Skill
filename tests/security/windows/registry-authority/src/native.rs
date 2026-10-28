#![allow(non_snake_case)]
use crate::protocol::{Failure, Result, cleanup_failed, need, token_need};
use std::ffi::c_void;
use std::ptr::null_mut;

pub type Raw = *mut c_void;

#[repr(C)]
pub struct Unicode {
    pub length: u16,
    pub maximum: u16,
    pub buffer: *const u16,
}

#[repr(C)]
pub struct Attributes {
    pub length: u32,
    pub root: Raw,
    pub name: *const Unicode,
    pub flags: u32,
    pub descriptor: Raw,
    pub qos: Raw,
}

#[repr(C)]
#[derive(Default)]
pub struct Security {
    pub length: u32,
    pub descriptor: Raw,
    pub inherit: i32,
}

#[repr(C)]
#[derive(Default)]
pub struct Startup {
    pub size: u32,
    pub reserved: Raw,
    pub desktop: Raw,
    pub title: Raw,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub chars_x: u32,
    pub chars_y: u32,
    pub fill: u32,
    pub flags: u32,
    pub show: u16,
    pub reserved_bytes: u16,
    pub reserved_data: Raw,
    pub input: Raw,
    pub output: Raw,
    pub error: Raw,
}

#[repr(C)]
#[derive(Default)]
pub struct StartupEx {
    pub startup: Startup,
    pub attributes: Raw,
}

#[repr(C)]
#[derive(Default)]
pub struct ProcessInfo {
    pub process: Raw,
    pub thread: Raw,
    pub pid: u32,
    pub tid: u32,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtOpenKeyEx(
        handle: *mut Raw,
        access: u32,
        attributes: *const Attributes,
        options: u32,
    ) -> i32;
    pub fn NtClose(handle: Raw) -> i32;
    pub fn NtQueryObject(handle: Raw, class: i32, data: Raw, size: u32, returned: *mut u32) -> i32;
    pub fn NtQueryKey(handle: Raw, class: i32, data: Raw, size: u32, returned: *mut u32) -> i32;
    pub fn NtQuerySecurityAttributesToken(
        token: Raw,
        names: *const Unicode,
        count: u32,
        data: Raw,
        size: u32,
        returned: *mut u32,
    ) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    pub fn OpenProcessToken(process: Raw, access: u32, token: *mut Raw) -> i32;
    pub fn GetTokenInformation(
        token: Raw,
        class: i32,
        data: Raw,
        size: u32,
        returned: *mut u32,
    ) -> i32;
    pub fn RegQueryInfoKeyW(
        key: Raw,
        class: Raw,
        chars: Raw,
        reserved: Raw,
        keys: *mut u32,
        max_key: Raw,
        max_class: Raw,
        values: *mut u32,
        max_value: Raw,
        max_data: Raw,
        security: Raw,
        modified: *mut u64,
    ) -> i32;
    pub fn RegEnumKeyExW(
        key: Raw,
        index: u32,
        name: *mut u16,
        chars: *mut u32,
        reserved: Raw,
        class: Raw,
        class_chars: Raw,
        modified: Raw,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn GetCurrentProcess() -> Raw;
    pub fn CloseHandle(handle: Raw) -> i32;
    pub fn GetLastError() -> u32;
    pub fn SetLastError(error: u32);
    pub fn IsProcessInJob(process: Raw, job: Raw, result: *mut i32) -> i32;
    pub fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
    pub fn GetStdHandle(id: u32) -> Raw;
    pub fn GetFileType(handle: Raw) -> u32;
    pub fn CompareStringOrdinal(
        first: *const u16,
        first_len: i32,
        second: *const u16,
        second_len: i32,
        ignore_case: i32,
    ) -> i32;
    pub fn CreatePipe(read: *mut Raw, write: *mut Raw, security: *const Security, size: u32)
    -> i32;
    pub fn SetHandleInformation(handle: Raw, mask: u32, flags: u32) -> i32;
    pub fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *const Security,
        disposition: u32,
        flags: u32,
        template: Raw,
    ) -> Raw;
    pub fn InitializeProcThreadAttributeList(
        list: Raw,
        count: u32,
        flags: u32,
        size: *mut usize,
    ) -> i32;
    pub fn UpdateProcThreadAttribute(
        list: Raw,
        flags: u32,
        attribute: usize,
        value: Raw,
        size: usize,
        previous: Raw,
        returned: Raw,
    ) -> i32;
    pub fn DeleteProcThreadAttributeList(list: Raw);
    pub fn CreateProcessW(
        image: *const u16,
        command: *mut u16,
        process_security: Raw,
        thread_security: Raw,
        inherit: i32,
        flags: u32,
        environment: Raw,
        cwd: *const u16,
        startup: *const StartupEx,
        info: *mut ProcessInfo,
    ) -> i32;
    pub fn ResumeThread(thread: Raw) -> u32;
    pub fn WaitForSingleObject(handle: Raw, milliseconds: u32) -> u32;
    pub fn GetExitCodeProcess(handle: Raw, code: *mut u32) -> i32;
    pub fn TerminateProcess(handle: Raw, code: u32) -> i32;
    pub fn PeekNamedPipe(
        handle: Raw,
        data: Raw,
        size: u32,
        read: Raw,
        available: *mut u32,
        remaining: Raw,
    ) -> i32;
    pub fn ReadFile(handle: Raw, data: Raw, size: u32, read: *mut u32, overlapped: Raw) -> i32;
}

pub struct Handle {
    pub raw: Raw,
    key: bool,
}

impl Handle {
    pub fn new(raw: Raw, key: bool) -> Self {
        Self { raw, key }
    }

    pub fn valid(&self) -> bool {
        let value = self.raw as usize;
        value > 0 && value < 0x7FFFFFFFFFFFFFFF && !(0x80000000..=0x800000FF).contains(&value)
    }

    pub fn close(&mut self) -> Result<()> {
        if !self.valid() {
            return Ok(());
        }
        let raw = std::mem::replace(&mut self.raw, null_mut());
        // SAFETY: this owner exclusively holds a live API-returned handle, closed exactly once.
        let success = unsafe {
            if self.key {
                NtClose(raw) == 0
            } else {
                CloseHandle(raw) != 0
            }
        };
        if success {
            Ok(())
        } else {
            Err(Failure::new("close", "cleanup"))
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.close().is_err() {
            cleanup_failed();
        }
    }
}

pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

pub fn same_name(first: &str, second: &str) -> Result<bool> {
    let first = wide(first);
    let second = wide(second);
    // SAFETY: both NUL-terminated UTF-16 arrays remain live for this synchronous comparison.
    let result = unsafe { CompareStringOrdinal(first.as_ptr(), -1, second.as_ptr(), -1, 1) };
    need((1..=3).contains(&result), "identity")?;
    Ok(result == 2)
}

pub fn detached() -> Result<()> {
    let mut console = 0;
    // SAFETY: writable scalar and borrowed standard handles; no handle is transferred or closed.
    unsafe {
        SetLastError(0);
        let count = GetConsoleProcessList(&mut console, 1);
        let error = GetLastError();
        token_need(count == 0 && error == 6, "control-console")?;
        for (id, kind, stage) in [
            (-10i32, 2, "control-stdin"),
            (-11, 3, "control-stdout"),
            (-12, 3, "control-stderr"),
        ] {
            let handle = GetStdHandle(id as u32);
            token_need(
                !handle.is_null() && handle as isize != -1 && GetFileType(handle) == kind,
                stage,
            )?;
        }
        let mut in_job = 0;
        token_need(
            IsProcessInJob(GetCurrentProcess(), null_mut(), &mut in_job) != 0 && in_job != 0,
            "control-job",
        )
    }
}
