//! Exact Win32 ABI used by the fixed lowbox controller.
use super::*;

#[repr(C)]
pub(super) struct Security {
    pub(super) size: u32,
    pub(super) descriptor: Handle,
    pub(super) inherit: i32,
}
#[repr(C)]
#[derive(Default)]
pub(super) struct Startup {
    pub(super) size: u32,
    pub(super) reserved: Handle,
    pub(super) desktop: Handle,
    pub(super) title: Handle,
    pub(super) x: u32,
    pub(super) y: u32,
    pub(super) width: u32,
    pub(super) height: u32,
    pub(super) chars_x: u32,
    pub(super) chars_y: u32,
    pub(super) fill: u32,
    pub(super) flags: u32,
    pub(super) show: u16,
    pub(super) reserved_bytes: u16,
    pub(super) reserved_data: Handle,
    pub(super) input: Handle,
    pub(super) output: Handle,
    pub(super) error: Handle,
}
#[repr(C)]
pub(super) struct StartupEx {
    pub(super) startup: Startup,
    pub(super) attributes: Handle,
}
#[repr(C)]
#[derive(Default)]
pub(super) struct ProcessInfo {
    pub(super) process: Handle,
    pub(super) thread: Handle,
    pub(super) pid: u32,
    pub(super) tid: u32,
}
#[repr(C)]
pub(super) struct Capabilities {
    pub(super) sid: Handle,
    pub(super) capabilities: Handle,
    pub(super) count: u32,
    pub(super) reserved: u32,
}
#[repr(C)]
pub(super) struct SidAttributes {
    pub(super) sid: Handle,
    pub(super) attributes: u32,
}

#[link(name = "userenv")]
unsafe extern "system" {
    pub(super) fn CreateAppContainerProfile(
        name: *const u16,
        display: *const u16,
        description: *const u16,
        capabilities: Handle,
        count: u32,
        sid: *mut Handle,
    ) -> i32;
    pub(super) fn DeleteAppContainerProfile(name: *const u16) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    pub(super) fn FreeSid(sid: Handle) -> Handle;
    pub(super) fn ConvertSidToStringSidW(sid: Handle, text: *mut *mut u16) -> i32;
    pub(super) fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    pub(super) fn GetTokenInformation(
        token: Handle,
        class: i32,
        data: Handle,
        size: u32,
        returned: *mut u32,
    ) -> i32;
    pub(super) fn AdjustTokenPrivileges(
        token: Handle,
        disable: i32,
        new: *const c_void,
        size: u32,
        previous: Handle,
        returned: *mut u32,
    ) -> i32;
    pub(super) fn CreateRestrictedToken(
        token: Handle,
        flags: u32,
        disable_count: u32,
        disabled: *const SidAttributes,
        delete_count: u32,
        deleted: Handle,
        restrict_count: u32,
        restricting: Handle,
        result: *mut Handle,
    ) -> i32;
    pub(super) fn CreateProcessAsUserW(
        token: Handle,
        image: *const u16,
        command: *mut u16,
        process_security: *const Security,
        thread_security: *const Security,
        inherit: i32,
        flags: u32,
        environment: Handle,
        cwd: *const u16,
        startup: *const StartupEx,
        info: *mut ProcessInfo,
    ) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    pub(super) fn CreatePipe(
        read: *mut Handle,
        write: *mut Handle,
        security: *const Security,
        size: u32,
    ) -> i32;
    pub(super) fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> i32;
    pub(super) fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *const Security,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    pub(super) fn InitializeProcThreadAttributeList(
        list: Handle,
        count: u32,
        flags: u32,
        size: *mut usize,
    ) -> i32;
    pub(super) fn UpdateProcThreadAttribute(
        list: Handle,
        flags: u32,
        attribute: usize,
        value: Handle,
        size: usize,
        previous: Handle,
        returned: Handle,
    ) -> i32;
    pub(super) fn DeleteProcThreadAttributeList(list: Handle);
    pub(super) fn GetCurrentProcess() -> Handle;
    pub(super) fn PeekNamedPipe(
        pipe: Handle,
        data: Handle,
        size: u32,
        read: *mut u32,
        available: *mut u32,
        remaining: *mut u32,
    ) -> i32;
    pub(super) fn ReadFile(
        file: Handle,
        data: Handle,
        size: u32,
        read: *mut u32,
        overlapped: Handle,
    ) -> i32;
    pub(super) fn GetExitCodeProcess(process: Handle, code: *mut u32) -> i32;
    pub(super) fn TerminateProcess(process: Handle, code: u32) -> i32;
    pub(super) fn SetLastError(code: u32);
}
