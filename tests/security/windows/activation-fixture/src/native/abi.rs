//! Exact Windows x64 fixture ABI. This module uses core and imports no CRT.
pub type Handle = *mut core::ffi::c_void;
#[repr(C)]
pub struct ActCtx {
    pub size: u32,
    pub flags: u32,
    pub source: *const u16,
    pub architecture: u16,
    pub language: u16,
    pub directory: *const u16,
    pub resource: *const u16,
    pub application: *const u16,
    pub module: Handle,
}
const _: () = {
    assert!(core::mem::size_of::<usize>() == 8);
    assert!(core::mem::size_of::<ActCtx>() == 56);
    assert!(core::mem::offset_of!(ActCtx, size) == 0);
    assert!(core::mem::offset_of!(ActCtx, flags) == 4);
    assert!(core::mem::offset_of!(ActCtx, source) == 8);
    assert!(core::mem::offset_of!(ActCtx, architecture) == 16);
    assert!(core::mem::offset_of!(ActCtx, language) == 18);
    assert!(core::mem::offset_of!(ActCtx, directory) == 24);
    assert!(core::mem::offset_of!(ActCtx, resource) == 32);
    assert!(core::mem::offset_of!(ActCtx, application) == 40);
    assert!(core::mem::offset_of!(ActCtx, module) == 48);
};
#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn CreateActCtxW(context: *const ActCtx) -> Handle;
    pub fn GetLastError() -> u32;
    pub fn ReleaseActCtx(context: Handle);
    pub fn GetModuleHandleW(name: *const u16) -> Handle;
    pub fn GetStdHandle(kind: u32) -> Handle;
    pub fn WriteFile(
        file: Handle,
        data: *const u8,
        count: u32,
        written: *mut u32,
        overlapped: Handle,
    ) -> i32;
    pub fn ExitProcess(code: u32) -> !;
}
