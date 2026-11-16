//! Fixed own-module RT_MANIFEST ID2 operation. No selector, arbitrary path, token or registry work.
#[cfg(all(windows, target_arch = "x86_64", target_env = "msvc"))]
mod native {
    use activation_fixture::{ActCtx, PRE_CALL, result};
    use std::{ffi::c_void, ptr::null};
    type Raw = *mut c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> Raw;
        fn CreateActCtxW(context: *const ActCtx) -> Raw;
        fn ReleaseActCtx(context: Raw);
        fn GetLastError() -> u32;
        fn GetStdHandle(kind: u32) -> Raw;
        fn WriteFile(
            file: Raw,
            data: *const u8,
            count: u32,
            written: *mut u32,
            overlapped: Raw,
        ) -> i32;
        fn ExitProcess(code: u32) -> !;
    }
    fn emit(output: Raw, text: &[u8], failure: u32) {
        let mut written = 0;
        if output.is_null()
            || output as usize == usize::MAX
            || unsafe {
                WriteFile(
                    output,
                    text.as_ptr(),
                    text.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            } == 0
            || written as usize != text.len()
        {
            unsafe { ExitProcess(failure) };
        }
    }
    pub fn run() -> ! {
        if std::env::args_os().len() != 1 || std::mem::size_of::<ActCtx>() != 56 {
            unsafe { ExitProcess(120) };
        }
        let own = unsafe { GetModuleHandleW(null()) };
        let Some(context) = ActCtx::explicit_id2(own as usize) else {
            unsafe { ExitProcess(120) }
        };
        let output = unsafe { GetStdHandle(-11i32 as u32) };
        emit(output, PRE_CALL, 122);
        let handle = unsafe { CreateActCtxW(&context) };
        // No call, allocation, formatting or release may precede failure-code capture.
        let error = if handle as usize == usize::MAX {
            unsafe { GetLastError() }
        } else {
            0
        };
        let created = !handle.is_null() && handle as usize != usize::MAX;
        if created {
            unsafe { ReleaseActCtx(handle) };
        }
        if handle.is_null() {
            unsafe { ExitProcess(120) };
        }
        let Some(line) = result(created, error) else {
            unsafe { ExitProcess(120) }
        };
        emit(output, line.as_bytes(), 121);
        unsafe { ExitProcess(0) }
    }
}
fn main() {
    #[cfg(all(windows, target_arch = "x86_64", target_env = "msvc"))]
    native::run();
    #[cfg(not(all(windows, target_arch = "x86_64", target_env = "msvc")))]
    {
        eprintln!("startup-explicit-id2 requires Windows x64 MSVC");
        std::process::exit(1);
    }
}
