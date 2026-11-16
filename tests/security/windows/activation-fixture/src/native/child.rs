//! Fixed external executable-ID1 or DLL-ID2 request. The wrapper binds the closed role.
use super::{
    abi::{self, ActCtx},
    config,
    emit::{Record, emit},
};
pub const RESOURCE_ID: u16 = 1;
pub const LABEL: &[u8] = b"WINDOWS_CHILD_ACTIVATION";
pub fn run() -> ! {
    let context = ActCtx {
        size: 56,
        flags: 0x2e,
        source: config::FIXED_PYTHON.as_ptr(),
        architecture: 0,
        language: config::FIXED_LANGUAGE,
        directory: config::FIXED_DIRECTORY.as_ptr(),
        resource: RESOURCE_ID as *const u16,
        application: config::FIXED_PYTHON.as_ptr(),
        module: core::ptr::null_mut(),
    };
    // SAFETY: fixed prepared canonical UTF-16 inputs remain live for the call.
    let handle = unsafe { abi::CreateActCtxW(&context) };
    // Capture GetLastError before release, allocation, output or any other call.
    let error = if handle as usize == usize::MAX {
        unsafe { abi::GetLastError() }
    } else {
        0
    };
    let success = !handle.is_null() && handle as usize != usize::MAX;
    if success {
        unsafe { abi::ReleaseActCtx(handle) };
    }
    if handle.is_null() || !success && error == 0 {
        unsafe { abi::ExitProcess(120) }
    }
    let mut line = Record::new();
    line.append(LABEL);
    line.append(b" created=");
    line.append(if success { b"True" } else { b"False" });
    line.append(b" win32_error=0x");
    line.hexadecimal(error);
    line.append(b" cause_claimed=False child_equivalence_claimed=False\n");
    emit(
        unsafe { abi::GetStdHandle(-11i32 as u32) },
        line.bytes(),
        121,
    );
    unsafe { abi::ExitProcess(0) }
}
