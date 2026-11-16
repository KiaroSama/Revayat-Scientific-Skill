//! Fixed own-module resource call. Source variants alter only these reviewed role constants.
use super::{
    abi::{self, ActCtx},
    emit::{Record, emit},
};
pub const RESOURCE_ID: u16 = 2;
pub const LABEL: &[u8] = b"WINDOWS_SELF_ACTIVATION";
pub const PRE_CALL_RECEIPT: bool = false;
pub fn run() -> ! {
    let own = unsafe { abi::GetModuleHandleW(core::ptr::null()) };
    if own.is_null() || own as usize == usize::MAX {
        unsafe { abi::ExitProcess(120) }
    }
    let context = ActCtx {
        size: 56,
        flags: 0x88,
        source: core::ptr::null(),
        architecture: 0,
        language: 0,
        directory: core::ptr::null(),
        resource: RESOURCE_ID as *const u16,
        application: core::ptr::null(),
        module: own,
    };
    let output = if PRE_CALL_RECEIPT {
        let output = unsafe { abi::GetStdHandle(-11i32 as u32) };
        emit(output, b"EXPLICIT_ID2_BEFORE_CALL\n", 122);
        output
    } else {
        core::ptr::null_mut()
    };
    let handle = unsafe { abi::CreateActCtxW(&context) };
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
    line.append(b" entry_reached=True created=");
    line.append(if success { b"True" } else { b"False" });
    line.append(b" win32_error=0x");
    line.hexadecimal(error);
    line.append(b"\n");
    let output = if PRE_CALL_RECEIPT {
        output
    } else {
        unsafe { abi::GetStdHandle(-11i32 as u32) }
    };
    emit(output, line.bytes(), 121);
    unsafe { abi::ExitProcess(0) }
}
