//! Supplementary own-module ID2 control; never a Python or original fixture identity.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![allow(dead_code)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(test))]
// Dependencies are staged into the owned compiler directory; their originals are formatted there.
#[rustfmt::skip]
mod abi;
#[cfg(not(test))]
#[rustfmt::skip]
mod builtins;
#[cfg(not(test))]
#[rustfmt::skip]
mod emit;

/// The owned launcher supplies one quoted executable and no selectors. The first
/// argument has Windows' special executable-name grammar; backslashes are literal.
pub fn no_arguments(mut unit: impl FnMut(usize) -> Option<u16>) -> bool {
    if unit(0) != Some(u16::from(b'"')) {
        return false;
    }
    let mut content = false;
    let mut closed = false;
    for index in 1..32767 {
        let Some(value) = unit(index) else {
            return false;
        };
        if value == 0 {
            return content && closed;
        }
        if closed {
            if value != u16::from(b' ') && value != u16::from(b'\t') {
                return false;
            }
        } else if value == u16::from(b'"') {
            if !content {
                return false;
            }
            closed = true;
        } else {
            content = true;
        }
    }
    false
}

#[cfg(not(test))]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCommandLineW() -> *const u16;
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "system" fn StartupEntry() -> ! {
    use abi::ActCtx;
    let command = unsafe { GetCommandLineW() };
    if command.is_null()
        || !no_arguments(|index| {
            // GetCommandLineW owns a NUL-terminated process command line. The
            // parser stops at that terminator and never reads beyond its bound.
            Some(unsafe { *command.add(index) })
        })
    {
        unsafe { abi::ExitProcess(120) }
    }
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
        resource: 2usize as *const u16,
        application: core::ptr::null(),
        module: own,
    };
    let output = unsafe { abi::GetStdHandle(-11i32 as u32) };
    emit::emit(output, b"EXPLICIT_ID2_BEFORE_CALL\n", 122);
    let handle = unsafe { abi::CreateActCtxW(&context) };
    let error = if handle as usize == usize::MAX {
        unsafe { abi::GetLastError() }
    } else {
        0
    };
    let created = !handle.is_null() && handle as usize != usize::MAX;
    if created {
        unsafe { abi::ReleaseActCtx(handle) };
    }
    if handle.is_null() || created != (error == 0) {
        unsafe { abi::ExitProcess(120) }
    }
    let mut line = emit::Record::new();
    line.append(b"WINDOWS_EXPLICIT_ID2_ACTIVATION entry_reached=True created=");
    line.append(if created { b"True" } else { b"False" });
    line.append(b" win32_error=0x");
    line.hexadecimal(error);
    line.append(b"\n");
    emit::emit(output, line.bytes(), 121);
    unsafe { abi::ExitProcess(0) }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
