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
mod emit;

/// The owned launcher supplies one quoted executable and no selectors. The first
/// argument has Windows' special executable-name grammar; backslashes are literal.
pub fn no_arguments(mut unit: impl FnMut(usize) -> Option<u16>) -> bool {
    if unit(0) != Some(u16::from(b'"')) {
        return false;
    }
    let mut content = false;
    let mut closed = false;
    let mut index = 1usize;
    while index < 32767 {
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
        index = index.wrapping_add(1);
    }
    false
}

/// Exactly eight uppercase hexadecimal bytes, without table/slice indexing,
/// checked arithmetic or a formatting runtime. The callback cannot select input.
pub fn hexadecimal(mut value: u32, mut byte: impl FnMut(u8)) {
    let mut remaining = 8u32;
    while remaining != 0 {
        let nibble = (value >> 28) as u8;
        byte(if nibble < 10 {
            b'0'.wrapping_add(nibble)
        } else {
            b'A'.wrapping_add(nibble.wrapping_sub(10))
        });
        value <<= 4;
        remaining = remaining.wrapping_sub(1);
    }
}

#[cfg(not(test))]
fn emit_byte(output: abi::Handle, byte: u8) {
    let mut written = 0;
    // SAFETY: live one-byte local and synchronous inherited stdout; no slice or
    // buffer construction can introduce a core bounds/panic dependency.
    if unsafe { abi::WriteFile(output, &byte, 1, &mut written, core::ptr::null_mut()) } == 0
        || written != 1
    {
        unsafe { abi::ExitProcess(121) }
    }
}

#[cfg(not(test))]
fn command_unit(command: *const u16, index: usize) -> u16 {
    let value: u16;
    // SAFETY: GetCommandLineW owns the nonnull UTF-16 process string. The only
    // caller bounds index below32767 and stops at its first terminator. This
    // x64 load avoids compiler-inserted debug dereference panic linkage; it
    // changes no pointer admission or command-line bound.
    unsafe {
        core::arch::asm!("mov {value:x}, word ptr [{pointer}]",
            value = out(reg) value, pointer = in(reg) command.wrapping_add(index),
            options(readonly, nostack, preserves_flags));
    }
    value
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
            Some(command_unit(command, index))
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
    emit::emit(
        output,
        b"WINDOWS_EXPLICIT_ID2_ACTIVATION entry_reached=True created=",
        121,
    );
    emit::emit(output, if created { b"True" } else { b"False" }, 121);
    emit::emit(output, b" win32_error=0x", 121);
    hexadecimal(error, |byte| emit_byte(output, byte));
    emit::emit(output, b"\n", 121);
    unsafe { abi::ExitProcess(0) }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
