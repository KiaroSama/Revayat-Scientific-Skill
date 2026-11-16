//! Independent hosted debugger control; fixed exported literal and one real call.
#![no_std]
#![no_main]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn ExitProcess(code: u32) -> !;
}
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "system" fn DebugControlSite() -> u32 {
    0x53444331
}
#[unsafe(no_mangle)]
pub extern "system" fn StartupEntry() -> ! {
    // Volatile function-pointer presentation prevents interprocedural constant
    // propagation from eliding the actual noinline exported control call.
    let site = DebugControlSite as extern "system" fn() -> u32;
    let site = unsafe { core::ptr::read_volatile(&site) };
    unsafe { ExitProcess(u32::from(site() != 0x53444331)) }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
