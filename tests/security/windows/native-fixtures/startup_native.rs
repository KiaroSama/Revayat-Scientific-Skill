//! Fixed independent pass fixture. No CRT, target code, input or output.
#![no_std]
#![no_main]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn ExitProcess(code: u32) -> !;
}
#[unsafe(no_mangle)]
pub extern "system" fn StartupEntry() -> ! {
    unsafe { ExitProcess(0) }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
