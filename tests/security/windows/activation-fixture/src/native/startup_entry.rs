#![no_std]
#![no_main]
#![allow(dead_code)]
#![deny(unsafe_op_in_unsafe_fn)]
mod abi;
mod builtins;
mod config;
mod emit;
#[path = "role.rs"]
mod role;
#[unsafe(no_mangle)]
pub extern "system" fn StartupEntry() -> ! {
    role::run()
}
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // A trusted fixture contract failure faults the owned process, never reports success.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
