#![no_std]
#![no_main]
#![allow(dead_code)]
#![deny(unsafe_op_in_unsafe_fn)]
mod abi;
mod builtins;
#[path = "role.rs"]
mod role;
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
