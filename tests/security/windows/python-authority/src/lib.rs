//! Unreferenced C-API port. No admitted producer or native-execution claim exists.
//! A pinned, held-source/image producer and independent review are required before native use.
#![no_std]
#![no_main]
pub mod ascii;
pub mod body;
pub mod bootstrap;
#[path = "../../activation-fixture/src/native/builtins.rs"]
pub mod builtins;
pub mod child_wire;
pub mod classify;
pub mod ctypes;
pub mod descendant;
pub mod descendant_api;
pub mod entry;
pub mod failure;
pub mod ffi;
pub mod object;
pub mod registry;
pub mod small;
#[path = "../../activation-fixture/src/native/stack_probe.rs"]
pub mod stack_probe;
pub mod token;
pub mod wide;
pub mod wire;
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
