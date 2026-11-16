//! Entry marker only: the loader must process the external Python ID1 payload first.
use super::{abi, emit::emit};
pub fn run() -> ! {
    let output = unsafe { abi::GetStdHandle(-11i32 as u32) };
    emit(
        output,
        b"WINDOWS_DEFAULT_ACTIVATION_ENTRY reached=True\n",
        121,
    );
    unsafe { abi::ExitProcess(0) }
}
