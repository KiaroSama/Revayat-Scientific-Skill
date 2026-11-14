//! Bounded fixed fixture transport. No allocation, formatting runtime or input selector.
use super::abi::{self, Handle};
pub fn emit(output: Handle, bytes: &[u8], failure: u32) {
    let mut written = 0;
    // SAFETY: output is the inherited fixture stdout; bytes stay live for this synchronous write.
    if output.is_null()
        || output as usize == usize::MAX
        || bytes.len() > 256
        || unsafe {
            abi::WriteFile(
                output,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut written,
                core::ptr::null_mut(),
            )
        } == 0
        || written as usize != bytes.len()
    {
        unsafe { abi::ExitProcess(failure) }
    }
}
pub struct Record {
    bytes: [u8; 256],
    length: usize,
}
impl Record {
    pub const fn new() -> Self {
        Self {
            bytes: [0; 256],
            length: 0,
        }
    }
    pub fn append(&mut self, value: &[u8]) {
        if value.len() > self.bytes.len() - self.length {
            unsafe { abi::ExitProcess(121) }
        }
        for byte in value {
            self.bytes[self.length] = *byte;
            self.length += 1;
        }
    }
    pub fn hexadecimal(&mut self, value: u32) {
        for shift in (0..8).rev() {
            self.append(&[b"0123456789ABCDEF"[((value >> (shift * 4)) & 15) as usize]]);
        }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}
