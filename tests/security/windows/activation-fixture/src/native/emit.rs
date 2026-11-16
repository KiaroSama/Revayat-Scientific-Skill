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
        if self.length > self.bytes.len()
            || value.len() > self.bytes.len().wrapping_sub(self.length)
        {
            unsafe { abi::ExitProcess(121) }
        }
        for byte in value {
            let Some(target) = self.bytes.get_mut(self.length) else {
                unsafe { abi::ExitProcess(121) }
            };
            *target = *byte;
            self.length = self.length.wrapping_add(1);
        }
    }
    pub fn hexadecimal(&mut self, value: u32) {
        let [first, second, third, fourth] = value.to_be_bytes();
        self.hexadecimal_byte(first);
        self.hexadecimal_byte(second);
        self.hexadecimal_byte(third);
        self.hexadecimal_byte(fourth);
    }
    fn hexadecimal_byte(&mut self, value: u8) {
        self.hexadecimal_digit(value >> 4);
        self.hexadecimal_digit(value & 15);
    }
    fn hexadecimal_digit(&mut self, digit: u8) {
        let byte = if digit < 10 {
            b'0'.wrapping_add(digit)
        } else {
            b'A'.wrapping_add(digit.wrapping_sub(10))
        };
        self.append(&[byte]);
    }
    pub fn bytes(&self) -> &[u8] {
        let Some(bytes) = self.bytes.get(..self.length) else {
            unsafe { abi::ExitProcess(121) }
        };
        bytes
    }
}
