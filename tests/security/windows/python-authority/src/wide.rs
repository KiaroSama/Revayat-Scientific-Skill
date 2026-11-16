//! Bounded UTF-8 name composition; token/registry authority still uses actual Python encoding.
use super::object::{Fault, Result, require};
pub struct Name {
    bytes: [u8; 8192],
    length: usize,
}
impl Name {
    pub fn new() -> Self {
        Self {
            bytes: [0; 8192],
            length: 0,
        }
    }
    pub fn push(&mut self, text: &str) -> Result<()> {
        require(text.len() <= self.bytes.len() - self.length)?;
        self.bytes
            .get_mut(self.length..self.length + text.len())
            .ok_or(Fault::Control)?
            .copy_from_slice(text.as_bytes());
        self.length += text.len();
        Ok(())
    }
    pub fn text(&self) -> Result<&str> {
        let bytes = self.bytes.get(..self.length).ok_or(Fault::Control)?;
        // Every pushed fragment is &str and fragments are never split.
        Ok(unsafe { core::str::from_utf8_unchecked(bytes) })
    }
}
impl Drop for Name {
    fn drop(&mut self) {
        self.bytes.fill(0);
        self.length = 0;
    }
}
