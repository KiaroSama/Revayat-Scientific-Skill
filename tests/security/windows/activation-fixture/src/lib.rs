//! Fixed explicit-ID2 fixture contracts, separate from target admission or Python equivalence.
pub mod resource;
pub use resource::MANIFEST;
pub const PRE_CALL: &[u8] = b"EXPLICIT_ID2_BEFORE_CALL\n";
#[repr(C)]
pub struct ActCtx {
    pub size: u32,
    pub flags: u32,
    pub source: usize,
    pub architecture: u16,
    pub language: u16,
    pub directory: usize,
    pub resource: usize,
    pub application: usize,
    pub module: usize,
}
impl ActCtx {
    pub fn explicit_id2(module: usize) -> Option<Self> {
        if module == 0 || module == usize::MAX {
            return None;
        }
        Some(Self {
            size: 56,
            flags: 0x88,
            source: 0,
            architecture: 0,
            language: 0,
            directory: 0,
            resource: 2,
            application: 0,
            module,
        })
    }
}
pub fn result(created: bool, error: u32) -> Option<String> {
    if created != (error == 0) {
        return None;
    }
    Some(format!(
        "WINDOWS_EXPLICIT_ID2_ACTIVATION entry_reached=True created={} win32_error=0x{error:08X}\n",
        if created { "True" } else { "False" }
    ))
}
#[cfg(test)]
mod tests;
