//! Bounded ETW property decoding and identity comparison. No session is started by this module.
use super::PrivateFailure;
use anyhow::Result;

pub const SESSION_CAPACITY: usize = 4216;
pub const SESSION_NAME: &str = "WinSxs Trace Session";
fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
#[derive(Clone)]
pub struct SessionSnapshot {
    pub handle: u64,
    pub guid: [u8; 16],
    pub name: String,
    pub path: String,
    pub mode: u32,
    pub buffer_kib: u32,
    pub maximum_buffers: u32,
    pub events_lost: u32,
    pub log_lost: u32,
    pub realtime_lost: u32,
}
impl SessionSnapshot {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        contract::decode_optional(Some(bytes))
    }
    pub fn require_capture(&self) -> Result<()> {
        contract::capture_optional(Some(self))
    }
    pub fn require_same(&self, actual: &Self) -> Result<()> {
        contract::same_optional(Some(self), Some(actual))
    }
}
pub fn select_session<'a>(
    sessions: &'a [SessionSnapshot],
    path: &str,
) -> Result<Option<&'a SessionSnapshot>> {
    contract::select_optional(Some(sessions), path)
}
pub fn require_enumeration(status: u32, count: u32) -> Result<()> {
    if status != 0 || count > 256 {
        return Err(PrivateFailure {
            stage: format!("session-enumeration win32={status:08X} count={count}").into(),
            original: anyhow::anyhow!("fixed SxS session enumeration failed"),
        }
        .into());
    }
    Ok(())
}

#[path = "session_checks.rs"]
mod checks;
#[path = "session_contract.rs"]
pub mod contract;
pub use checks::check_validation;
