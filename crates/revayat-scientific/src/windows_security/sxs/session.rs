//! Bounded ETW property decoding and identity comparison. No session is started by this module.
use super::PrivateFailure;
use anyhow::Result;

pub const SESSION_CAPACITY: usize = 4216;
pub const SESSION_NAME: &str = "WinSxs Trace Session";
fn check(value: bool, stage: &'static str) -> Result<()> {
    if !value {
        return Err(PrivateFailure {
            stage,
            original: anyhow::anyhow!("fixed SxS session predicate rejected"),
        }
        .into());
    }
    Ok(())
}
fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn text(bytes: &[u8], offset: usize) -> Result<String> {
    let end = (offset..offset + 2048)
        .step_by(2)
        .find(|&i| bytes[i] == 0 && bytes[i + 1] == 0);
    check(end.is_some(), "session-terminator")?;
    let mut units = bytes[offset..end.unwrap()]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let result =
        String::from_utf16(&units).map_err(|e| super::safe(e.into(), "session-text-encoding"));
    units.fill(0);
    result
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
        check(bytes.len() == SESSION_CAPACITY, "session-length")?;
        check(dword(bytes, 0) == SESSION_CAPACITY as u32, "session-header")?;
        check(
            dword(bytes, 112) == 2168 && dword(bytes, 116) == 120,
            "session-offsets",
        )?;
        Ok(Self {
            handle: u64::from_le_bytes(bytes[8..16].try_into()?),
            guid: bytes[24..40].try_into()?,
            name: text(bytes, 120)?,
            path: text(bytes, 2168)?,
            mode: dword(bytes, 64),
            buffer_kib: dword(bytes, 48),
            maximum_buffers: dword(bytes, 56),
            events_lost: dword(bytes, 88),
            log_lost: dword(bytes, 96),
            realtime_lost: dword(bytes, 100),
        })
    }
    pub fn require_capture(&self) -> Result<()> {
        check(
            matches!(self.mode, 1 | 0x00400000)
                && self.buffer_kib != 0
                && self.maximum_buffers != 0
                && u64::from(self.buffer_kib) * u64::from(self.maximum_buffers) <= 16384
                && self.events_lost == 0
                && self.log_lost == 0
                && self.realtime_lost == 0,
            "session-capture",
        )
    }
    pub fn require_same(&self, actual: &Self) -> Result<()> {
        check(self.handle == actual.handle, "session-handle")?;
        check(self.guid == actual.guid, "session-guid")?;
        check(self.name == actual.name, "session-name")?;
        check(
            super::ordinal_path_equal(&self.path, &actual.path)?,
            "session-path",
        )?;
        check(self.mode == actual.mode, "session-mode")
    }
}
pub fn select_session<'a>(
    sessions: &'a [SessionSnapshot],
    path: &str,
) -> Result<Option<&'a SessionSnapshot>> {
    check(sessions.len() <= 256, "session-selection")?;
    let mut found = None;
    for session in sessions {
        if session.name == SESSION_NAME || super::ordinal_path_equal(&session.path, path)? {
            check(found.is_none(), "session-selection")?;
            found = Some(session);
        }
    }
    let Some(found) = found else {
        return Ok(None);
    };
    check(found.name == SESSION_NAME, "session-name")?;
    check(
        super::ordinal_path_equal(&found.path, path)?,
        "session-path",
    )?;
    check(found.handle != 0, "session-handle")?;
    check(found.guid != [0; 16], "session-guid")?;
    Ok(Some(found))
}
pub fn require_enumeration(status: u32, count: u32) -> Result<()> {
    check(status == 0 && count <= 256, "session-enumeration")
}
