//! Optional transport inputs preserve the original null/first-predicate boundary.
use super::{SESSION_CAPACITY, SESSION_NAME, SessionSnapshot};
use crate::windows_security::sxs::safe_stage;
use anyhow::Result;
#[derive(Clone, Copy, Debug)]
pub enum Predicate {
    Length,
    Header,
    Offsets,
    TextOffset,
    Terminator,
    Selection,
    Present,
    Handle,
    Guid,
    Name,
    Path,
    Mode,
}
impl Predicate {
    pub fn label(self) -> &'static str {
        match self {
            Self::Length => "length",
            Self::Header => "header",
            Self::Offsets => "offsets",
            Self::TextOffset => "textoffset",
            Self::Terminator => "terminator",
            Self::Selection => "selection",
            Self::Present => "present",
            Self::Handle => "handle",
            Self::Guid => "guid",
            Self::Name => "name",
            Self::Path => "path",
            Self::Mode => "mode",
        }
    }
}
impl TryFrom<i32> for Predicate {
    type Error = anyhow::Error;
    fn try_from(value: i32) -> Result<Self> {
        Ok(match value {
            0 => Self::Length,
            1 => Self::Header,
            2 => Self::Offsets,
            3 => Self::TextOffset,
            4 => Self::Terminator,
            5 => Self::Selection,
            6 => Self::Present,
            7 => Self::Handle,
            8 => Self::Guid,
            9 => Self::Name,
            10 => Self::Path,
            11 => Self::Mode,
            _ => anyhow::bail!("unsupported fixed SxS session predicate"),
        })
    }
}
pub fn need(value: bool, predicate: Predicate) -> Result<()> {
    if !value {
        return Err(safe_stage(
            anyhow::anyhow!("fixed SxS session predicate rejected"),
            format!("session-predicate check={}", predicate.label()),
        ));
    }
    Ok(())
}
pub fn at_start<T>(raw: i32, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let label = match raw {
        0 => "initial",
        1 => "intent",
        2 => "start-tool",
        3 => "post-tool",
        4 => "bind",
        5 => "post-bind",
        6 => "bind-save",
        _ => anyhow::bail!("unsupported fixed SxS start stage"),
    };
    operation().map_err(|error| super::super::safe(error, label))
}
pub fn decode_optional(bytes: Option<&[u8]>) -> Result<SessionSnapshot> {
    need(
        bytes.is_some_and(|bytes| bytes.len() == SESSION_CAPACITY),
        Predicate::Length,
    )?;
    let bytes = bytes.unwrap();
    need(
        super::dword(bytes, 0) == SESSION_CAPACITY as u32,
        Predicate::Header,
    )?;
    need(
        super::dword(bytes, 112) == 2168 && super::dword(bytes, 116) == 120,
        Predicate::Offsets,
    )?;
    Ok(SessionSnapshot {
        handle: u64::from_le_bytes(bytes[8..16].try_into()?),
        guid: bytes[24..40].try_into()?,
        name: text(bytes, 120)?,
        path: text(bytes, 2168)?,
        mode: super::dword(bytes, 64),
        buffer_kib: super::dword(bytes, 48),
        maximum_buffers: super::dword(bytes, 56),
        events_lost: super::dword(bytes, 88),
        log_lost: super::dword(bytes, 96),
        realtime_lost: super::dword(bytes, 100),
    })
}
pub fn text(bytes: &[u8], offset: usize) -> Result<String> {
    need(matches!(offset, 120 | 2168), Predicate::TextOffset)?;
    need(bytes.len() == SESSION_CAPACITY, Predicate::Length)?;
    let end = (offset..offset + 2048)
        .step_by(2)
        .find(|at| bytes[*at..*at + 2] == [0, 0]);
    need(end.is_some(), Predicate::Terminator)?;
    let mut units = bytes[offset..end.unwrap()]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|unit| u16::from_le_bytes(*unit))
        .collect::<Vec<_>>();
    let result = String::from_utf16(&units)
        .map_err(|error| super::super::safe(error.into(), "session-text-encoding"));
    units.fill(0);
    result
}
pub fn capture_optional(value: Option<&SessionSnapshot>) -> Result<()> {
    need(value.is_some(), Predicate::Present)?;
    let value = value.unwrap();
    if !(matches!(value.mode, 1 | 0x00400000)
        && value.buffer_kib != 0
        && value.maximum_buffers != 0
        && u64::from(value.buffer_kib) * u64::from(value.maximum_buffers) <= 16384
        && value.events_lost == 0
        && value.log_lost == 0
        && value.realtime_lost == 0)
    {
        return Err(safe_stage(
            anyhow::anyhow!("fixed SxS capture predicate rejected"),
            format!(
                "session-capture mode={:08X} buffer_kib={} maximum_buffers={} events_lost={} log_lost={} realtime_lost={}",
                value.mode,
                value.buffer_kib,
                value.maximum_buffers,
                value.events_lost,
                value.log_lost,
                value.realtime_lost
            ),
        ));
    }
    Ok(())
}
pub fn same_optional(
    expected: Option<&SessionSnapshot>,
    actual: Option<&SessionSnapshot>,
) -> Result<()> {
    need(expected.is_some() && actual.is_some(), Predicate::Present)?;
    let (expected, actual) = (expected.unwrap(), actual.unwrap());
    need(expected.handle == actual.handle, Predicate::Handle)?;
    need(expected.guid == actual.guid, Predicate::Guid)?;
    need(expected.name == actual.name, Predicate::Name)?;
    need(
        super::super::ordinal_path_equal(&expected.path, &actual.path)?,
        Predicate::Path,
    )?;
    need(expected.mode == actual.mode, Predicate::Mode)
}
pub fn select_optional<'a>(
    sessions: Option<&'a [SessionSnapshot]>,
    path: &str,
) -> Result<Option<&'a SessionSnapshot>> {
    need(
        sessions.is_some_and(|sessions| sessions.len() <= 256),
        Predicate::Selection,
    )?;
    let mut matches = Vec::new();
    for session in sessions.unwrap() {
        if session.name == SESSION_NAME || super::super::ordinal_path_equal(&session.path, path)? {
            matches.push(session);
        }
    }
    if matches.len() > 1 {
        return Err(safe_stage(
            anyhow::anyhow!("fixed SxS session match collision"),
            format!("session-selection matches={}", matches.len()),
        ));
    }
    let found = matches.first().copied();
    if let Some(found) = found {
        need(found.name == SESSION_NAME, Predicate::Name)?;
        need(
            super::super::ordinal_path_equal(&found.path, path)?,
            Predicate::Path,
        )?;
        need(found.handle != 0, Predicate::Handle)?;
        need(found.guid != [0; 16], Predicate::Guid)?;
    }
    Ok(found)
}
