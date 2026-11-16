//! Exact session receipts and stop ordering. Native callers supply their real query/stop operations.
use super::{SESSION_NAME, SessionSnapshot, select_session};
use anyhow::{Result, ensure};

pub fn stop_owned(
    logfile: &str,
    starter_reaped: bool,
    capture: bool,
    expected: Option<&SessionSnapshot>,
    mut all: impl FnMut() -> Result<Vec<SessionSnapshot>>,
    mut query: impl FnMut() -> Result<Option<SessionSnapshot>>,
    stop: impl FnOnce(&SessionSnapshot) -> Result<SessionSnapshot>,
) -> Result<()> {
    ensure!(starter_reaped, "SxS starter has not been reaped");
    let sessions = all()?;
    let found = select_session(&sessions, logfile)?;
    let queried = query()?;
    let Some(found) = found else {
        ensure!(
            queried.is_none() && !capture,
            "SxS session absence is unqualified"
        );
        return Ok(());
    };
    found.require_same(
        queried
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SxS session query disagrees with enumeration"))?,
    )?;
    if let Some(expected) = expected {
        expected.require_same(found)?;
    }
    // Unbound recovery is valid only behind the caller's preabsence/private-log/exclusive-owner gate.
    let stopped = stop(found)?;
    ensure!(
        query()?.is_none() && select_session(&all()?, logfile)?.is_none(),
        "SxS session remains after stop"
    );
    if capture {
        stopped.require_capture()?;
    }
    Ok(())
}
fn identifier(run: &str) -> Result<()> {
    ensure!(
        run.len() == 32
            && run
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid SxS run identity"
    );
    Ok(())
}
fn volume(volume: &str) -> Result<()> {
    let bytes = volume.as_bytes();
    ensure!(
        bytes.len() == 3
            && (b'D'..=b'Z').contains(&bytes[0].to_ascii_uppercase())
            && bytes[1] == b':'
            && bytes[2] == b'\\',
        "SxS volume is outside the fixed owned drive profile"
    );
    Ok(())
}
pub fn intent_text(run: &str, drive: &str) -> Result<String> {
    identifier(run)?;
    volume(drive)?;
    Ok(format!("sxs-intent-v1\n{run}\n{drive}\n"))
}
pub fn intent_volume(text: &str, run: &str) -> Result<String> {
    identifier(run)?;
    ensure!(text.len() <= 2048, "SxS intent exceeds bound");
    let fields: Vec<_> = text.split('\n').collect();
    ensure!(
        fields.len() == 4
            && fields[0] == "sxs-intent-v1"
            && fields[1] == run
            && fields[3].is_empty(),
        "SxS intent binding differs"
    );
    volume(fields[2])?;
    Ok(fields[2].to_owned())
}
fn guid_text(bytes: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}
fn parse_guid(text: &str) -> Result<[u8; 16]> {
    ensure!(
        text.len() == 36
            && text
                .bytes()
                .enumerate()
                .all(|(i, b)| if matches!(i, 8 | 13 | 18 | 23) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }),
        "invalid SxS GUID"
    );
    let compact = text.replace('-', "");
    let mut bytes = [0; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)?;
    }
    bytes[..4].reverse();
    bytes[4..6].reverse();
    bytes[6..8].reverse();
    ensure!(bytes != [0; 16], "empty SxS GUID");
    Ok(bytes)
}
pub fn bound_text(run: &str, found: &SessionSnapshot) -> Result<String> {
    identifier(run)?;
    ensure!(
        found.handle != 0 && found.guid != [0; 16],
        "SxS bound identity is absent"
    );
    Ok(format!(
        "sxs-bound-v1\n{run}\n{:016X}\n{}\n{:08X}\n",
        found.handle,
        guid_text(&found.guid),
        found.mode
    ))
}
pub fn decode_bound(text: &str, run: &str, logfile: &str) -> Result<SessionSnapshot> {
    identifier(run)?;
    ensure!(text.len() <= 2048, "SxS bound receipt exceeds limit");
    let fields: Vec<_> = text.split('\n').collect();
    ensure!(
        fields.len() == 6
            && fields[0] == "sxs-bound-v1"
            && fields[1] == run
            && fields[5].is_empty(),
        "SxS bound receipt binding differs"
    );
    let handle = u64::from_str_radix(fields[2], 16)?;
    let mode = u32::from_str_radix(fields[4], 16)?;
    ensure!(
        handle != 0 && fields[2] == format!("{handle:016X}") && fields[4] == format!("{mode:08X}"),
        "noncanonical SxS bound scalars"
    );
    Ok(SessionSnapshot {
        handle,
        guid: parse_guid(fields[3])?,
        mode,
        name: SESSION_NAME.to_owned(),
        path: logfile.to_owned(),
        buffer_kib: 0,
        maximum_buffers: 0,
        events_lost: 0,
        log_lost: 0,
        realtime_lost: 0,
    })
}
