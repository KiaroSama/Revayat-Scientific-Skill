//! Bounded Application/SideBySide collection shared by the native adapter and source validators.
use super::{classify_event, safe};
use crate::windows_security::activation::Failures;
use anyhow::{Result, ensure};

#[derive(Clone, Copy, Debug, Default)]
pub struct Next {
    pub success: bool,
    pub count: u32,
    pub error: u32,
    pub handle: usize,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Rendered {
    pub success: bool,
    pub error: u32,
    pub bytes: u32,
    pub properties: u32,
}
/// Each non-null event and query handle transfers to exactly one `close` attempt. Output fields
/// remain visible when `next` fails, so an acquired event cannot escape cleanup during an error.
pub trait EventApi {
    fn query(&mut self) -> Result<usize>;
    fn next(&mut self, query: usize, timeout: u32, value: &mut Next) -> Result<()>;
    fn render(&mut self, item: usize, capacity: u32, data: usize) -> Result<Rendered>;
    fn allocate(&mut self, capacity: u32) -> Result<usize>;
    fn read(&mut self, data: usize, bytes: &mut [u8]) -> Result<()>;
    fn release(&mut self, data: usize, capacity: u32) -> Result<()>;
    fn close(&mut self, handle: usize) -> Result<()>;
    /// Read-only audit hook after the complete managed copy has been cleared, before release.
    fn decoded_bytes_cleared(&mut self, _bytes: &[u8]) {}
}
fn valid(handle: usize) -> bool {
    handle != 0 && handle != usize::MAX
}
fn flatten(error: anyhow::Error, errors: &mut Vec<anyhow::Error>) {
    match error.downcast::<Failures>() {
        Ok(group) if !group.errors.is_empty() => {
            for error in group.errors {
                flatten(error, errors);
            }
        }
        Ok(group) => errors.push(group.into()),
        Err(error) => errors.push(error),
    }
}
fn finish<T>(operation: Result<T>, cleanup: Result<()>) -> Result<T> {
    match cleanup {
        Ok(()) => operation,
        Err(error) => {
            let mut errors = Vec::new();
            if let Err(primary) = operation {
                flatten(primary, &mut errors);
            }
            flatten(error, &mut errors);
            Err(Failures { errors }.into())
        }
    }
}
/// Counterpart of StartupActivationEvents.UseNext, including partially acquired output cleanup.
pub fn use_next<A: EventApi>(
    api: &mut A,
    query: usize,
    timeout: u32,
    consume: impl FnOnce(&mut A, usize) -> Result<()>,
) -> Result<bool> {
    let mut value = Next::default();
    let operation = (|| {
        api.next(query, timeout, &mut value)?;
        if !value.success && value.error == 259 {
            ensure!(
                value.count == 0 && value.handle == 0,
                "fixed SxS event evidence contract failed"
            );
            return Ok(false);
        }
        ensure!(
            value.success && value.count == 1 && valid(value.handle),
            "fixed SxS event evidence contract failed"
        );
        consume(api, value.handle)?;
        Ok(true)
    })();
    let cleanup = if valid(value.handle) {
        api.close(value.handle)
    } else {
        Ok(())
    };
    finish(operation, cleanup)
}
pub fn enumerate(
    mut next: impl FnMut() -> Result<bool>,
    mut consume: impl FnMut() -> Result<()>,
) -> Result<()> {
    for count in 0..=16 {
        if !next()? {
            return Ok(());
        }
        ensure!(count < 16, "fixed SxS event evidence contract failed");
        consume()?;
    }
    Ok(())
}
pub fn required_bytes(value: Rendered) -> Result<u32> {
    ensure!(
        !value.success
            && value.error == 122
            && (4..=65536).contains(&value.bytes)
            && value.bytes.is_multiple_of(2)
            && value.properties == 0,
        "fixed SxS event evidence contract failed"
    );
    Ok(value.bytes)
}
pub fn decode(bytes: &[u8], used: u32, capacity: u32, properties: u32) -> Result<String> {
    ensure!(
        used >= 4
            && used <= capacity
            && used as usize == bytes.len()
            && used.is_multiple_of(2)
            && properties == 0
            && bytes[bytes.len() - 2..] == [0, 0],
        "fixed SxS event evidence contract failed"
    );
    let mut units = bytes[..bytes.len() - 2]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|unit| u16::from_le_bytes(*unit))
        .collect::<Vec<_>>();
    let decoded = String::from_utf16(&units)
        .map_err(|_| anyhow::anyhow!("fixed SxS event evidence contract failed"));
    units.fill(0);
    let text = decoded?;
    ensure!(
        !text.contains('\0'),
        "fixed SxS event evidence contract failed"
    );
    Ok(text)
}
fn render(
    api: &mut impl EventApi,
    item: usize,
    total: &mut u32,
    deadline: &mut impl FnMut() -> Result<()>,
) -> Result<String> {
    deadline()?;
    let capacity = required_bytes(api.render(item, 0, 0)?)?;
    ensure!(
        *total <= 262144 - capacity,
        "fixed SxS event evidence contract failed"
    );
    *total += capacity;
    let data = api.allocate(capacity)?;
    ensure!(valid(data), "fixed SxS event evidence contract failed");
    let mut bytes = Vec::new();
    let operation = (|| {
        deadline()?;
        let rendered = api.render(item, capacity, data)?;
        ensure!(
            rendered.success
                && rendered.bytes >= 4
                && rendered.bytes <= capacity
                && rendered.bytes.is_multiple_of(2)
                && rendered.properties == 0,
            "fixed SxS event evidence contract failed"
        );
        bytes.try_reserve_exact(rendered.bytes as usize)?;
        bytes.resize(rendered.bytes as usize, 0);
        api.read(data, &mut bytes)?;
        decode(&bytes, rendered.bytes, capacity, rendered.properties)
    })();
    for byte in &mut bytes {
        // SAFETY: each pointer addresses its unique initialized byte; volatile clearing survives
        // optimization even when the adapter's read-only audit hook is a no-op.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    api.decoded_bytes_cleared(&bytes);
    finish(operation, api.release(data, capacity))
}
/// Actual collection returns only fixed classification/summary metadata. No raw event XML escapes.
pub fn collect(
    api: &mut impl EventApi,
    image: &str,
    start: &str,
    end: &str,
    mut deadline: impl FnMut() -> Result<()>,
    mut timeout: impl FnMut() -> u32,
) -> Result<Vec<String>> {
    let query = api.query()?;
    ensure!(valid(query), "fixed SxS event evidence contract failed");
    let mut lines = Vec::new();
    let mut scanned = 0u32;
    let mut total = 0;
    let pending = std::cell::RefCell::new(None);
    let operation = (|| {
        enumerate(
            || {
                deadline()?;
                use_next(api, query, timeout(), |api, handle| {
                    deadline()?;
                    ensure!(scanned < 16, "fixed SxS event evidence contract failed");
                    let xml = render(api, handle, &mut total, &mut deadline)?;
                    *pending.borrow_mut() = classify_event(&xml, image, start, end)?;
                    scanned += 1;
                    Ok(())
                })
            },
            || {
                if let Some(line) = pending.borrow_mut().take() {
                    lines.push(line);
                }
                Ok(())
            },
        )?;
        deadline()
    })();
    finish(operation, api.close(query))?;
    lines.push(format!("WINDOWS_SXS_EVENTS phase=modified-preflight scanned_count={scanned} selected_count={} status={} producer_verified=False cause_claimed=False",
        lines.len(), if lines.is_empty() {"inconclusive_no_match"} else {"evidence_present"}));
    Ok(lines)
}

/// Builds the fixed local query only from UTC timestamps in a window of at most five minutes.
pub fn query_text(start: &str, end: &str) -> Result<String> {
    fn ticks(value: [u32; 7]) -> u64 {
        let [year, month, day, hour, minute, second, fraction] = value;
        let previous = u64::from(year - 1);
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let months = [
            31u64,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let days = 365 * previous + previous / 4 - previous / 100
            + previous / 400
            + months[..month as usize - 1].iter().sum::<u64>()
            + u64::from(day - 1);
        (((days * 24 + u64::from(hour)) * 60 + u64::from(minute)) * 60 + u64::from(second))
            * 10_000_000
            + u64::from(fraction)
    }
    let from = ticks(super::events::timestamp(start)?);
    let to = ticks(super::events::timestamp(end)?);
    ensure!(
        to >= from && to - from <= 300 * 10_000_000,
        "fixed SxS event query window differs"
    );
    Ok(format!(
        "*[System[Provider[@Name='SideBySide'] and TimeCreated[@SystemTime>='{start}' and @SystemTime<='{end}']]]"
    ))
}

#[path = "event_validation.rs"]
mod validation;
pub use validation::check_startup_events_validation;
