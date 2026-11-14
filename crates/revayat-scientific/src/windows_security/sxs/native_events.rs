//! Actual Windows Event Log adapter. An empty query is inconclusive, never visibility evidence.
use super::event_collector::{EventApi, Next, Rendered, collect, query_text};
use crate::windows_security::activation::diagnostics::{self, Numbers, Stage};
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    ffi::c_void,
    path::Path,
    time::{Duration, Instant},
};
#[link(name = "wevtapi")]
unsafe extern "system" {
    fn EvtQuery(
        session: *mut c_void,
        path: *const u16,
        query: *const u16,
        flags: u32,
    ) -> *mut c_void;
    fn EvtNext(
        query: *mut c_void,
        capacity: u32,
        events: *mut *mut c_void,
        timeout: u32,
        flags: u32,
        returned: *mut u32,
    ) -> i32;
    fn EvtRender(
        context: *mut c_void,
        fragment: *mut c_void,
        flags: u32,
        capacity: u32,
        buffer: *mut c_void,
        used: *mut u32,
        properties: *mut u32,
    ) -> i32;
    fn EvtClose(handle: *mut c_void) -> i32;
}
#[repr(C)]
#[derive(Default)]
struct SystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    millisecond: u16,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
    fn GetSystemTimeAsFileTime(time: *mut u64);
    fn FileTimeToSystemTime(file: *const u64, time: *mut SystemTime) -> i32;
}
/// UTC timestamps include the complete Windows FILETIME fraction, for the exact observation window.
pub fn utc_now() -> Result<String> {
    let mut file = 0;
    let mut time = SystemTime::default();
    // SAFETY: both outputs have the exact native FILETIME/SYSTEMTIME layouts and writable storage.
    unsafe { GetSystemTimeAsFileTime(&mut file) };
    let success = unsafe { FileTimeToSystemTime(&file, &mut time) };
    let error = if success == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    if success == 0 {
        return Err(diagnostics::native(
            Stage::EvtClock,
            Numbers {
                native_error: error,
                ..Default::default()
            },
        ));
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:07}Z",
        time.year,
        time.month,
        time.day,
        time.hour,
        time.minute,
        time.second,
        file % 10_000_000
    ))
}
struct NativeEvents {
    query: Vec<u16>,
    // Owned aligned allocations remain initialized until the entire capacity is cleared/released.
    buffers: BTreeMap<usize, Vec<u16>>,
}
fn clear(buffer: &mut [u16]) {
    for unit in buffer {
        // SAFETY: each pointer addresses a unique initialized owned unit. Volatile stores ensure
        // the full native render capacity is cleared before its allocation is returned.
        unsafe { std::ptr::write_volatile(unit, 0) };
    }
}
impl Drop for NativeEvents {
    fn drop(&mut self) {
        for buffer in self.buffers.values_mut() {
            clear(buffer);
        }
    }
}
impl EventApi for NativeEvents {
    fn query(&mut self) -> Result<usize> {
        let channel = "Application"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        // SAFETY: fixed local channel, validated bounded query, live terminated UTF-16 storage.
        let handle = unsafe {
            EvtQuery(
                std::ptr::null_mut(),
                channel.as_ptr(),
                self.query.as_ptr(),
                0x201,
            )
        };
        let error = if handle.is_null() {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        if handle.is_null() || handle as usize == usize::MAX {
            return Err(diagnostics::native(
                Stage::EvtQuery,
                Numbers {
                    native_error: error,
                    ..Default::default()
                },
            ));
        }
        Ok(handle as usize)
    }
    fn next(&mut self, query: usize, timeout: u32, value: &mut Next) -> Result<()> {
        let mut handle = std::ptr::null_mut();
        let mut returned = 0;
        // SAFETY: query is retained by collect; one writable event slot and count are provided.
        let success = unsafe {
            EvtNext(
                query as *mut c_void,
                1,
                &mut handle,
                timeout,
                0,
                &mut returned,
            )
        };
        let error = if success == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        *value = Next {
            success: success != 0,
            count: returned,
            error,
            handle: handle as usize,
        };
        if success == 0 && error != 259
            || success != 0 && (returned != 1 || handle.is_null() || handle as usize == usize::MAX)
        {
            return Err(diagnostics::native(
                Stage::EvtNext,
                Numbers {
                    native_error: Some(error),
                    result: Some(success as u32),
                    count: Some(returned),
                    ..Default::default()
                },
            ));
        }
        Ok(())
    }
    fn render(&mut self, item: usize, capacity: u32, data: usize) -> Result<Rendered> {
        if capacity == 0 {
            ensure!(data == 0, "event sizing unexpectedly supplied a buffer");
        } else {
            ensure!(
                self.buffers
                    .get(&data)
                    .is_some_and(|buffer| buffer.len() * 2 == capacity as usize),
                "event render allocation identity differs"
            );
        }
        let mut used = 0;
        let mut properties = 0;
        // SAFETY: retained event, or the exact owned initialized buffer capacity verified above.
        // EvtRenderEventXml (1) produces UTF-16 XML including its terminating zero.
        let success = unsafe {
            EvtRender(
                std::ptr::null_mut(),
                item as *mut c_void,
                1,
                capacity,
                data as *mut c_void,
                &mut used,
                &mut properties,
            )
        };
        let error = if success == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        let rendered = Rendered {
            success: success != 0,
            error,
            bytes: used,
            properties,
        };
        let valid = if capacity == 0 {
            success == 0
                && error == 122
                && (4..=65536).contains(&used)
                && used.is_multiple_of(2)
                && properties == 0
        } else {
            success != 0
                && used >= 4
                && used <= capacity
                && used.is_multiple_of(2)
                && properties == 0
        };
        if !valid {
            return Err(diagnostics::native(
                if capacity == 0 {
                    Stage::EvtSize
                } else {
                    Stage::EvtRender
                },
                Numbers {
                    native_error: Some(error),
                    result: Some(success as u32),
                    bytes: Some(used),
                    properties: Some(properties),
                    ..Default::default()
                },
            ));
        }
        Ok(rendered)
    }
    fn allocate(&mut self, capacity: u32) -> Result<usize> {
        ensure!(
            (4..=65536).contains(&capacity) && capacity.is_multiple_of(2),
            "event allocation size differs"
        );
        let mut buffer = Vec::<u16>::new();
        buffer
            .try_reserve_exact(capacity as usize / 2)
            .map_err(|error| diagnostics::at(error.into(), Stage::EvtAllocate))?;
        buffer.resize(capacity as usize / 2, 0);
        let data = buffer.as_mut_ptr() as usize;
        ensure!(
            data != 0 && data != usize::MAX && !self.buffers.contains_key(&data),
            "event allocation identity collided"
        );
        self.buffers.insert(data, buffer);
        Ok(data)
    }
    fn read(&mut self, data: usize, bytes: &mut [u8]) -> Result<()> {
        let buffer = self
            .buffers
            .get(&data)
            .ok_or_else(|| anyhow::anyhow!("event read allocation missing"))?;
        ensure!(
            bytes.len() <= buffer.len() * 2,
            "event read exceeds owned allocation"
        );
        // SAFETY: initialized u16 backing allocation; requested byte extent is checked above.
        let source =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), bytes.len()) };
        bytes.copy_from_slice(source);
        Ok(())
    }
    fn release(&mut self, data: usize, capacity: u32) -> Result<()> {
        let mut buffer = self
            .buffers
            .remove(&data)
            .ok_or_else(|| anyhow::anyhow!("event allocation already released"))?;
        let qualified = buffer.len() * 2 == capacity as usize;
        clear(&mut buffer);
        ensure!(qualified, "event release capacity changed");
        Ok(())
    }
    fn close(&mut self, handle: usize) -> Result<()> {
        // SAFETY: collect/use_next transfers one retained event or query handle exactly once.
        let success = unsafe { EvtClose(handle as *mut c_void) };
        let error = if success == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        if success == 0 {
            return Err(diagnostics::native(
                Stage::EvtClose,
                Numbers {
                    native_error: error,
                    ..Default::default()
                },
            ));
        }
        Ok(())
    }
    fn classify(
        &mut self,
        xml: &str,
        image: &str,
        start: &str,
        end: &str,
    ) -> Result<Option<String>> {
        super::classify_event(xml, image, start, end)
            .map_err(|error| diagnostics::at(error, Stage::EvtClassify))
    }
}
/// Queries the real local Application log after the caller has restored its intervention.
/// Returned metadata never attests producer identity, a child-visible event, or a causal explanation.
pub fn observe_startup_events(image: &Path, start: &str, end: &str) -> Result<Vec<String>> {
    let operation = (|| {
        super::super::activation::native::require_host()?;
        ensure!(
            image.is_absolute()
                && image
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case("python.exe")),
            "fixed SxS event query requires prepared Python identity"
        );
        let image = image
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("event image is not Unicode"))?;
        let query =
            query_text(start, end).map_err(|error| diagnostics::at(error, Stage::EvtClock))?;
        let mut api = NativeEvents {
            query: query.encode_utf16().chain(Some(0)).collect(),
            buffers: BTreeMap::new(),
        };
        let clock = Instant::now();
        collect(
            &mut api,
            image,
            start,
            end,
            || {
                ensure!(
                    clock.elapsed() < Duration::from_secs(5),
                    "fixed SxS query deadline exceeded"
                );
                Ok(())
            },
            || {
                5000u128
                    .saturating_sub(clock.elapsed().as_millis())
                    .min(1000) as u32
            },
        )
    })();
    operation.map_err(|error| super::safe(error, "event-evidence"))
}
