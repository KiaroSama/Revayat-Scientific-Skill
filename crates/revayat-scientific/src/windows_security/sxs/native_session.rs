//! Fixed standard-tool ETW session owner. Never starts a session or enables a provider itself.
use super::{
    SESSION_CAPACITY, SESSION_NAME, SessionSnapshot, require_enumeration, select_session,
    stop_owned,
};
use anyhow::{Result, ensure};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};
use std::{cell::Cell, ffi::c_void};
type Handle = *mut c_void;
#[link(name = "advapi32")]
unsafe extern "system" {
    fn ControlTraceW(handle: u64, name: *const u16, properties: Handle, operation: u32) -> u32;
    fn QueryAllTracesW(properties: *mut Handle, count: u32, returned: *mut u32) -> u32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateMutexW(security: Handle, owner: i32, name: *const u16) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
}
fn allocation() -> Vec<u64> {
    let mut bytes = vec![0; SESSION_CAPACITY / 8];
    let raw = unsafe {
        std::slice::from_raw_parts_mut(bytes.as_mut_ptr().cast::<u8>(), SESSION_CAPACITY)
    };
    for (at, value) in [(0, SESSION_CAPACITY as u32), (112, 2168), (116, 120)] {
        raw[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}
fn decode(bytes: &[u64]) -> Result<SessionSnapshot> {
    SessionSnapshot::decode(unsafe {
        std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), SESSION_CAPACITY)
    })
}
pub(super) struct SessionOwner {
    mutex: Handle,
    started: Cell<Instant>,
    cleanup: Cell<bool>,
}
impl SessionOwner {
    pub fn acquire() -> Result<Self> {
        super::super::activation::native::require_host()?;
        let name = "Local\\Scientific.Security.SxsTrace\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        let mutex = unsafe { CreateMutexW(null_mut(), 0, name.as_ptr()) };
        // CreateMutex signals an existing named object through last-error even on success.
        let error = unsafe { GetLastError() };
        if mutex.is_null() {
            anyhow::bail!("SxS exclusive owner creation failed winerror={error}");
        }
        let mut owner = Self {
            mutex,
            started: Cell::new(Instant::now()),
            cleanup: Cell::new(false),
        };
        if error == 183 {
            let result = owner.close();
            ensure!(result.is_ok(), "SxS owner collision cleanup failed");
            anyhow::bail!("SxS trace owner collision");
        }
        Ok(owner)
    }
    fn deadline(&self) -> Result<()> {
        ensure!(
            self.started.get().elapsed()
                < Duration::from_secs(if self.cleanup.get() { 5 } else { 30 }),
            "SxS session owner deadline exceeded"
        );
        super::super::activation::native::require_host()
    }
    pub fn all(&self) -> Result<Vec<SessionSnapshot>> {
        self.deadline()?;
        let mut allocations = (0..256).map(|_| allocation()).collect::<Vec<_>>();
        let mut pointers = allocations
            .iter_mut()
            .map(|a| a.as_mut_ptr().cast::<c_void>())
            .collect::<Vec<_>>();
        let mut returned = 0;
        let status = unsafe { QueryAllTracesW(pointers.as_mut_ptr(), 256, &mut returned) };
        let result = (|| {
            require_enumeration(status, returned)?;
            allocations[..returned as usize]
                .iter()
                .map(|bytes| decode(bytes))
                .collect()
        })();
        for bytes in &mut allocations {
            bytes.fill(0);
        }
        result
    }
    pub fn query(&self) -> Result<Option<SessionSnapshot>> {
        self.deadline()?;
        let mut properties = allocation();
        let name = SESSION_NAME
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let status = unsafe { ControlTraceW(0, name.as_ptr(), properties.as_mut_ptr().cast(), 0) };
        let result = (|| {
            if status == 4201 {
                return Ok(None);
            }
            ensure!(
                status == 0,
                "SxS fixed session query failed winerror={status}"
            );
            decode(&properties).map(Some)
        })();
        properties.fill(0);
        result
    }
    pub fn preabsent(&self, logfile: &str) -> Result<()> {
        ensure!(
            select_session(&self.all()?, logfile)?.is_none() && self.query()?.is_none(),
            "pre-existing SxS session collision"
        );
        Ok(())
    }
    pub fn bind(&self, logfile: &str) -> Result<SessionSnapshot> {
        let sessions = self.all()?;
        let selected = select_session(&sessions, logfile)?
            .ok_or_else(|| anyhow::anyhow!("SxS standard-tool session is absent"))?;
        let queried = self
            .query()?
            .ok_or_else(|| anyhow::anyhow!("SxS named session is absent"))?;
        selected.require_same(&queried)?;
        selected.require_capture()?;
        Ok(selected.clone())
    }
    pub fn stop(
        &self,
        logfile: &str,
        starter_reaped: bool,
        capture: bool,
        expected: Option<&SessionSnapshot>,
    ) -> Result<()> {
        ensure!(
            !self.cleanup.replace(true),
            "SxS session stop already attempted"
        );
        self.started.set(Instant::now());
        stop_owned(
            logfile,
            starter_reaped,
            capture,
            expected,
            || self.all(),
            || self.query(),
            |found| {
                self.deadline()?;
                let mut properties = allocation();
                let status = unsafe {
                    ControlTraceW(found.handle, null(), properties.as_mut_ptr().cast(), 1)
                };
                let result = if status == 0 {
                    decode(&properties)
                } else {
                    Err(anyhow::anyhow!(
                        "stop owned SxS session failed winerror={status}"
                    ))
                };
                properties.fill(0);
                result
            },
        )
    }
    pub fn close(&mut self) -> Result<()> {
        if self.mutex.is_null() {
            return Ok(());
        }
        let mutex = std::mem::replace(&mut self.mutex, null_mut());
        let success = unsafe { CloseHandle(mutex) };
        let error = if success == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        ensure!(
            success != 0,
            "SxS exclusive owner close failed winerror={error:?}"
        );
        Ok(())
    }
}
impl Drop for SessionOwner {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
