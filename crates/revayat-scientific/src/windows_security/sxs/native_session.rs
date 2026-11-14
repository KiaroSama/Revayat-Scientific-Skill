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
pub(super) struct SessionOwner<'a> {
    mutex: Handle,
    started: Cell<Instant>,
    cleanup: Cell<bool>,
    journal: Option<crate::windows_security::native::SxsJournal<'a>>,
}
impl<'a> SessionOwner<'a> {
    pub fn acquire_ephemeral() -> Result<Self> {
        Self::acquire(None)
    }
    pub fn acquire_bound(view: &'a crate::windows_security::native::NativeRunView) -> Result<Self> {
        Self::acquire(Some(crate::windows_security::native::SxsJournal::new(
            view,
        )?))
    }
    fn acquire(journal: Option<crate::windows_security::native::SxsJournal<'a>>) -> Result<Self> {
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
            journal,
        };
        if error == 183 {
            let closed = owner.close().err().into_iter().collect();
            return super::native_identity::finish(
                Err(anyhow::anyhow!("SxS trace owner collision")),
                closed,
            );
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
    pub fn preabsent(&mut self, logfile: &str) -> Result<()> {
        ensure!(
            select_session(&self.all()?, logfile)?.is_none() && self.query()?.is_none(),
            "pre-existing SxS session collision"
        );
        if let Some(journal) = &mut self.journal {
            journal.intent(logfile)?;
        }
        Ok(())
    }
    pub fn bind(&mut self, logfile: &str) -> Result<SessionSnapshot> {
        let sessions = self.all()?;
        let selected = select_session(&sessions, logfile)?
            .ok_or_else(|| anyhow::anyhow!("SxS standard-tool session is absent"))?;
        let queried = self
            .query()?
            .ok_or_else(|| anyhow::anyhow!("SxS named session is absent"))?;
        selected.require_same(&queried)?;
        selected.require_capture()?;
        if let Some(journal) = &mut self.journal {
            super::session::contract::at_start(6, || journal.bind(selected))?;
        }
        Ok(selected.clone())
    }
    pub fn stop(
        &mut self,
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
        let saved = self
            .journal
            .as_ref()
            .map(|journal| journal.expected(logfile))
            .transpose()?
            .flatten();
        if let (Some(saved), Some(expected)) = (&saved, expected) {
            saved.require_same(expected)?;
        }
        stop_owned(
            logfile,
            starter_reaped,
            capture,
            saved.as_ref().or(expected),
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
        )?;
        if let Some(journal) = &mut self.journal {
            journal.stopped()?;
        }
        Ok(())
    }
    pub fn durable_pending(&self) -> Result<bool> {
        self.journal
            .as_ref()
            .map_or(Ok(false), |journal| journal.pending())
    }
    pub fn close(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if let Some(journal) = &mut self.journal
            && let Err(error) = journal.close()
        {
            errors.push(error);
        }
        if !self.mutex.is_null() {
            let mutex = std::mem::replace(&mut self.mutex, null_mut());
            let success = unsafe { CloseHandle(mutex) };
            if success == 0 {
                errors.push(anyhow::anyhow!(
                    "SxS exclusive owner close failed winerror={}",
                    unsafe { GetLastError() }
                ));
            }
        }
        super::native_identity::finish(Ok(()), errors)
    }
}
impl Drop for SessionOwner<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// The outer runtime capability proves only process retirement; journal/session checks still run.
pub(crate) fn recover_owned_session(
    owner: &crate::windows_security::native::NativeRunOwner,
    proof: &crate::runtime::ReapedProcessTree,
) -> Result<()> {
    let view = owner.sxs_recovery_view(proof)?;
    // No record means this run never attempted an ETW session. Avoid colliding with unrelated captures.
    if !crate::windows_security::native::SxsJournal::has_records(view)? {
        return Ok(());
    }
    let mut session = SessionOwner::acquire_ephemeral()?;
    let operation = (|| {
        if let Some((journal, logfile)) =
            crate::windows_security::native::SxsJournal::recovery(view)?
        {
            session.journal = Some(journal);
            session.stop(&logfile, true, false, None)?;
        }
        Ok(())
    })()
    .map_err(|error| super::safe(error, "recovery"));
    super::native_identity::finish(operation, session.close().err().into_iter().collect())
}
