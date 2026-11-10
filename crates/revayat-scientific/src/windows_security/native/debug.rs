//! Fixed authority entry and explicit-ID2 CSR diagnostics. Never an LPAC launch fallback.
use super::*;
use crate::identity::{self, ObjectId};
use crate::windows_security::activation::{
    EventCleanup, Failures, native::require_host, threads::ResourceThreads,
};
use crate::windows_security::image::{PeImage, sha256};
use registry_authority::native as api;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt;
#[path = "debug_abi.rs"]
mod abi;
use abi::{Creation, Event, NativeContext, Region, close, duplicate};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugBoundary {
    BeforeExitWait,
    BeforeRetire,
    AfterRetire,
}
#[derive(Debug)]
pub struct EntryProof {
    pub creation_bound: bool,
    pub entry_captured: bool,
    pub live_restored: bool,
    pub natural_exit: bool,
    pub reaped: bool,
    pub creator_capture: bool,
    pub events: usize,
    pub dispatch_target_equal: bool,
    pub dispatch_return: Option<u32>,
}
struct Owner {
    process: Handle,
    thread: Handle,
    original_process: Handle,
    original_thread: Handle,
    pid: u32,
    tid: u32,
    job: WindowsJob,
    pending: Option<Event>,
    generations: Option<ResourceThreads<NativeContext>>,
    files: EventCleanup,
    started: Instant,
    events: usize,
    creation: bool,
    exited: bool,
    exit_seen: bool,
    retirement_attempted: bool,
    event_file_released: bool,
    initial: bool,
    entry: u32,
    image_size: u32,
    expected: ObjectId,
    base: u64,
    dispatch: Option<debug_dispatch::DispatchImages>,
    transport: Option<debug_capture::Transport>,
}
impl Owner {
    fn receive(&mut self, milliseconds: u32) -> Result<bool> {
        ensure!(self.pending.is_none(), "debug event already pending");
        let mut event: Event = unsafe { zeroed() };
        let success = unsafe { abi::WaitForDebugEventEx(&mut event, milliseconds) };
        let error = if success == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        if success == 0 {
            ensure!(
                matches!(error, 121 | 258),
                "debug event wait failed winerror={error}"
            );
            return Ok(false);
        }
        self.pending = Some(event);
        self.event_file_released = false;
        self.events += 1;
        if event.kind == 5 && event.pid == self.pid {
            self.exit_seen = true;
        }
        ensure!(
            event.pid == self.pid,
            "debug event belongs to another process"
        );
        Ok(true)
    }
    fn continue_event(&mut self, status: u32) -> Result<()> {
        let event = self
            .pending
            .ok_or_else(|| anyhow::anyhow!("debug continuation has no pending event"))?;
        let success = unsafe { abi::ContinueDebugEvent(event.pid, event.tid, status) };
        let error = if success == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        ensure!(success != 0, "debug continuation failed winerror={error:?}");
        self.pending = None;
        if let Some(generations) = &mut self.generations {
            generations.continued()?;
        }
        Ok(())
    }
    fn release_event_file(&mut self, event: Event) -> Result<()> {
        if self.event_file_released {
            return Ok(());
        }
        self.event_file_released = true;
        let mut handle = match event.kind {
            3 => unsafe { event.data.creation.file as usize },
            6 => unsafe { event.data.words[0] as usize },
            _ => 0,
        };
        self.files
            .close(&mut handle, |value| close(value as Handle))
    }
    fn bind_creation(&mut self, event: Event) -> Result<()> {
        ensure!(
            !self.creation && event.kind == 3 && event.tid == self.tid,
            "debug creation identity is ambiguous"
        );
        let created: Creation = unsafe { event.data.creation };
        ensure!(
            !created.file.is_null(),
            "debug creation image handle absent"
        );
        let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
            unsafe { zeroed() };
        let success = unsafe { abi::GetFileInformationByHandle(created.file, &mut info) };
        let error = if success == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        ensure!(
            success != 0
                && ObjectId {
                    volume: u64::from(info.dwVolumeSerialNumber),
                    index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow)
                } == self.expected,
            "debug creation image differs winerror={error:?}"
        );
        self.base = created.image_base as u64;
        ensure!(
            self.base != 0 && self.base <= 0x7fffffffffffffff - u64::from(self.image_size),
            "debug image base overflows"
        );
        let site = self.base + u64::from(self.entry);
        let mut region = Region::default();
        let returned = unsafe {
            abi::VirtualQueryEx(
                self.process,
                site as Handle,
                &mut region,
                size_of::<Region>(),
            )
        };
        ensure!(returned == size_of::<Region>() && region.state == 0x1000 && region.kind == 0x1000000
            && region.allocation == created.image_base && site >= region.address as u64
            && site - region.address as u64 < region.size as u64 && region.protect & 0x100 == 0
            && matches!(region.protect & 0xff, 0x10 | 0x20 | 0x40 | 0x80), "debug entry region is not executable owned image");
        let mut generations = ResourceThreads::new(
            self.pid,
            self.tid,
            NativeContext {
                started: self.started,
                cleanup: false,
                owner: std::thread::current().id(),
            },
        )?;
        generations.stop(self.pid, self.tid, 3, false)?;
        let mut thread = duplicate(created.thread)? as usize;
        let enrolled = generations.enroll(self.tid, &mut thread, true);
        self.generations = Some(generations); // Retain transferred handle even if enrollment failed.
        if thread != 0 {
            close(thread as Handle)?;
        }
        enrolled?;
        if self.dispatch.is_none() {
            self.generations.as_mut().unwrap().arm(site)?;
        }
        self.creation = true;
        Ok(())
    }
    fn release_creation_aliases(&mut self, event: Event) -> Result<()> {
        if event.kind != 3 {
            return Ok(());
        }
        let created = unsafe { event.data.creation };
        let mut errors = Vec::new();
        for (original, retained, event_handle) in [
            (
                &mut self.original_process,
                &mut self.process,
                created.process,
            ),
            (&mut self.original_thread, &mut self.thread, created.thread),
        ] {
            // If independent duplication failed, the still-original field belongs to the
            // OS after matching this event; invalidate it rather than closing it twice.
            if original.is_null() && *retained == event_handle {
                *retained = null_mut();
            }
            let handle = std::mem::replace(original, null_mut());
            if handle != event_handle
                && let Err(error) = close(handle)
            {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Failures { errors }.into())
        }
    }
    fn event(&mut self, event: Event) -> Result<u32> {
        require_host()?;
        if event.kind == 3 {
            self.bind_creation(event)?;
            return Ok(0x10002);
        }
        let generations = self
            .generations
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("debug event precedes creation"))?;
        generations.stop(event.pid, event.tid, event.kind, false)?;
        match event.kind {
            1 => {
                let words = unsafe { event.data.words };
                let code = words[0] as u32;
                let first = words[19] as u32 != 0;
                ensure!(
                    first && (self.dispatch.is_some() || event.tid == self.tid),
                    "debug exception is not creator first-chance"
                );
                if code == 0x80000003 {
                    ensure!(!self.initial, "debug initial breakpoint repeated");
                    generations.software(event.tid, true)?;
                    self.initial = true;
                } else {
                    ensure!(
                        code == 0x80000004 && (self.initial || self.dispatch.is_some()),
                        "debug exception is outside fixed entry observation"
                    );
                    if let Some(dispatch) = &mut self.dispatch {
                        generations.capture_dispatch(event.tid, true, words[2], || {
                            self.transport
                                .as_mut()
                                .ok_or_else(|| {
                                    anyhow::anyhow!("explicit fixture transport absent")
                                })?
                                .require_pre_call()?;
                            dispatch.require_target(self.process)
                        })?;
                    } else {
                        generations.capture_entry(event.tid, true, words[2])?;
                    }
                }
            }
            2 => {
                let mut thread = duplicate(unsafe { event.data.words[0] as Handle })? as usize;
                let result = generations.enroll(event.tid, &mut thread, true);
                if thread != 0 {
                    close(thread as Handle)?;
                }
                result?;
            }
            4 => {}
            5 => {
                ensure!(
                    unsafe { event.data.words[0] as u32 } == 0
                        && generations.captured()
                        && generations.capture_restored()
                        && !generations.failed(),
                    "debug child exit lacks qualified entry/restoration"
                );
                self.exited = true;
            }
            6 => {
                if let Some(dispatch) = &mut self.dispatch
                    && let Some([call, post]) = dispatch.load(
                        self.process,
                        unsafe { event.data.words[0] as Handle },
                        unsafe { event.data.words[1] },
                    )?
                {
                    generations.arm_dispatch(call, post)?;
                }
            }
            8 => {}
            7 => {
                if let Some(dispatch) = &self.dispatch {
                    dispatch.require_unload(unsafe { event.data.words[0] })?;
                }
                ensure!(
                    unsafe { event.data.words[0] } != self.base,
                    "debug owned image unloaded"
                );
            }
            _ => anyhow::bail!("unsupported debug event kind"),
        }
        Ok(0x10002)
    }
}

#[path = "debug_cleanup.rs"]
mod cleanup;
#[path = "debug_launch.rs"]
mod launch;
pub use launch::{
    observe_authority_entry, observe_authority_entry_observed, observe_explicit_id2_dispatch,
};
#[path = "debug_capture.rs"]
mod debug_capture;
#[path = "debug_dispatch.rs"]
mod debug_dispatch;
