//! Only the same admitted image and closed token-child argument vector may be spawned.
use super::{ffi::*, token};
use crate::windows_security::quota_controls::{
    self as contract, DESCENDANT_BYTES, OwnerInventory, Role, WorkerPlan,
};
use anyhow::{Result, ensure};
use registry_authority::native::{self as api, Startup};
use std::{
    mem::{size_of, size_of_val},
    ptr::null_mut,
    time::{Duration, Instant},
};

struct Attributes(Vec<u64>);
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { api::DeleteProcThreadAttributeList(self.0.as_mut_ptr().cast()) };
    }
}
struct Capture {
    bytes: Vec<u8>,
    eof: bool,
}
impl Capture {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            eof: false,
        }
    }
    fn drain(&mut self, handle: Raw, limit: usize) -> Result<()> {
        for _ in 0..=limit {
            if self.eof {
                return Ok(());
            }
            let mut available = 0;
            // SAFETY: sole synchronous reader of an owned pipe; inspect immediate failed-call code only.
            let ok = unsafe {
                api::PeekNamedPipe(
                    handle,
                    null_mut(),
                    0,
                    null_mut(),
                    &mut available,
                    null_mut(),
                )
            };
            if ok == 0 {
                let error = unsafe { GetLastError() };
                ensure!(error == 109, "quota descendant pipe peek failed");
                self.eof = true;
                return Ok(());
            }
            ensure!(
                (available as usize) <= limit.saturating_sub(self.bytes.len()),
                "quota descendant capture exceeds bound"
            );
            if available == 0 {
                return Ok(());
            }
            let mut buffer = [0u8; 1024];
            let capacity = (available as usize).min(buffer.len());
            let mut count = 0;
            let ok = unsafe {
                api::ReadFile(
                    handle,
                    buffer.as_mut_ptr().cast(),
                    capacity as u32,
                    &mut count,
                    null_mut(),
                )
            };
            if ok == 0 || count == 0 || count as usize > capacity {
                buffer.fill(0);
                anyhow::bail!("quota descendant pipe read failed");
            }
            self.bytes.extend_from_slice(&buffer[..count as usize]);
            buffer.fill(0);
        }
        anyhow::bail!("quota descendant capture made no bounded progress")
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}
fn pair(output: bool) -> Result<(Owned, Owned)> {
    let (mut read, mut write) = registry_authority::pipe::pair(output)
        .map_err(|_| anyhow::anyhow!("quota descendant pipe acquisition failed"))?;
    Ok((
        Owned(std::mem::replace(&mut read.raw, null_mut())),
        Owned(std::mem::replace(&mut write.raw, null_mut())),
    ))
}
struct Child {
    process: Owned,
    thread: Owned,
    input: Owned,
    output: Owned,
    output_write: Owned,
    error: Owned,
    error_write: Owned,
    started: bool,
    reaped: bool,
    closed: bool,
}
impl Child {
    fn new() -> Self {
        Self {
            process: Owned::empty(),
            thread: Owned::empty(),
            input: Owned::empty(),
            output: Owned::empty(),
            output_write: Owned::empty(),
            error: Owned::empty(),
            error_write: Owned::empty(),
            started: false,
            reaped: false,
            closed: false,
        }
    }
    fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let mut results = Vec::new();
        if self.started && !self.reaped {
            // SAFETY: exactly this fixed owned child; failures never waive the independent bounded reap.
            let signaled = unsafe { api::WaitForSingleObject(self.process.0, 0) };
            if signaled == 258 {
                results.push(
                    if unsafe { api::TerminateProcess(self.process.0, 125) } != 0 {
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!("quota descendant termination failed"))
                    },
                );
            } else if signaled != 0 {
                results.push(Err(anyhow::anyhow!(
                    "quota descendant termination state query failed"
                )));
            }
            let waited = unsafe { api::WaitForSingleObject(self.process.0, 2000) };
            results.push(if waited == 0 {
                Ok(())
            } else {
                Err(anyhow::anyhow!("quota descendant bounded reap failed"))
            });
        }
        for owner in [
            &mut self.thread,
            &mut self.process,
            &mut self.input,
            &mut self.output_write,
            &mut self.error_write,
            &mut self.output,
            &mut self.error,
        ] {
            results.push(owner.close());
        }
        all(results)
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.close().is_err() {
            note_cleanup_failure();
        }
    }
}
pub(super) fn observe(plan: &WorkerPlan, inventory: &OwnerInventory) -> Result<()> {
    let mut child = Child::new();
    let operation = (|| {
        let image = std::env::current_exe()
            .map_err(|_| anyhow::anyhow!("quota descendant fixed image lookup failed"))?;
        let image = image
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("quota descendant fixed image is not Unicode"))?;
        ensure!(
            image.encode_utf16().count() < 512 && !image.contains(['\0', '"']),
            "quota descendant fixed image path differs"
        );
        let mut command = format!("\"{image}\"");
        for arg in plan.arguments(Role::TokenChild)? {
            ensure!(
                !arg.contains(['\0', '"']),
                "quota descendant argument is not admitted"
            );
            command.push_str(" \"");
            command.push_str(&arg);
            for _ in arg.bytes().rev().take_while(|byte| *byte == b'\\') {
                command.push('\\');
            }
            command.push('"');
        }
        let mut command = wide(&command);
        let image = wide(image);
        let cwd = wide(&plan.scratch);
        (child.output, child.output_write) = pair(true)?;
        (child.error, child.error_write) = pair(false)?;
        // Duplicate exactly the inherited host-provisioned NUL input, never close its original.
        let borrowed = unsafe { api::GetStdHandle((-10i32) as u32) };
        ensure!(
            !borrowed.is_null() && borrowed as isize != -1 && unsafe { GetFileType(borrowed) } == 2,
            "quota descendant input is not NUL"
        );
        let mut raw = null_mut();
        let current = unsafe { GetCurrentProcess() };
        let ok = unsafe { api::DuplicateHandle(current, borrowed, current, &mut raw, 0, 1, 2) };
        if !raw.is_null() {
            child.input = Owned::new(raw)?;
        }
        ensure!(
            ok != 0 && !child.input.0.is_null() && unsafe { GetFileType(child.input.0) } == 2,
            "quota descendant NUL duplication failed"
        );
        let mut size = 0;
        let initial =
            unsafe { api::InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
        ensure!(
            initial == 0 && (1..=65536).contains(&size),
            "quota descendant attribute list size differs"
        );
        let mut storage = vec![0u64; size.div_ceil(8)];
        ensure!(
            unsafe {
                api::InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 1, 0, &mut size)
            } != 0,
            "quota descendant attribute initialization failed"
        );
        let mut attrs = Attributes(storage);
        let mut inherited = [child.input.0, child.output_write.0, child.error_write.0];
        ensure!(
            unsafe {
                api::UpdateProcThreadAttribute(
                    attrs.0.as_mut_ptr().cast(),
                    0,
                    0x20002,
                    inherited.as_mut_ptr().cast(),
                    size_of_val(&inherited),
                    null_mut(),
                    null_mut(),
                )
            } != 0,
            "quota descendant exact handle list failed"
        );
        let startup = StartupEx {
            startup: Startup {
                size: size_of::<StartupEx>() as u32,
                flags: 0x100,
                input: child.input.0,
                output: child.output_write.0,
                error: child.error_write.0,
                ..Startup::default()
            },
            attributes: attrs.0.as_mut_ptr().cast(),
        };
        let mut info = ProcessInfo::default();
        // SAFETY: same fixed image, closed argv, exact inherited standards, inherited environment;
        // DETACHED|SUSPENDED|UNICODE_ENVIRONMENT|EXTENDED_STARTUPINFO, without breakaway.
        let created = unsafe {
            api::CreateProcessW(
                image.as_ptr(),
                command.as_mut_ptr(),
                null_mut(),
                null_mut(),
                1,
                0x0008040C,
                null_mut(),
                cwd.as_ptr(),
                &startup,
                &mut info,
            )
        };
        child.started = created != 0;
        if !info.process.is_null() && info.process as isize != -1 {
            child.process = Owned(info.process);
        }
        if !info.thread.is_null() && info.thread as isize != -1 {
            child.thread = Owned(info.thread);
        }
        ensure!(
            created != 0 && !child.process.0.is_null() && !child.thread.0.is_null(),
            "quota descendant suspended creation failed"
        );
        let mut member = 0;
        ensure!(
            unsafe { api::IsProcessInJob(child.process.0, null_mut(), &mut member) } != 0
                && member != 0,
            "quota descendant inherited job membership was not confirmed"
        );
        token::inherited(child.process.0, &plan.package, inventory)?;
        ensure!(
            unsafe { api::ResumeThread(child.thread.0) } == 1,
            "quota descendant was not resumed exactly once from suspension"
        );
        all([
            child.output_write.close(),
            child.error_write.close(),
            child.input.close(),
            child.thread.close(),
        ])?;
        drop(attrs);
        let (mut stdout, mut stderr) = (Capture::new(), Capture::new());
        let clock = Instant::now();
        loop {
            stdout.drain(child.output.0, DESCENDANT_BYTES)?;
            stderr.drain(child.error.0, 512)?;
            let wait = unsafe { api::WaitForSingleObject(child.process.0, 25) };
            if wait == 0 {
                child.reaped = true;
                break;
            }
            ensure!(wait == 258, "quota descendant process wait failed");
            ensure!(
                clock.elapsed() < Duration::from_secs(5),
                "quota descendant exceeded original five-second capture deadline"
            );
        }
        let mut code = 0;
        ensure!(
            unsafe { api::GetExitCodeProcess(child.process.0, &mut code) } != 0,
            "quota descendant actual exit query failed"
        );
        stdout.drain(child.output.0, DESCENDANT_BYTES)?;
        stderr.drain(child.error.0, 512)?;
        ensure!(
            stdout.eof && stderr.eof && stderr.bytes.is_empty() && code == 0,
            "quota descendant actual exit, stderr or capture EOF was not qualified"
        );
        contract::require_token_record(&stdout.bytes, inventory)
    })();
    combine(operation, child.close())
}
