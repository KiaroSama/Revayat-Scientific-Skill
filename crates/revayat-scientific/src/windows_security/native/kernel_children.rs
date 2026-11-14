//! Fixed same-image roles only, owned before resume and independently killed/reaped/closed.
use super::super::{ffi::*, token};
use crate::windows_security::{
    kernel_controls::{KernelPlan, Role},
    quota_controls::OwnerInventory,
};
use anyhow::{Result, ensure};
use registry_authority::native::{self as api, Startup};
use std::{
    mem::{size_of, size_of_val},
    ptr::null_mut,
    time::{Duration, Instant},
};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetHandleInformation(handle: Raw, flags: *mut u32) -> i32;
}
struct Attributes(Vec<u64>);
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { api::DeleteProcThreadAttributeList(self.0.as_mut_ptr().cast()) };
    }
}
pub(super) struct Child {
    pub(super) process: Owned,
    thread: Owned,
    standards: Vec<Owned>,
    pub(super) output: Owned,
    pub(super) error: Owned,
    reaped: bool,
    closed: bool,
}
impl Child {
    fn new() -> Self {
        Self {
            process: Owned::empty(),
            thread: Owned::empty(),
            standards: Vec::new(),
            output: Owned::empty(),
            error: Owned::empty(),
            reaped: false,
            closed: false,
        }
    }
    pub(super) fn wait(&mut self, milliseconds: u32) -> Result<Option<u32>> {
        let waited = unsafe { api::WaitForSingleObject(self.process.0, milliseconds) };
        ensure!(
            waited == 0 || waited == 258,
            "kernel fixed child wait failed"
        );
        if waited == 258 {
            return Ok(None);
        }
        self.reaped = true;
        let mut code = 0;
        ensure!(
            unsafe { api::GetExitCodeProcess(self.process.0, &mut code) } != 0,
            "kernel fixed child actual exit query failed"
        );
        Ok(Some(code))
    }
    fn close_standards(&mut self) -> Result<()> {
        all(self.standards.iter_mut().map(Owned::close))
    }
    pub(super) fn close(&mut self, milliseconds: u32) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let mut errors = Vec::new();
        if !self.process.0.is_null() && !self.reaped {
            match self.wait(0) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    if unsafe { api::TerminateProcess(self.process.0, 125) } == 0 {
                        errors.push(anyhow::anyhow!("kernel fixed child termination failed"));
                    }
                    match self.wait(milliseconds) {
                        Ok(Some(_)) => {}
                        _ => errors.push(anyhow::anyhow!(
                            "kernel fixed child bounded cleanup wait failed"
                        )),
                    }
                }
                Err(error) => errors.push(error),
            }
        }
        for result in [
            self.close_standards(),
            self.thread.close(),
            self.process.close(),
            self.output.close(),
            self.error.close(),
        ] {
            if let Err(error) = result {
                errors.push(error);
            }
        }
        all(errors.into_iter().map(Err))
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.close(2000).is_err() {
            note_cleanup_failure();
        }
    }
}
pub(super) enum Spawn {
    Started(Child),
    Denied(u32),
}
fn duplicate(owner: &mut Child, id: i32, kind: u32) -> Result<()> {
    let raw = unsafe { api::GetStdHandle(id as u32) };
    ensure!(
        !raw.is_null() && raw as isize != -1 && unsafe { GetFileType(raw) } == kind,
        "kernel inherited standard handle differs"
    );
    let mut copied = null_mut();
    let current = unsafe { GetCurrentProcess() };
    let ok = unsafe { api::DuplicateHandle(current, raw, current, &mut copied, 0, 1, 2) };
    if !copied.is_null() && copied as isize != -1 {
        owner.standards.push(Owned(copied));
    }
    ensure!(
        ok != 0 && !copied.is_null() && copied as isize != -1,
        "kernel standard duplicate failed"
    );
    Ok(())
}
fn pair(output: bool) -> Result<(Owned, Owned)> {
    let (mut read, mut write) = registry_authority::pipe::pair(output)
        .map_err(|_| anyhow::anyhow!("kernel private child pipe failed"))?;
    Ok((
        Owned(std::mem::replace(&mut read.raw, null_mut())),
        Owned(std::mem::replace(&mut write.raw, null_mut())),
    ))
}
pub(super) fn spawn(
    plan: &KernelPlan,
    role: Role,
    inventory: &OwnerInventory,
    clock: Instant,
) -> Result<Spawn> {
    ensure!(
        matches!(
            role,
            Role::TokenChild | Role::PidHold | Role::PidExtra | Role::WallHold
        ),
        "kernel child role is not admitted"
    );
    let mut owner = Child::new();
    let operation = (|| {
        ensure!(
            clock.elapsed() < Duration::from_secs(5),
            "kernel standard preparation deadline exceeded"
        );
        duplicate(&mut owner, -10, 2)?;
        if role == Role::TokenChild {
            let (read, write) = pair(true)?;
            owner.output = read;
            owner.standards.push(write);
            let (read, write) = pair(false)?;
            owner.error = read;
            owner.standards.push(write);
        } else {
            duplicate(&mut owner, -11, 3)?;
            duplicate(&mut owner, -12, 3)?;
        }
        ensure!(
            owner.standards.len() == 3,
            "kernel standard inventory differs"
        );
        let mut inherited = [null_mut(); 3];
        for (index, handle) in owner.standards.iter().enumerate() {
            let mut flags = 0;
            ensure!(
                handle.0 as usize & 3 != 3
                    && unsafe { GetFileType(handle.0) } == if index == 0 { 2 } else { 3 }
                    && unsafe { GetHandleInformation(handle.0, &mut flags) } != 0
                    && flags & 1 == 1,
                "kernel standard handle type/inherit flag differs"
            );
            inherited[index] = handle.0;
        }
        ensure!(
            inherited[0] != inherited[1]
                && inherited[0] != inherited[2]
                && inherited[1] != inherited[2],
            "kernel standard handles alias"
        );
        let image = std::env::current_exe()
            .map_err(|_| anyhow::anyhow!("kernel child image query failed"))?;
        ensure!(
            image.file_name() == Some(std::ffi::OsStr::new("revayat-quota-worker.exe")),
            "kernel child image name differs"
        );
        let image_text = image
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("kernel child image is not Unicode"))?;
        ensure!(
            image_text.encode_utf16().count() < 512 && !image_text.contains(['\0', '"']),
            "kernel child image bounds differ"
        );
        let mut command = format!("\"{image_text}\"");
        for arg in plan.arguments(role)? {
            ensure!(!arg.contains(['\0', '"']), "kernel child argument differs");
            command.push_str(" \"");
            command.push_str(&arg);
            for _ in arg.bytes().rev().take_while(|byte| *byte == b'\\') {
                command.push('\\');
            }
            command.push('"');
        }
        let mut command = wide(&command);
        let image = wide(image_text);
        let cwd = wide(&plan.quota.scratch);
        let mut size = 0;
        let initial =
            unsafe { api::InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
        ensure!(
            initial == 0 && (1..=65536).contains(&size),
            "kernel child attribute size differs"
        );
        let mut storage = vec![0u64; size.div_ceil(8)];
        ensure!(
            unsafe {
                api::InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 1, 0, &mut size)
            } != 0,
            "kernel child attributes initialization failed"
        );
        let mut attrs = Attributes(storage);
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
            "kernel child exact handle list failed"
        );
        let startup = StartupEx {
            startup: Startup {
                size: size_of::<StartupEx>() as u32,
                flags: 0x100,
                input: inherited[0],
                output: inherited[1],
                error: inherited[2],
                ..Startup::default()
            },
            attributes: attrs.0.as_mut_ptr().cast(),
        };
        let mut info = ProcessInfo::default();
        // SAFETY: same fixed admitted image, closed role/argv, exact inherited standards;
        // detached+suspended without breakaway. NULL env inherits this checked13-name block.
        let created = unsafe {
            api::CreateProcessW(
                image.as_ptr(),
                command.as_mut_ptr(),
                null_mut(),
                null_mut(),
                1,
                0x8040c,
                null_mut(),
                cwd.as_ptr(),
                &startup,
                &mut info,
            )
        };
        let code = unsafe { GetLastError() };
        if !info.process.is_null() && info.process as isize != -1 {
            owner.process = Owned(info.process);
        }
        if !info.thread.is_null() && info.thread as isize != -1 {
            owner.thread = Owned(info.thread);
        }
        if created == 0 {
            return Ok(Some(code));
        }
        ensure!(
            !owner.process.0.is_null() && !owner.thread.0.is_null(),
            "kernel child acquired incomplete process handles"
        );
        if role == Role::PidExtra && owner.wait(0)?.is_some() {
            return Ok(None);
        }
        let mut member = 0;
        ensure!(
            unsafe { api::IsProcessInJob(owner.process.0, null_mut(), &mut member) } != 0
                && member == 1,
            "kernel child inherited job membership differs"
        );
        token::inherited(owner.process.0, &plan.quota.package, inventory)?;
        ensure!(
            unsafe { api::ResumeThread(owner.thread.0) } == 1,
            "kernel child resume was not one suspended thread"
        );
        ensure!(
            clock.elapsed() < Duration::from_secs(5),
            "kernel fixed child preparation exceeded deadline"
        );
        Ok(None)
    })();
    match operation {
        Ok(None) => {
            if let Err(primary) = all([owner.close_standards(), owner.thread.close()]) {
                return combine(Err(primary), owner.close(2000));
            }
            Ok(Spawn::Started(owner))
        }
        Ok(Some(code)) => {
            owner.close(2000)?;
            Ok(Spawn::Denied(code))
        }
        Err(primary) => combine(Err(primary), owner.close(2000)),
    }
}
