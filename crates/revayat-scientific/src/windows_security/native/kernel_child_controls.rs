//! Actual independent token transport, PID ceiling and owned wall descendant.
use super::{
    super::ffi::*,
    children::{self, Child, Spawn},
};
use crate::windows_security::{
    kernel_controls::{KernelPlan, Role, WALL_MARKER},
    quota_controls::{self, OwnerInventory},
};
use anyhow::{Result, ensure};
use registry_authority::native as api;
use std::{
    io::Write,
    ptr::null_mut,
    time::{Duration, Instant},
};
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
                ensure!(
                    unsafe { GetLastError() } == 109,
                    "kernel token child pipe peek failed"
                );
                self.eof = true;
                return Ok(());
            }
            ensure!(
                available as usize <= limit.saturating_sub(self.bytes.len()),
                "kernel token child capture exceeds bound"
            );
            if available == 0 {
                return Ok(());
            }
            let mut bytes = [0u8; 1024];
            let capacity = (available as usize).min(bytes.len());
            let mut count = 0;
            let ok = unsafe {
                api::ReadFile(
                    handle,
                    bytes.as_mut_ptr().cast(),
                    capacity as u32,
                    &mut count,
                    null_mut(),
                )
            };
            if ok == 0 || count == 0 || count as usize > capacity {
                bytes.fill(0);
                anyhow::bail!("kernel token child pipe read failed");
            }
            self.bytes.extend_from_slice(&bytes[..count as usize]);
            bytes.fill(0);
        }
        anyhow::bail!("kernel token child capture made no bounded progress")
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}
fn started(value: Spawn) -> Result<Child> {
    match value {
        Spawn::Started(child) => Ok(child),
        Spawn::Denied(_) => anyhow::bail!("kernel required fixed child could not be created"),
    }
}
pub(super) fn token_child(plan: &KernelPlan, inventory: &OwnerInventory) -> Result<()> {
    let clock = Instant::now();
    let mut child = started(children::spawn(plan, Role::TokenChild, inventory, clock)?)?;
    let operation = (|| {
        let (mut output, mut error) = (Capture::new(), Capture::new());
        let code = loop {
            ensure!(
                clock.elapsed() < Duration::from_secs(5),
                "kernel token child total deadline exceeded"
            );
            output.drain(child.output.0, 65_535)?;
            error.drain(child.error.0, 512)?;
            if let Some(code) = child.wait(25)? {
                break code;
            }
        };
        output.drain(child.output.0, 65_535)?;
        error.drain(child.error.0, 512)?;
        ensure!(
            clock.elapsed() < Duration::from_secs(5)
                && output.eof
                && error.eof
                && error.bytes.is_empty()
                && code == 0,
            "kernel token child exit/capture/EOF was not qualified"
        );
        quota_controls::require_token_record(&output.bytes, inventory)
    })();
    combine(operation, child.close(2000))
}
pub(super) fn pids(plan: &KernelPlan, inventory: &OwnerInventory) -> Result<()> {
    let clock = Instant::now();
    let mut children = Vec::new();
    let operation = (|| {
        for _ in 0..7 {
            children.push(started(children::spawn(
                plan,
                Role::PidHold,
                inventory,
                clock,
            )?)?);
        }
        // The fixed ten-second holds are still live within the shared five-second launch window.
        for child in &mut children {
            ensure!(
                child.wait(0)?.is_none(),
                "kernel PID hold child exited before ceiling observation"
            );
        }
        let mut accounting: super::super::super::Accounting = unsafe { std::mem::zeroed() };
        let mut returned = 0;
        ensure!(
            unsafe {
                super::super::super::QueryInformationJobObject(
                    null_mut(),
                    1,
                    (&mut accounting as *mut super::super::super::Accounting).cast(),
                    std::mem::size_of_val(&accounting) as u32,
                    &mut returned,
                )
            } != 0
                && returned as usize == std::mem::size_of_val(&accounting)
                && accounting.active == 8,
            "kernel PID ceiling lacks actual eight-process setup"
        );
        match children::spawn(plan, Role::PidExtra, inventory, clock)? {
            Spawn::Denied(code) => ensure!(
                [1816, 5, 8].contains(&code),
                "kernel extra child creation failed without recognized PID denial"
            ),
            Spawn::Started(mut extra) => {
                let result = extra.wait(3000);
                children.push(extra);
                ensure!(
                    result?.is_some_and(|code| code != 0),
                    "kernel PID ceiling admitted successful extra process or failed to terminate it"
                );
            }
        }
        Ok(())
    })();
    combine(
        operation,
        all(children.iter_mut().map(|child| child.close(3000))),
    )
}
pub(super) fn wall(plan: &KernelPlan, inventory: &OwnerInventory) -> Result<String> {
    let mut child = started(children::spawn(
        plan,
        Role::WallHold,
        inventory,
        Instant::now(),
    )?)?;
    let operation = (|| {
        ensure!(
            child.wait(0)?.is_none(),
            "kernel wall descendant exited before marker"
        );
        let mut output = std::io::stdout().lock();
        output
            .write_all(WALL_MARKER)
            .map_err(|_| anyhow::anyhow!("kernel wall marker write failed"))?;
        output
            .flush()
            .map_err(|_| anyhow::anyhow!("kernel wall marker flush failed"))?;
        drop(output);
        // The concrete host owner must terminate the entire job. No success/completion record exists here.
        let clock = Instant::now();
        while clock.elapsed() < Duration::from_secs(30) {
            ensure!(
                child.wait(25)?.is_none(),
                "kernel wall descendant exited before owned host termination"
            );
        }
        anyhow::bail!("kernel wall actor survived expected owned deadline")
    })();
    combine(operation, child.close(3000))
}
