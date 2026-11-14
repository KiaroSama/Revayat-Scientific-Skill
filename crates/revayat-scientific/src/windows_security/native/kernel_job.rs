//! Actual inherited-job values and the fixed committed-memory negative control.
use super::super::super::{CpuLimits, ExtendedLimits, QueryInformationJobObject};
use super::super::ffi::*;
use crate::windows_security::kernel_controls as plan;
use anyhow::{Result, ensure};
use std::{
    mem::{size_of, zeroed},
    ptr::null_mut,
};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualAlloc(address: Raw, bytes: usize, allocation: u32, protect: u32) -> Raw;
    fn VirtualFree(address: Raw, bytes: usize, kind: u32) -> i32;
}
pub(super) fn require() -> Result<()> {
    let mut actual: ExtendedLimits = unsafe { zeroed() };
    let mut returned = 0;
    // SAFETY: NULL selects this actual process's inherited job; exact initialized native output.
    ensure!(
        unsafe {
            QueryInformationJobObject(
                null_mut(),
                9,
                (&mut actual as *mut ExtendedLimits).cast(),
                size_of::<ExtendedLimits>() as u32,
                &mut returned,
            )
        } != 0
            && returned as usize == size_of::<ExtendedLimits>(),
        "kernel effective job query failed"
    );
    ensure!(
        actual.basic.flags & plan::JOB_FLAGS == plan::JOB_FLAGS
            && actual.basic.flags & 0x1800 == 0
            && actual.basic.processes == 8
            && actual.basic.job_time == plan::JOB_CPU_TICKS
            && actual.process_memory as u64 == plan::PROCESS_MEMORY
            && actual.job_memory as u64 == plan::JOB_MEMORY,
        "kernel effective job limits or breakaway policy differ"
    );
    let mut cpu: CpuLimits = unsafe { zeroed() };
    let mut returned = 0;
    ensure!(
        unsafe {
            QueryInformationJobObject(
                null_mut(),
                15,
                (&mut cpu as *mut CpuLimits).cast(),
                size_of::<CpuLimits>() as u32,
                &mut returned,
            )
        } != 0
            && returned as usize == size_of::<CpuLimits>()
            && cpu.flags == 5
            && cpu.rate == 1000,
        "kernel effective hard CPU cap differs"
    );
    Ok(())
}
pub(super) fn memory() -> Result<()> {
    // SAFETY: fixed anonymous reserve+commit request, no existing address or user pointer.
    let allocation = unsafe { VirtualAlloc(null_mut(), 385 * 1024 * 1024, 0x3000, 4) };
    let error = unsafe { GetLastError() };
    if !allocation.is_null() {
        let closed = unsafe { VirtualFree(allocation, 0, 0x8000) };
        return combine(
            Err(anyhow::anyhow!(
                "kernel admitted excessive committed-memory request"
            )),
            if closed != 0 {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "kernel unexpected allocation release failed"
                ))
            },
        );
    }
    ensure!(
        [8, 1455, 1816].contains(&error),
        "kernel excessive allocation failed without recognized memory/quota denial"
    );
    Ok(())
}
