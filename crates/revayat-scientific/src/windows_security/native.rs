//! Win32 job ownership. Every child remains suspended until kernel attachment.
use super::{JobLimits, Lifecycle, plain_path};
use anyhow::{Context, Result, ensure};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::os::windows::{ffi::OsStrExt, io::AsRawHandle, process::CommandExt};
use std::path::Path;
use std::process::{Child, Command};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

type Handle = *mut c_void;
#[path = "native/native_quota.rs"]
pub(crate) mod native_quota;
/// Only the explicit fixed quota-worker binary dispatches this native entry.
/// Host-side token preparation and lifecycle authority remain separate.
pub fn quota_worker_main() -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
        native_quota::worker_main()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        eprintln!("Native quota controls require Windows x64.");
        1
    }
}
#[path = "native/authority.rs"]
mod authority;
#[path = "native/debug.rs"]
mod debug;
#[path = "native/fixture.rs"]
mod fixture;
pub use debug::{
    DebugBoundary, EntryProof, observe_authority_entry, observe_authority_entry_observed,
    observe_explicit_id2_dispatch,
};
#[path = "native/network.rs"]
mod network;
pub use authority::{
    run_machine_authority_session, run_machine_kernel_session, run_machine_quota_session,
    run_owned_registry_authority, run_registry_authority,
};
#[path = "native/recovery.rs"]
mod recovery;
#[path = "native/state.rs"]
mod state;
pub(crate) use authority::{AuthorityObserver, run_observed, run_owned_observed, run_sxs_tool};
pub(crate) use recovery::SxsJournal;
pub use recovery::{recover_profile, recover_run};
pub use state::{NativeRunOwner, NativeRunView, run_bootstrap_checks};
#[path = "native/dos_path.rs"]
mod dos_path;
#[path = "native/scratch_access.rs"]
mod scratch_access;
#[path = "native/scratch_diagnostic.rs"]
mod scratch_diagnostic;
#[path = "native/scratch_disk.rs"]
mod scratch_disk;
#[path = "native/scratch_layout.rs"]
mod scratch_layout;
#[path = "native/scratch_lease.rs"]
mod scratch_lease;
#[path = "native/scratch_private.rs"]
mod scratch_private;
#[path = "native/scratch_quota.rs"]
mod scratch_quota;
#[path = "native/scratch_recovery.rs"]
mod scratch_recovery;
pub use scratch_disk::ScratchVolume;
pub use scratch_recovery::recover_scratch;
#[path = "native/registry_machine.rs"]
pub mod registry_machine;
const KILL_ON_CLOSE: u32 = 0x2000;
const REQUIRED_LIMITS: u32 = KILL_ON_CLOSE | 0x200 | 0x100 | 8 | 4;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BasicLimits {
    process_time: i64,
    job_time: i64,
    flags: u32,
    minimum_working: usize,
    maximum_working: usize,
    processes: u32,
    affinity: usize,
    priority: u32,
    scheduling: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoCounters {
    reads: u64,
    writes: u64,
    other: u64,
    read_bytes: u64,
    write_bytes: u64,
    other_bytes: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ExtendedLimits {
    basic: BasicLimits,
    io: IoCounters,
    process_memory: usize,
    job_memory: usize,
    peak_process: usize,
    peak_job: usize,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Accounting {
    user: i64,
    kernel: i64,
    period_user: i64,
    period_kernel: i64,
    faults: u32,
    total: u32,
    active: u32,
    terminated: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CpuLimits {
    flags: u32,
    rate: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateJobObjectW(security: Handle, name: *const u16) -> Handle;
    fn SetInformationJobObject(job: Handle, class: i32, data: *const c_void, size: u32) -> i32;
    fn QueryInformationJobObject(
        job: Handle,
        class: i32,
        data: Handle,
        size: u32,
        returned: *mut u32,
    ) -> i32;
    fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
    fn IsProcessInJob(process: Handle, job: Handle, result: *mut i32) -> i32;
    fn TerminateJobObject(job: Handle, exit: u32) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn LocalFree(memory: Handle) -> Handle;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn GetLastError() -> u32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtResumeProcess(process: Handle) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut Handle,
        size: *mut u32,
    ) -> i32;
    fn SetFileSecurityW(path: *const u16, information: u32, descriptor: Handle) -> i32;
}

/// Owned kernel job. It cannot be cloned or inherited by workers.
pub struct WindowsJob {
    handle: Handle,
    state: Lifecycle,
}

impl WindowsJob {
    fn create(limits: JobLimits) -> Result<Self> {
        let limits = limits.validate()?;
        // SAFETY: null optional attributes/name create a non-inheritable anonymous job.
        let handle = unsafe { CreateJobObjectW(null_mut(), null()) };
        ensure!(
            !handle.is_null(),
            "create job: {}",
            std::io::Error::last_os_error()
        );
        let owner = Self {
            handle,
            state: Lifecycle::Prepared,
        };
        let wanted = ExtendedLimits {
            basic: BasicLimits {
                job_time: i64::from(limits.cpu_seconds) * 10_000_000,
                flags: if limits == JobLimits::ownership() {
                    KILL_ON_CLOSE
                } else if limits == JobLimits::security_bootstrap() {
                    KILL_ON_CLOSE | 8
                } else {
                    REQUIRED_LIMITS
                },
                processes: limits.processes,
                ..Default::default()
            },
            process_memory: limits.process_memory,
            job_memory: limits.job_memory,
            ..Default::default()
        };
        // SAFETY: owned job, exact initialized native structure and size.
        ensure!(
            unsafe {
                SetInformationJobObject(
                    handle,
                    9,
                    (&wanted as *const ExtendedLimits).cast(),
                    size_of::<ExtendedLimits>() as u32,
                )
            } != 0,
            "set job limits: {}",
            std::io::Error::last_os_error()
        );
        let mut actual: ExtendedLimits = unsafe { zeroed() };
        let mut returned = 0;
        // SAFETY: writable native output storage remains live for the query.
        ensure!(
            unsafe {
                QueryInformationJobObject(
                    handle,
                    9,
                    (&mut actual as *mut ExtendedLimits).cast(),
                    size_of::<ExtendedLimits>() as u32,
                    &mut returned,
                )
            } != 0,
            "query job limits: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            returned as usize == size_of::<ExtendedLimits>()
                && actual.basic.flags == wanted.basic.flags
                && actual.basic.processes == limits.processes
                && actual.basic.job_time == wanted.basic.job_time
                && actual.process_memory == limits.process_memory
                && actual.job_memory == limits.job_memory,
            "kernel job limits differ from required values"
        );
        if limits.cpu_seconds != 0 {
            let cpu = CpuLimits {
                flags: 5,
                rate: 1000,
            };
            // SAFETY: exact native CPU limit structure, live owned job.
            ensure!(
                unsafe {
                    SetInformationJobObject(
                        handle,
                        15,
                        (&cpu as *const CpuLimits).cast(),
                        size_of::<CpuLimits>() as u32,
                    )
                } != 0,
                "set job CPU rate"
            );
            let mut actual_cpu = CpuLimits::default();
            // SAFETY: native output structure remains writable throughout query.
            ensure!(
                unsafe {
                    QueryInformationJobObject(
                        handle,
                        15,
                        (&mut actual_cpu as *mut CpuLimits).cast(),
                        size_of::<CpuLimits>() as u32,
                        &mut returned,
                    )
                } != 0
                    && returned as usize == size_of::<CpuLimits>()
                    && actual_cpu.flags == cpu.flags
                    && actual_cpu.rate == cpu.rate,
                "kernel CPU limits differ"
            );
        }
        Ok(owner)
    }
    pub fn terminate(&mut self) -> Result<()> {
        self.request_termination()?;
        self.reap()
    }
    fn request_termination(&mut self) -> Result<()> {
        ensure!(!self.handle.is_null(), "job is closed");
        // SAFETY: exclusive live job; termination includes every contained descendant.
        ensure!(
            unsafe { TerminateJobObject(self.handle, 125) } != 0,
            "terminate job: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    fn reap(&mut self) -> Result<()> {
        let start = Instant::now();
        loop {
            let mut value: Accounting = unsafe { zeroed() };
            let mut returned = 0;
            // SAFETY: live job and exact writable output storage.
            ensure!(
                unsafe {
                    QueryInformationJobObject(
                        self.handle,
                        1,
                        (&mut value as *mut Accounting).cast(),
                        size_of::<Accounting>() as u32,
                        &mut returned,
                    )
                } != 0,
                "query job accounting: {}",
                std::io::Error::last_os_error()
            );
            ensure!(
                returned as usize == size_of::<Accounting>(),
                "invalid job accounting length"
            );
            if value.active == 0 {
                self.state = Lifecycle::Reaped;
                return Ok(());
            }
            ensure!(
                start.elapsed() < Duration::from_secs(2),
                "job process tree was not reaped"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    /// Explicitly kill/reap descendants even after the direct child exited.
    pub fn finish(&mut self) -> Result<()> {
        self.terminate()?;
        self.close_retired()
    }
    fn close_retired(&mut self) -> Result<()> {
        let reaped = self.state == Lifecycle::Reaped;
        let handle = std::mem::replace(&mut self.handle, null_mut());
        // SAFETY: exclusively owned job closed once; raw handle is invalidated first.
        ensure!(
            unsafe { CloseHandle(handle) } != 0,
            "close job: {}",
            std::io::Error::last_os_error()
        );
        ensure!(reaped, "job closed without qualified accounting reap");
        self.state = Lifecycle::Closed;
        Ok(())
    }
}
impl Drop for WindowsJob {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: final ownership guard; KILL_ON_JOB_CLOSE prevents detached survivors.
            unsafe {
                CloseHandle(self.handle);
            }
            self.handle = null_mut();
        }
    }
}

/// Launch ownership is established before a single instruction executes.
/// This primitive enforces process/resource ownership; LPAC policy is separate.
pub fn spawn_owned(command: &mut Command, limits: JobLimits) -> Result<(Child, WindowsJob)> {
    let mut job = WindowsJob::create(limits)?;
    command.creation_flags(0x0000_0004 | 0x0800_0000); // CREATE_SUSPENDED | CREATE_NO_WINDOW
    let mut child = command.spawn().context("create suspended Windows child")?;
    job.state.advance(Lifecycle::Suspended)?;
    let process = child.as_raw_handle();
    let result = (|| {
        // SAFETY: both handles are live owned objects; suspended child cannot fork first.
        ensure!(
            unsafe { AssignProcessToJobObject(job.handle, process) } != 0,
            "assign suspended child: {}",
            std::io::Error::last_os_error()
        );
        job.state.advance(Lifecycle::Attached)?;
        let mut member = 0;
        // SAFETY: read-only query with writable scalar result.
        ensure!(
            unsafe { IsProcessInJob(process, job.handle, &mut member) } != 0 && member != 0,
            "child job membership was not confirmed"
        );
        job.state.advance(Lifecycle::Qualified)?;
        // SAFETY: only the owned, suspended, already attached process is resumed.
        ensure!(
            unsafe { NtResumeProcess(process) } == 0,
            "resume contained child failed"
        );
        job.state.advance(Lifecycle::Running)?;
        Ok(())
    })();
    if let Err(error) = result {
        let killed = child.kill();
        let waited = child.wait();
        let reaped = job.terminate();
        if killed.is_err() || waited.is_err() || reaped.is_err() {
            return Err(error.context("suspended child cleanup also failed"));
        }
        return Err(error);
    }
    Ok((child, job))
}

/// Give only SYSTEM, the owning user and the package access to a fresh scratch
/// directory. No Everyone/All Application Packages ACE is admitted.
pub fn protect_scratch(path: &Path, package_sid: &str) -> Result<()> {
    super::package_sid(package_sid)?;
    plain_path(path)?;
    ensure!(path.is_dir(), "scratch root must exist");
    let user = super::sxs::current_user_sid()?;
    // LUA can make an administrator owner deny-only. Supply the normal-token
    // half explicitly, with the same bounded Modify rights as the package half.
    let sddl = format!(
        "D:P(D;OICI;0xc0000;;;{package_sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)(A;OICI;0x1301bf;;;{user})(A;OICI;0x1301bf;;;{package_sid})S:(ML;OICI;NW;;;LW)"
    );
    apply_policy(path, &sddl)
}

/// Real positive under this still-suspended fixture child's qualified LPAC context.
fn require_scratch_write(path: &Path, process: Handle, package: &str) -> Result<()> {
    use std::{
        cell::Cell,
        io::{Read, Seek, Write},
        os::windows::{fs::OpenOptionsExt, io::IntoRawHandle},
    };
    plain_path(path)?;
    let identity = crate::identity::path_object_id(path)?;
    let probe = path.join("native-suspended-create-only-control");
    let created = Cell::new(false);
    let started = Instant::now();
    let deadline = || {
        ensure!(
            started.elapsed() <= Duration::from_secs(8),
            "owned scratch suspended control deadline exceeded"
        );
        Ok(())
    };
    let operation = super::sxs::with_authority(process, package, deadline, |qualify| {
        qualify()?;
        // Match the real worker's requested access and create-only/delete-on-close flags.
        // A collision is fatal and never authorizes deleting the existing pathname.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(0xc0010000)
            .share_mode(0)
            .custom_flags(0x04200000)
            .open(&probe)
            .context("owned scratch suspended create failed")?;
        created.set(true);
        let expected = b"native owned scratch control\0\r\n";
        let mut actual = [0u8; 32];
        let result = (|| {
            qualify()?;
            file.write_all(expected)
                .context("owned scratch suspended write failed")?;
            file.flush()
                .context("owned scratch suspended flush failed")?;
            file.sync_all()
                .context("owned scratch suspended sync failed")?;
            file.rewind()
                .context("owned scratch suspended rewind failed")?;
            file.read_exact(&mut actual[..expected.len()])
                .context("owned scratch suspended read failed")?;
            let mut tail = [0u8; 1];
            ensure!(
                actual[..expected.len()] == expected[..] && file.read(&mut tail)? == 0,
                "owned scratch suspended readback differs"
            );
            qualify()
        })();
        actual.fill(0);
        let handle = file.into_raw_handle();
        let closed = if unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) } != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error()).context("owned scratch suspended close failed")
        };
        crate::runtime::with_cleanup(result, closed)
    });
    // The context has reverted before host path/identity checks. Every acquired
    // file was independently closed; no pathname-delete fallback masks uncertainty.
    let rechecked = (|| {
        plain_path(path)?;
        ensure!(
            crate::identity::path_object_id(path)? == identity,
            "owned scratch root identity changed during suspended control"
        );
        if created.get() {
            match std::fs::symlink_metadata(&probe) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
                Ok(_) => anyhow::bail!("owned scratch suspended control did not retire"),
            }
        }
        Ok(())
    })();
    crate::runtime::with_cleanup(operation, rechecked)
}

fn protect_image(path: &Path, package_sid: &str) -> Result<()> {
    super::package_sid(package_sid)?;
    plain_path(path)?;
    ensure!(path.is_file(), "prepared image must exist");
    // Medium mandatory integrity plus package mutation deny protect the image
    // independently of its writable low-integrity parent scratch directory.
    let sddl = format!(
        "D:P(D;;0x000d0116;;;{package_sid})(A;;FA;;;SY)(A;;FA;;;OW)(A;;0x1200a9;;;{package_sid})S:(ML;;NW;;;ME)"
    );
    apply_policy(path, &sddl)
}

fn apply_policy(path: &Path, sddl: &str) -> Result<()> {
    let sddl = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let text = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor = null_mut();
    let mut bytes = 0;
    // SAFETY: live UTF-16 input and writable allocation output; released below.
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                &mut bytes,
            )
        } != 0,
        "parse scratch ACL: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: parsed native descriptor and live NUL-terminated path; set protected DACL and MIC only.
    let applied = unsafe { SetFileSecurityW(text.as_ptr(), 0x8000_0004 | 0x10, descriptor) };
    let error = if applied == 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    // SAFETY: descriptor was allocated by LocalAlloc in the conversion function.
    let released = unsafe { LocalFree(descriptor) };
    ensure!(released.is_null(), "scratch ACL cleanup failed");
    if let Some(error) = error {
        return Err(error.into());
    }
    plain_path(path)?;
    Ok(())
}

/// Observe termination without requesting mutation rights or treating access
/// denial as evidence of a reaped process.
pub fn process_exited(pid: u32) -> Result<bool> {
    ensure!(pid != 0, "invalid process identity");
    // SAFETY: opens only synchronization rights for this nonzero PID.
    let handle = unsafe { OpenProcess(0x0010_0000, 0, pid) };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        ensure!(error == 87, "query process lifetime: native error {error}");
        return Ok(true);
    }
    // SAFETY: live synchronized process handle, nonblocking wait.
    let result = unsafe { WaitForSingleObject(handle, 0) };
    let closed = unsafe { CloseHandle(handle) };
    ensure!(closed != 0, "close process observation handle");
    ensure!(result == 0 || result == 258, "invalid process wait result");
    Ok(result == 0)
}
