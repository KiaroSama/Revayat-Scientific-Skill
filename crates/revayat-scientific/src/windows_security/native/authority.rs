//! Fixed authoritative registry probe in an owned, zero-capability LPAC.
use super::*;
use crate::windows_security::{Capture, ERROR_LIMIT, OUTPUT_LIMIT, privilege_inventory};
use std::io::Write;

#[path = "authority_abi.rs"]
mod abi;
use abi::*;

pub(super) fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

pub(super) struct Descriptor(pub(super) Handle);
impl Descriptor {
    pub(super) fn new(sddl: &str) -> Result<Self> {
        let text = wide(sddl);
        let mut descriptor = null_mut();
        let mut bytes = 0;
        // SAFETY: live terminated SDDL and initialized output slots.
        ensure!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut descriptor,
                    &mut bytes,
                )
            } != 0,
            "parse owned process security"
        );
        ensure!(
            !descriptor.is_null() && (20..=65536).contains(&bytes),
            "invalid process descriptor"
        );
        Ok(Self(descriptor))
    }
    pub(super) fn close(&mut self) -> Result<()> {
        if !self.0.is_null() {
            let descriptor = std::mem::replace(&mut self.0, null_mut());
            ensure!(
                unsafe { LocalFree(descriptor) }.is_null(),
                "process descriptor cleanup failed"
            );
        }
        Ok(())
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

struct Owned(Handle);
impl Owned {
    fn checked(handle: Handle) -> Result<Self> {
        ensure!(
            !handle.is_null() && handle as isize != -1,
            "invalid native owner"
        );
        Ok(Self(handle))
    }
    fn close(&mut self) -> Result<()> {
        if self.0.is_null() {
            return Ok(());
        }
        let handle = std::mem::replace(&mut self.0, null_mut());
        // SAFETY: exclusive handle ownership invalidated before close.
        ensure!(
            unsafe { CloseHandle(handle) } != 0,
            "native handle cleanup failed"
        );
        Ok(())
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
fn restricted_primary() -> Result<Owned> {
    let mut original = null_mut();
    // SAFETY: borrowed pseudo handle; returned primary-token handle immediately owned.
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), 0xb, &mut original) } != 0,
        "open primary for restricted copy"
    );
    let mut original = Owned::checked(original)?;
    // Complete binary SID S-1-5-32-544, with native DWORD alignment.
    let mut administrator = [0x0000_0201u32, 0x0500_0000, 32, 544];
    let disabled = SidAttributes {
        sid: administrator.as_mut_ptr().cast(),
        attributes: 0,
    };
    let mut restricted = null_mut();
    // SAFETY: exact live SID_AND_ATTRIBUTES; create a restricted LUA primary,
    // never SANDBOX_INERT and never an unrestricted fallback.
    let success = unsafe {
        CreateRestrictedToken(
            original.0,
            5,
            1,
            &disabled,
            0,
            null_mut(),
            0,
            null_mut(),
            &mut restricted,
        )
    };
    let owner = Owned(restricted);
    original.close()?;
    ensure!(
        success != 0 && !owner.0.is_null(),
        "create restricted LUA primary failed"
    );
    Ok(owner)
}
struct Profile {
    name: Vec<u16>,
    sid: Handle,
}
impl Profile {
    fn new() -> Result<Self> {
        let nonce = tempfile::Builder::new()
            .prefix("revayat-profile-")
            .tempdir()?;
        let name = wide(nonce.path().file_name().context("profile nonce")?);
        let mut sid = null_mut();
        // SAFETY: live terminated name; empty capability set; returned SID owned below.
        ensure!(
            unsafe {
                CreateAppContainerProfile(
                    name.as_ptr(),
                    name.as_ptr(),
                    name.as_ptr(),
                    null_mut(),
                    0,
                    &mut sid,
                )
            } == 0,
            "create owned AppContainer profile"
        );
        ensure!(!sid.is_null(), "profile SID unavailable");
        Ok(Self { name, sid })
    }
    fn sid_text(&self) -> Result<String> {
        let mut text = null_mut();
        // SAFETY: profile owns SID; conversion allocation is released after bounded read.
        ensure!(
            unsafe { ConvertSidToStringSidW(self.sid, &mut text) } != 0,
            "convert package SID"
        );
        let result = (|| {
            let mut length = 0;
            while length < 256 && unsafe { *text.add(length) } != 0 {
                length += 1;
            }
            ensure!(length < 256, "package SID exceeds bound");
            // SAFETY: terminator was located in native SID string allocation.
            Ok(String::from_utf16(unsafe {
                std::slice::from_raw_parts(text, length)
            })?)
        })();
        // SAFETY: native conversion used LocalAlloc.
        ensure!(
            unsafe { LocalFree(text.cast()) }.is_null(),
            "SID text cleanup failed"
        );
        result
    }
    fn close(&mut self) -> Result<()> {
        if self.sid.is_null() {
            return Ok(());
        }
        let sid = std::mem::replace(&mut self.sid, null_mut());
        // SAFETY: FreeSid releases exact owned profile SID; delete exact generated profile only.
        let freed = unsafe { FreeSid(sid) }.is_null();
        let deleted = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) } == 0;
        ensure!(freed && deleted, "owned profile cleanup failed");
        Ok(())
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
struct Attributes {
    data: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn new() -> Result<Self> {
        let mut size = 0;
        // SAFETY: size-only call cannot dereference null list.
        unsafe { InitializeProcThreadAttributeList(null_mut(), 3, 0, &mut size) };
        ensure!(
            (1..=65536).contains(&size),
            "invalid process attribute size"
        );
        let mut value = Self {
            data: vec![0; size.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        // SAFETY: aligned allocation spans requested size and remains live until deletion.
        ensure!(
            unsafe {
                InitializeProcThreadAttributeList(value.data.as_mut_ptr().cast(), 3, 0, &mut size)
            } != 0,
            "initialize process attributes"
        );
        value.initialized = true;
        Ok(value)
    }
    fn set(&mut self, key: usize, pointer: Handle, size: usize) -> Result<()> {
        // SAFETY: caller retains pointed attribute values until after CreateProcessW.
        ensure!(
            unsafe {
                UpdateProcThreadAttribute(
                    self.data.as_mut_ptr().cast(),
                    0,
                    key,
                    pointer,
                    size,
                    null_mut(),
                    null_mut(),
                )
            } != 0,
            "set process attribute"
        );
        Ok(())
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe { DeleteProcThreadAttributeList(self.data.as_mut_ptr().cast()) };
        }
    }
}
fn pipe() -> Result<(Owned, Owned)> {
    let mut read = null_mut();
    let mut write = null_mut();
    let security = Security {
        size: size_of::<Security>() as u32,
        descriptor: null_mut(),
        inherit: 1,
    };
    // SAFETY: exact writable handle slots and live attributes.
    let success = unsafe { CreatePipe(&mut read, &mut write, &security, 4096) };
    let reader = Owned(read);
    let writer = Owned(write);
    ensure!(
        success != 0 && !reader.0.is_null() && !writer.0.is_null(),
        "create capture pipe"
    );
    // SAFETY: read endpoint remains exclusively in controller.
    ensure!(
        unsafe { SetHandleInformation(reader.0, 1, 0) } != 0,
        "disable capture reader inheritance"
    );
    Ok((reader, writer))
}
fn remove_privileges(process: Handle) -> Result<()> {
    let mut raw = null_mut();
    // SAFETY: owned suspended process; returned token immediately owned.
    ensure!(
        unsafe { OpenProcessToken(process, 0x28, &mut raw) } != 0,
        "open suspended worker token"
    );
    let mut token = Owned::checked(raw)?;
    let mut size = 0;
    unsafe { GetTokenInformation(token.0, 3, null_mut(), 0, &mut size) };
    ensure!((4..=65536).contains(&size), "invalid privilege query size");
    let mut data = vec![0u32; (size as usize).div_ceil(4)];
    let capacity = size;
    // SAFETY: aligned writable allocation covers advertised capacity.
    ensure!(
        unsafe { GetTokenInformation(token.0, 3, data.as_mut_ptr().cast(), capacity, &mut size) }
            != 0
            && size <= capacity,
        "read worker privilege inventory"
    );
    let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), size as usize) };
    ensure!(bytes.len() >= 4, "short privilege header");
    let count = u32::from_le_bytes(bytes[..4].try_into()?) as usize;
    ensure!(
        count <= 128 && 4 + count * 12 <= bytes.len(),
        "invalid privilege inventory"
    );
    let mut remove = vec![0u32];
    for entry in bytes[4..4 + count * 12].as_chunks::<12>().0 {
        let luid = u64::from_le_bytes(entry[..8].try_into()?);
        if luid != 23 {
            remove[0] += 1;
            remove.extend([luid as u32, (luid >> 32) as u32, 4]);
        }
    }
    if remove[0] > 0 {
        // SAFETY: packed TOKEN_PRIVILEGES with native 4-byte alignment, exact count and entries.
        unsafe { SetLastError(0) };
        let success = unsafe {
            AdjustTokenPrivileges(
                token.0,
                0,
                remove.as_ptr().cast(),
                0,
                null_mut(),
                null_mut(),
            )
        };
        let error = unsafe { GetLastError() };
        ensure!(
            success != 0 && error == 0,
            "worker privileges were not fully removed"
        );
    }
    // SAFETY: reuse owned bounded allocation and validate returned span independently.
    ensure!(
        unsafe { GetTokenInformation(token.0, 3, data.as_mut_ptr().cast(), capacity, &mut size) }
            != 0
            && size <= capacity,
        "read final worker privileges"
    );
    privilege_inventory(
        unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), capacity as usize) },
        size as usize,
    )?;
    data.fill(0);
    remove.fill(0);
    token.close()
}
fn drain(pipe: &Owned, capture: &mut Capture, limit: usize) -> Result<()> {
    for _ in 0..=limit {
        let mut available = 0;
        // SAFETY: read-only pipe query and writable scalar output.
        let success = unsafe {
            PeekNamedPipe(
                pipe.0,
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        };
        if success == 0 {
            ensure!(
                unsafe { GetLastError() } == 109,
                "capture pipe query failed"
            );
            capture.end();
            return Ok(());
        }
        if available == 0 {
            return Ok(());
        }
        let mut buffer = [0u8; 1024];
        let capacity = (available as usize).min(buffer.len());
        let mut read = 0;
        // SAFETY: live owned pipe, writable stack buffer, capacity does not exceed storage.
        ensure!(
            unsafe {
                ReadFile(
                    pipe.0,
                    buffer.as_mut_ptr().cast(),
                    capacity as u32,
                    &mut read,
                    null_mut(),
                )
            } != 0
                && read > 0
                && read as usize <= capacity,
            "capture pipe read failed"
        );
        capture.append(&buffer[..read as usize], limit)?;
    }
    anyhow::bail!("capture read budget exhausted")
}

/// Run only the fixed native verifier. A host launch cannot satisfy this API.
/// Success requires the primary AND descendant's actual token/registry proofs.
pub fn run_registry_authority(image: &Path) -> Result<String> {
    plain_path(image)?;
    ensure!(image.is_file(), "authority image is missing");
    let mut profile = Profile::new()?;
    let sid = profile.sid_text()?;
    let network = super::network::NetworkControls::new()?;
    let mut registry = super::fixture::RegistryFixture::new(&sid)?;
    let foreign = tempfile::Builder::new()
        .prefix("revayat-private-control-")
        .tempdir()?;
    let foreign_file = foreign.path().join("private-sentinel");
    std::fs::write(&foreign_file, b"owned private sentinel\0\r\n")?;
    super::fixture::protect_foreign(foreign.path(), &sid)?;
    super::fixture::protect_foreign(&foreign_file, &sid)?;
    let foreign_identity = crate::identity::file_identity(&foreign_file, None)?;
    let prepared = tempfile::Builder::new()
        .prefix("revayat-authority-")
        .tempdir()?;
    protect_scratch(prepared.path(), &sid)?;
    let target = prepared.path().join("registry-authority.exe");
    let source = crate::identity::file_identity(image, Some(8 * 1024 * 1024))?;
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&target)?;
    let mut input = std::fs::File::open(image)?;
    std::io::copy(&mut input, &mut output)?;
    output.flush()?;
    output.sync_all()?;
    drop(output);
    let copied = crate::identity::file_identity(&target, Some(8 * 1024 * 1024))?;
    ensure!(
        source.same_bytes(&copied)
            && crate::identity::file_identity(image, Some(8 * 1024 * 1024))? == source,
        "authority image changed during preparation"
    );
    protect_image(&target, &sid)?;
    let (mut stdout, mut stdout_writer) = pipe()?;
    let (mut stderr, mut stderr_writer) = pipe()?;
    let security = Security {
        size: size_of::<Security>() as u32,
        descriptor: null_mut(),
        inherit: 1,
    };
    let nul = wide("NUL");
    let mut stdin = Owned::checked(unsafe {
        CreateFileW(nul.as_ptr(), 0x80000000, 3, &security, 3, 0x80, null_mut())
    })?;
    let mut attributes = Attributes::new()?;
    let mut capabilities = Capabilities {
        sid: profile.sid,
        capabilities: null_mut(),
        count: 0,
        reserved: 0,
    };
    let mut lpac = 1u32;
    let mut handles = [stdin.0, stdout_writer.0, stderr_writer.0];
    attributes.set(
        0x20009,
        (&mut capabilities as *mut Capabilities).cast(),
        size_of::<Capabilities>(),
    )?;
    attributes.set(0x2000f, (&mut lpac as *mut u32).cast(), 4)?;
    attributes.set(0x20002, handles.as_mut_ptr().cast(), size_of_val(&handles))?;
    let startup = StartupEx {
        startup: Startup {
            size: size_of::<StartupEx>() as u32,
            flags: 0x100,
            input: stdin.0,
            output: stdout_writer.0,
            error: stderr_writer.0,
            ..Default::default()
        },
        attributes: attributes.data.as_mut_ptr().cast(),
    };
    let target_wide = wide(&target);
    let mut command = wide(format!("\"{}\"", target.display()));
    let cwd = wide(prepared.path());
    let root = std::env::var_os("SystemRoot").context("SystemRoot is required")?;
    let mut environment = wide(format!(
        "REVAYAT_AUTHORITY_FIXTURE={}\0REVAYAT_AUTHORITY_FOREIGN={}\0REVAYAT_AUTHORITY_NETWORK={}\0SystemRoot={}\0TEMP={}\0TMP={}\0WINDIR={}\0",
        registry.name,
        foreign_file.display(),
        network.ports,
        root.to_string_lossy(),
        prepared.path().display(),
        prepared.path().display(),
        root.to_string_lossy()
    ));
    let mut info = ProcessInfo::default();
    let mut job = WindowsJob::create(JobLimits::default())?;
    let mut restricted = restricted_primary()?;
    let mut descriptor = Descriptor::new(&format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;GA;;;{sid})S:(ML;;NW;;;LW)"
    ))?;
    let process_security = Security {
        size: size_of::<Security>() as u32,
        descriptor: descriptor.0,
        inherit: 0,
    };
    // SAFETY: every pointer references initialized live backing storage; exact three-handle allowlist;
    // explicit image, environment, cwd; no thread may run before attachment/qualification below.
    let created = unsafe {
        CreateProcessAsUserW(
            restricted.0,
            target_wide.as_ptr(),
            command.as_mut_ptr(),
            &process_security,
            &process_security,
            1,
            0x80000 | 0x400 | 8 | 4,
            environment.as_mut_ptr().cast(),
            cwd.as_ptr(),
            &startup,
            &mut info,
        )
    };
    let mut process = Owned(info.process);
    let mut thread = Owned(info.thread);
    ensure!(
        created != 0 && !process.0.is_null() && !thread.0.is_null(),
        "create suspended zero-capability LPAC authority failed"
    );
    job.state.advance(Lifecycle::Suspended)?;
    let mut out = Capture::default();
    let mut err = Capture::default();
    let execution = (|| {
        ensure!(
            unsafe { AssignProcessToJobObject(job.handle, process.0) } != 0,
            "assign authority job"
        );
        job.state.advance(Lifecycle::Attached)?;
        let mut member = 0;
        ensure!(
            unsafe { IsProcessInJob(process.0, job.handle, &mut member) } != 0 && member != 0,
            "authority job membership mismatch"
        );
        remove_privileges(process.0)?;
        job.state.advance(Lifecycle::Qualified)?;
        restricted.close()?;
        descriptor.close()?;
        stdout_writer.close()?;
        stderr_writer.close()?;
        stdin.close()?;
        ensure!(
            unsafe { NtResumeProcess(process.0) } == 0,
            "resume authority"
        );
        job.state.advance(Lifecycle::Running)?;
        let started = Instant::now();
        loop {
            drain(&stdout, &mut out, OUTPUT_LIMIT)?;
            drain(&stderr, &mut err, ERROR_LIMIT)?;
            let wait = unsafe { WaitForSingleObject(process.0, 10) };
            ensure!(wait == 0 || wait == 258, "authority wait failed");
            if wait == 0 {
                break;
            }
            ensure!(
                started.elapsed() < Duration::from_secs(20),
                "authority wall deadline exceeded"
            );
        }
        let mut code = 0;
        ensure!(
            unsafe { GetExitCodeProcess(process.0, &mut code) } != 0,
            "authority exit query failed"
        );
        // Kill/reap surviving descendants before final EOF, policy restore, or profile deletion.
        job.terminate()?;
        drain(&stdout, &mut out, OUTPUT_LIMIT)?;
        drain(&stderr, &mut err, ERROR_LIMIT)?;
        let output = out.finish(OUTPUT_LIMIT)?;
        let errors = err.finish(ERROR_LIMIT)?;
        ensure!(
            code == 0 && errors.is_empty(),
            "native authority refused containment exit={code:08X}"
        );
        let lines = output.split_inclusive('\n').collect::<Vec<_>>();
        ensure!(
            lines.len() == 2,
            "authority must provide two complete records"
        );
        let child = registry_authority::protocol::fixture_child_record(lines[1].as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid descendant authority frame"))?;
        ensure!(
            child
                == registry_authority::protocol::fixture_record("descendant", 1, 0)
                    .map_err(|_| anyhow::anyhow!("invalid fixed fixture record"))?,
            "owned fixture inventory differs"
        );
        let expected = child.replace("\"role\":\"descendant\"", "\"role\":\"primary\"");
        // Native controls guarantee accessible=0; permissive source-oracle fixtures are not admission.
        ensure!(
            lines[0] == expected && lines[0].starts_with("{\"accessible\":0,"),
            "primary and descendant authority differ"
        );
        Ok(output.to_owned())
    })();
    let mut cleanup = Vec::new();
    // A failed assignment must also reap a still-suspended, not-yet-job-owned child.
    let wait = unsafe { WaitForSingleObject(process.0, 0) };
    if wait == 258 {
        let killed = unsafe { TerminateProcess(process.0, 125) };
        let waited = unsafe { WaitForSingleObject(process.0, 2000) };
        if killed == 0 || waited != 0 {
            cleanup.push("process");
        }
    } else if wait != 0 {
        cleanup.push("process");
    }
    if job.finish().is_err() {
        cleanup.push("job");
    }
    drop(job);
    for owned in [
        &mut thread,
        &mut process,
        &mut stdin,
        &mut stdout_writer,
        &mut stderr_writer,
        &mut stdout,
        &mut stderr,
    ] {
        if owned.close().is_err() {
            cleanup.push("handle");
        }
    }
    if restricted.close().is_err() {
        cleanup.push("restricted-token");
    }
    if descriptor.close().is_err() {
        cleanup.push("descriptor");
    }
    drop(attributes);
    out.clear();
    err.clear();
    drop(input);
    match crate::identity::file_identity(&foreign_file, None) {
        Ok(current) if current == foreign_identity => {}
        _ => cleanup.push("private-sentinel"),
    }
    if registry.close().is_err() {
        cleanup.push("registry-fixture");
    }
    if prepared.close().is_err() {
        cleanup.push("scratch");
    }
    if foreign.close().is_err() {
        cleanup.push("private-fixture");
    }
    if profile.close().is_err() {
        cleanup.push("profile");
    }
    if cleanup.is_empty() {
        return execution;
    }
    match execution {
        Err(primary) => Err(primary.context(format!(
            "authority cleanup also failed in {} owned operations",
            cleanup.len()
        ))),
        Ok(_) => anyhow::bail!(
            "authority cleanup failed in {} owned operations",
            cleanup.len()
        ),
    }
}
