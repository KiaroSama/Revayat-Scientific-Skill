//! Real host-only activation fixture adapter. No token, registry or process authority is granted.
use super::{ActCtx, CallRole, Failures, creation_outcome, require_absent_thread_token};
use crate::{identity, windows_security::plain_path};
use anyhow::{Result, ensure};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;
use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::IntoRawHandle};
use std::path::{Component, Path};
use std::time::{Duration, Instant};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateActCtxW(context: *const ActCtx) -> *mut c_void;
    fn ReleaseActCtx(context: *mut c_void);
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn GetLastError() -> u32;
    fn GetCurrentThread() -> *mut c_void;
    fn QueryActCtxW(
        flags: u32,
        context: *mut c_void,
        index: *const u32,
        kind: u32,
        buffer: *mut c_void,
        capacity: usize,
        returned: *mut usize,
    ) -> i32;
    fn GetWindowsDirectoryW(buffer: *mut u16, capacity: u32) -> u32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenThreadToken(
        thread: *mut c_void,
        access: u32,
        as_self: i32,
        token: *mut *mut c_void,
    ) -> i32;
}
/// A denied query is not absence. Never changes the caller's current identity.
pub fn require_host() -> Result<()> {
    let mut token = std::ptr::null_mut();
    // SAFETY: current-thread pseudo-handle is borrowed, output token is owned below.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), 8, 1, &mut token) };
    let error = if opened == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let result = require_absent_thread_token(opened != 0, error, token as usize);
    if !token.is_null() && token as usize != usize::MAX {
        // SAFETY: any unexpected real query output is closed exactly once before refusal.
        if unsafe { CloseHandle(token) } == 0 {
            let error = unsafe { GetLastError() };
            let mut errors = result.err().into_iter().collect::<Vec<_>>();
            errors.push(anyhow::anyhow!(
                "activation thread-token close failed winerror={error}"
            ));
            return Err(Failures { errors }.into());
        }
    }
    result
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestRole {
    Host,
    CollectorControl,
}
impl ManifestRole {
    pub fn filename(self) -> &'static str {
        match self {
            Self::Host => "activation-host.manifest",
            Self::CollectorControl => "collector.manifest",
        }
    }
    pub fn bytes(self, run: &str) -> Result<Vec<u8>> {
        ensure!(
            run.len() == 32
                && run
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid activation fixture run identity"
        );
        let namespace = if self == Self::Host {
            " xmlns=\"urn:schemas-microsoft-com:asm.v1\""
        } else {
            ""
        };
        let name = if self == Self::Host {
            "HostControl"
        } else {
            "TraceControl"
        };
        Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<assembly{namespace} manifestVersion=\"1.0\"><assemblyIdentity type=\"win32\" version=\"1.0.0.0\" name=\"Scientific.Security.{name}.{run}\"/></assembly>\n").into_bytes())
    }
}
fn io_failure(operation: &'static str, error: std::io::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "activation fixture I/O failed operation={operation} winerror={:?}",
        error.raw_os_error()
    )
}
fn readback(file: &mut File, expected: &[u8]) -> Result<()> {
    let metadata = file.metadata().map_err(|e| io_failure("metadata", e))?;
    ensure!(
        metadata.is_file() && metadata.len() == expected.len() as u64,
        "activation fixture size or role differs"
    );
    file.seek(SeekFrom::Start(0))
        .map_err(|e| io_failure("seek", e))?;
    let mut actual = vec![0; expected.len() + 1];
    let result = (|| {
        let mut offset = 0;
        while offset < actual.len() {
            let read = file
                .read(&mut actual[offset..])
                .map_err(|e| io_failure("read", e))?;
            if read == 0 {
                break;
            }
            offset += read;
        }
        ensure!(
            offset == expected.len() && actual[..offset] == *expected,
            "activation fixture content differs"
        );
        Ok(())
    })();
    actual.fill(0);
    result
}
fn deadline(start: Instant) -> Result<()> {
    ensure!(
        start.elapsed() < Duration::from_secs(10),
        "activation fixture deadline exceeded"
    );
    Ok(())
}
#[derive(Debug)]
pub struct ManifestObservation {
    pub created: bool,
    pub error: u32,
    pub assemblies: u32,
}
fn assemblies(context: *mut c_void, root: &Path, start: Instant) -> Result<u32> {
    use super::assembly::{assembly_count, decode_path, qualify_path, require_profile};
    let root_text = root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("activation path is not Unicode"))?;
    let mut windows = [0u16; 32768];
    let length = unsafe { GetWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) };
    let error = if length == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    ensure!(
        length > 0 && (length as usize) < windows.len(),
        "Windows directory query failed winerror={error:?}"
    );
    let windows = String::from_utf16(&windows[..length as usize])?;
    let mut buffer = vec![0u64; 8192];
    let result = (|| {
        let mut returned = 0;
        require_host()?;
        deadline(start)?;
        // SAFETY: retained valid activation context, aligned writable allocation of exactly64KiB.
        let success = unsafe {
            QueryActCtxW(
                0,
                context,
                std::ptr::null(),
                2,
                buffer.as_mut_ptr().cast(),
                65536,
                &mut returned,
            )
        };
        let error = if success == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        ensure!(
            success != 0,
            "activation assembly count query failed winerror={error:?}"
        );
        let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), 65536) };
        let count = assembly_count(bytes, returned)?;
        let mut labels = Vec::new();
        for index in 1..=count {
            buffer.fill(0);
            returned = 0;
            require_host()?;
            deadline(start)?;
            let success = unsafe {
                QueryActCtxW(
                    0,
                    context,
                    &index,
                    3,
                    buffer.as_mut_ptr().cast(),
                    65536,
                    &mut returned,
                )
            };
            let error = if success == 0 {
                Some(unsafe { GetLastError() })
            } else {
                None
            };
            ensure!(
                success != 0 && (104..=65536).contains(&returned),
                "activation assembly metadata query failed winerror={error:?}"
            );
            let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), 65536) };
            let kind = u32::from_le_bytes(bytes[8..12].try_into()?);
            let length = u32::from_le_bytes(bytes[12..16].try_into()?);
            let pointer = u64::from_le_bytes(bytes[72..80].try_into()?);
            ensure!(
                kind == 2,
                "activation assembly manifest is not a Win32 file"
            );
            let path = decode_path(bytes, buffer.as_ptr() as u64, returned, pointer, length)?;
            labels.push(qualify_path(&path, root_text, &windows, index)?);
            plain_path(Path::new(&path))?;
            require_host()?;
            let file = OpenOptions::new()
                .read(true)
                .share_mode(7)
                .custom_flags(0x00200000)
                .open(&path)
                .map_err(|e| io_failure("assembly-open", e))?;
            let raw = file.into_raw_handle();
            let closed = unsafe { CloseHandle(raw) };
            let error = if closed == 0 {
                Some(unsafe { GetLastError() })
            } else {
                None
            };
            ensure!(
                closed != 0,
                "activation assembly file close failed winerror={error:?}"
            );
        }
        require_profile(&labels, count as usize)?;
        require_host()?;
        deadline(start)?;
        Ok(count)
    })();
    buffer.fill(0);
    result
}
/// Calls CreateActCtxW against one exact held project-owned fixture, then releases and rechecks it.
/// Success proves this host operation only; it never proves LPAC equivalence or trace visibility.
pub fn observe_manifest(path: &Path, run: &str, role: ManifestRole) -> Result<ManifestObservation> {
    ensure!(
        size_of::<usize>() == 8 && size_of::<ActCtx>() == 56,
        "activation fixture requires Windows x64 ABI"
    );
    ensure!(
        path.is_absolute()
            && path.file_name().is_some_and(|name| name == role.filename())
            && !path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir)),
        "activation fixture path or role differs"
    );
    require_host()?;
    plain_path(path)?;
    let expected = role.bytes(run)?;
    let start = Instant::now();
    // FILE_SHARE_READ excludes writers/deletion for the full native observation and readback.
    let mut held = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(path)
        .map_err(|e| io_failure("open", e))?;
    let mut activation = std::ptr::null_mut();
    let result = (|| {
        deadline(start)?;
        let identity = identity::object_id(&held)?;
        require_host()?;
        readback(&mut held, &expected)?;
        let source = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        ensure!(
            source.len() <= 32768 && !source[..source.len() - 1].contains(&0),
            "activation fixture path encoding differs"
        );
        let context = ActCtx::fixed(CallRole::StandaloneManifest, source.as_ptr() as usize, 0, 0);
        deadline(start)?;
        require_host()?;
        // SAFETY: fixed x64 ACTCTX and all UTF-16 backing storage remain live throughout the call.
        let handle = unsafe { CreateActCtxW(&context) };
        // Capture the failure code before any other native call, allocation, formatting or cleanup.
        let outcome = creation_outcome(handle as usize, || unsafe { GetLastError() });
        if !handle.is_null() && handle as usize != usize::MAX {
            activation = handle;
        }
        let outcome = outcome?;
        require_host()?;
        deadline(start)?;
        readback(&mut held, &expected)?;
        plain_path(path)?;
        ensure!(
            identity::object_id(&held)? == identity && identity::path_object_id(path)? == identity,
            "activation fixture identity changed"
        );
        ensure!(
            outcome.created == (role == ManifestRole::Host)
                && outcome.error == (if role == ManifestRole::Host { 0 } else { 14001 }),
            "activation host/collector control outcome differs"
        );
        let assemblies = if outcome.created {
            assemblies(handle, path, start)?
        } else {
            0
        };
        Ok(ManifestObservation {
            created: outcome.created,
            error: outcome.error,
            assemblies,
        })
    })();
    let mut failures = Vec::new();
    if !activation.is_null() {
        // SAFETY: exactly one valid CreateActCtxW result is owned here; it is never activated.
        unsafe { ReleaseActCtx(activation) };
    }
    match require_host() {
        Ok(()) => {
            if let Err(error) = readback(&mut held, &expected) {
                failures.push(error);
            }
        }
        Err(error) => failures.push(error),
    }
    let raw = held.into_raw_handle();
    // SAFETY: ownership was transferred from File and is consumed once, including on primary error.
    if unsafe { CloseHandle(raw) } == 0 {
        let error = unsafe { GetLastError() };
        failures.push(anyhow::anyhow!(
            "activation held-file close failed winerror={error}"
        ));
    }
    if let Err(error) = deadline(start) {
        failures.push(error);
    }
    if failures.is_empty() {
        return result;
    }
    if let Err(primary) = result {
        failures.insert(0, primary);
    }
    Err(Failures { errors: failures }.into())
}
