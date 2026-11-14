//! Real host-only activation fixture adapter. No token, registry or process authority is granted.
use super::{ActCtx, CallRole, Failures, creation_outcome, require_absent_thread_token};
use crate::{identity, windows_security::plain_path};
use anyhow::{Result, ensure};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;
use std::os::windows::{fs::OpenOptionsExt, io::IntoRawHandle};
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
        if self == Self::CollectorControl {
            return super::control::manifest_bytes(run);
        }
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
    pub assembly_metadata: Vec<String>,
}
fn assemblies(context: *mut c_void, root: &Path, start: Instant) -> Result<(u32, Vec<String>)> {
    use super::assembly::{
        decode_path, path_metadata, read_count, require_path_type, require_profile, require_size,
    };
    let root_text = root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("activation path is not Unicode"))?;
    let windows = windows_directory()?;
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
        let mut lines = Vec::new();
        let count = read_count(bytes, returned, &mut lines)?;
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
                success != 0,
                "activation assembly metadata query failed winerror={error:?}"
            );
            require_size(returned, 104)?;
            let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), 65536) };
            let kind = u32::from_le_bytes(bytes[8..12].try_into()?);
            let length = u32::from_le_bytes(bytes[12..16].try_into()?);
            let pointer = u64::from_le_bytes(bytes[72..80].try_into()?);
            require_path_type(kind)?;
            let path = decode_path(bytes, buffer.as_ptr() as u64, returned, pointer, length)?;
            lines.push(path_metadata(
                &path, root_text, &windows, index, returned, kind,
            )?);
            labels.push(qualify_file(Path::new(&path), root, &windows, index)?);
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
        Ok((count, lines))
    })();
    super::assembly::release(
        result,
        vec![Box::new(|| {
            for unit in &mut buffer {
                // SAFETY: each initialized owned query-buffer unit is uniquely borrowed here.
                unsafe { std::ptr::write_volatile(unit, 0) };
            }
            Ok(())
        })],
    )
}
fn windows_directory() -> Result<String> {
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
    Ok(String::from_utf16(&windows[..length as usize])?)
}
fn existing_plain(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    ensure!(
        path.is_absolute(),
        "native fixture inputs require absolute paths"
    );
    let ancestors = path.ancestors().collect::<Vec<_>>();
    ensure!(
        ancestors.len() <= 64,
        "native fixture path exceeds ancestor bound"
    );
    for ancestor in ancestors.into_iter().rev() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.file_attributes() & 0x400 == 0 && !metadata.file_type().is_symlink(),
            "native fixture selected input or ancestor is a reparse point"
        );
    }
    Ok(())
}
/// Qualification includes every path component, so a link at the leaf or any parent is refused.
pub fn qualify_file(
    path: &Path,
    root: &Path,
    windows: &str,
    index: u32,
) -> Result<super::assembly::AssemblyLabel> {
    let path_text = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("activation path is not Unicode"))?;
    let root_text = root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("activation root is not Unicode"))?;
    let label = super::assembly::qualify_path(path_text, root_text, windows, index)?;
    existing_plain(path)?;
    Ok(label)
}
/// Source counterpart of ActivationAssemblyAccess.CheckValidation(work), including real Windows
/// dangling and intermediate directory-link refusal, ownership-preserving cleanup, and readback.
pub fn check_assembly_validation(work: &Path) -> Result<()> {
    use std::os::windows::fs::{MetadataExt, symlink_dir};
    let operation = (|| {
        require_host()?;
        existing_plain(work)?;
        let windows = windows_directory()?;
        let python = work.join("python.exe");
        super::assembly::check_assembly_contract(
            python
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("activation fixture is not Unicode"))?,
            &windows,
        )?;
        let root = tempfile::Builder::new()
            .prefix("activation-assembly-fixture-")
            .tempdir_in(work)?;
        let leaf = root.path().join("python.exe");
        let link = root.path().join("linked");
        let mut leaf_owned = false;
        let mut link_owned = false;
        let operation = (|| {
            std::fs::write(&leaf, [0])?;
            ensure!(
                qualify_file(&leaf, &leaf, &windows, 1)? == super::assembly::AssemblyLabel::Root,
                "activation plain-file positive control failed"
            );
            std::fs::remove_file(&leaf)?;
            ensure!(
                qualify_file(&leaf, &leaf, &windows, 1).is_err(),
                "activation missing file qualified as existing plain input"
            );
            symlink_dir(root.path().join("absent"), &leaf)?;
            leaf_owned = true;
            ensure!(
                qualify_file(&leaf, &leaf, &windows, 1).is_err()
                    && std::fs::symlink_metadata(&leaf)?.file_attributes() & 0x400 != 0,
                "activation dangling fixture was followed or changed"
            );
            std::fs::remove_dir(&leaf)?;
            leaf_owned = false;
            let actual = root.path().join("actual");
            std::fs::create_dir(&actual)?;
            std::fs::write(actual.join("python.exe"), [0])?;
            symlink_dir(&actual, &link)?;
            link_owned = true;
            let alias = link.join("python.exe");
            ensure!(
                qualify_file(&alias, &alias, &windows, 1).is_err(),
                "activation intermediate directory link was accepted"
            );
            Ok(())
        })();
        let mut root = Some(root);
        super::assembly::release(
            operation,
            vec![
                Box::new(|| {
                    if leaf_owned {
                        std::fs::remove_dir(&leaf)?;
                    }
                    Ok(())
                }),
                Box::new(|| {
                    if link_owned {
                        std::fs::remove_dir(&link)?;
                    }
                    Ok(())
                }),
                Box::new(|| {
                    root.take().unwrap().close()?;
                    Ok(())
                }),
            ],
        )
    })();
    operation.map_err(|error| {
        crate::windows_security::sxs::safe(error, "activation-assembly-validation")
    })
}
struct CollectorControl<'a> {
    path: &'a Path,
    expected: Vec<u8>,
    call: super::FixedPathCall,
    identity: Option<identity::ObjectId>,
    start: Instant,
}
impl super::control::TraceControlIo for CollectorControl<'_> {
    type Held = File;
    fn acquire(&mut self) -> Result<File> {
        require_host()?;
        plain_path(self.path)?;
        OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(self.path)
            .map_err(|error| io_failure("open", error))
    }
    fn create(&mut self) -> Result<(usize, u32)> {
        require_host()?;
        let context = self.call.context();
        // SAFETY: fixed x64 ACTCTX with live terminated UTF-16 source storage.
        let handle = unsafe { CreateActCtxW(&context) };
        // Read failure last-error immediately before another native call, allocation or cleanup.
        let error = if handle as usize == usize::MAX {
            unsafe { GetLastError() }
        } else {
            0
        };
        Ok((handle as usize, error))
    }
    fn release(&mut self, handle: usize) -> Result<()> {
        // SAFETY: execute transfers each unexpected valid context to this release exactly once.
        unsafe { ReleaseActCtx(handle as *mut c_void) };
        Ok(())
    }
    fn readback(&mut self, held: &mut File) -> Result<()> {
        require_host()?;
        plain_path(self.path)?;
        let actual = identity::object_id(held)?;
        let expected = *self.identity.get_or_insert(actual);
        ensure!(
            actual == expected && identity::path_object_id(self.path)? == expected,
            "activation fixture identity changed"
        );
        readback(held, &self.expected)
    }
    fn close(&mut self, held: File) -> Result<()> {
        let raw = held.into_raw_handle();
        // SAFETY: the held File transfers one owned handle, consumed exactly once.
        let success = unsafe { CloseHandle(raw) };
        let error = if success == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        ensure!(
            success != 0,
            "activation held-file close failed winerror={error:?}"
        );
        Ok(())
    }
    fn deadline(&mut self) -> Result<()> {
        deadline(self.start)
    }
    fn emit(&mut self) -> Result<()> {
        Ok(())
    }
}
impl Drop for CollectorControl<'_> {
    fn drop(&mut self) {
        self.expected.fill(0);
    }
}
fn observe_collector(path: &Path, run: &str) -> Result<ManifestObservation> {
    let call = super::FixedPathCall::new(
        CallRole::StandaloneManifest,
        path.to_str()
            .ok_or_else(|| anyhow::anyhow!("activation path is not Unicode"))?,
        0,
    )?;
    let mut io = CollectorControl {
        path,
        expected: super::control::manifest_bytes(run)?,
        call,
        identity: None,
        start: Instant::now(),
    };
    super::control::execute(&mut io)?;
    Ok(ManifestObservation {
        created: false,
        error: 14001,
        assemblies: 0,
        assembly_metadata: Vec::new(),
    })
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
    if role == ManifestRole::CollectorControl {
        return observe_collector(path, run);
    }
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
        let call = super::FixedPathCall::new(
            CallRole::StandaloneManifest,
            path.to_str()
                .ok_or_else(|| anyhow::anyhow!("activation path is not Unicode"))?,
            0,
        )?;
        let context = call.context();
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
        let (assemblies, assembly_metadata) = if outcome.created {
            assemblies(handle, path, start)?
        } else {
            (0, Vec::new())
        };
        Ok(ManifestObservation {
            created: outcome.created,
            error: outcome.error,
            assemblies,
            assembly_metadata,
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

#[path = "native_dll.rs"]
mod dll;
pub use dll::{DllObservation, observe_explicit_host_fixture, observe_fixed_dll};
