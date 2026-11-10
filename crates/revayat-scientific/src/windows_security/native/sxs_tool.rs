//! Fixed System32 sxstrace child with exact HANDLE_LIST, resource bounds and independent reaping.
use super::*;
use crate::windows_security::activation::native::require_host;
use std::os::windows::{fs::OpenOptionsExt, io::IntoRawHandle};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, capacity: u32) -> u32;
    fn GetWindowsDirectoryW(buffer: *mut u16, capacity: u32) -> u32;
}
pub(super) fn arguments(folder: &Path, parse: bool) -> Result<Vec<String>> {
    let folder = folder
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("SxS tool folder encoding differs"))?;
    let bytes = folder.as_bytes();
    ensure!(
        bytes.len() == 45
            && (b'D'..=b'Z').contains(&bytes[0])
            && &bytes[1..13] == b":\\sxs-trace-"
            && bytes[13..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
        "SxS fixed tool folder differs"
    );
    let mut args = vec![
        if parse { "parse" } else { "trace" }.to_owned(),
        format!("-logfile:{folder}\\capture.etl"),
    ];
    args.push(if parse {
        format!("-outfile:{folder}\\capture.txt")
    } else {
        "-nostop".to_owned()
    });
    Ok(args)
}
#[derive(Default)]
struct Discard {
    bytes: usize,
    eof: bool,
}
impl Discard {
    fn accept(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            !self.eof && bytes.len() <= 1_048_576usize.saturating_sub(self.bytes),
            "SxS fixed tool output exceeded capture bound"
        );
        self.bytes += bytes.len();
        Ok(())
    }
    fn drain(&mut self, pipe: &Owned) -> Result<()> {
        for _ in 0..=1024 {
            let mut available = 0;
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
            let code = if success == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            if success == 0 {
                ensure!(
                    code == 109,
                    "SxS fixed tool capture query failed winerror={code}"
                );
                self.eof = true;
                return Ok(());
            }
            if available == 0 {
                return Ok(());
            }
            let mut buffer = [0u8; 4096];
            let capacity = (available as usize).min(buffer.len());
            let mut read = 0;
            let success = unsafe {
                ReadFile(
                    pipe.0,
                    buffer.as_mut_ptr().cast(),
                    capacity as u32,
                    &mut read,
                    null_mut(),
                )
            };
            let code = if success == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            let result = (|| {
                ensure!(
                    success != 0 && read > 0 && read as usize <= capacity,
                    "SxS fixed tool capture read failed winerror={code}"
                );
                self.accept(&buffer[..read as usize])
            })();
            buffer.fill(0);
            result?;
        }
        anyhow::bail!("SxS fixed tool capture drain budget exhausted")
    }
}
fn directory(system: bool) -> Result<std::path::PathBuf> {
    let mut output = [0u16; 32768];
    let length = unsafe {
        if system {
            GetSystemDirectoryW(output.as_mut_ptr(), 32768)
        } else {
            GetWindowsDirectoryW(output.as_mut_ptr(), 32768)
        }
    };
    let code = if length == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    ensure!(
        (3..32768).contains(&length),
        "SxS fixed system directory query failed winerror={code}"
    );
    let path = std::path::PathBuf::from(String::from_utf16(&output[..length as usize])?);
    plain_path(&path)?;
    ensure!(
        path.is_absolute() && path.is_dir(),
        "SxS fixed system directory differs"
    );
    Ok(path)
}
/// A nonzero exit, any stderr bytes, uncertain cleanup, or a surviving child is always failure.
pub(crate) fn run(folder: &Path, parse: bool, reaped: &mut bool) -> Result<()> {
    require_host()?;
    let args = arguments(folder, parse)?;
    plain_path(folder)?;
    let system = directory(true)?;
    let windows = directory(false)?;
    let image = system.join("sxstrace.exe");
    plain_path(&image)?;
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(&image)?;
    let identity = crate::identity::object_id(&held)?;
    ensure!(
        crate::identity::path_object_id(&image)? == identity && held.metadata()?.is_file(),
        "SxS fixed system tool identity differs"
    );
    let (mut stdout, mut stdout_writer) = pipe()?;
    let (mut stderr, mut stderr_writer) = pipe()?;
    let security = Security {
        size: size_of::<Security>() as u32,
        descriptor: null_mut(),
        inherit: 1,
    };
    let mut stdin = Owned::checked(unsafe {
        CreateFileW(
            wide("NUL").as_ptr(),
            0x80000000,
            3,
            &security,
            3,
            0x80,
            null_mut(),
        )
    })?;
    let mut attributes = Attributes::with_count(1)?;
    let mut handles = [stdin.0, stdout_writer.0, stderr_writer.0];
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
    let image_wide = wide(&image);
    let cwd = wide(folder);
    let mut command = wide(format!(
        "\"{}\" {}",
        image.display(),
        args.iter()
            .map(|arg| format!("\"{arg}\""))
            .collect::<Vec<_>>()
            .join(" ")
    ));
    let mut environment = wide(format!(
        "PATH={}\0SystemRoot={}\0TEMP={}\0TMP={}\0WINDIR={}\0",
        system.display(),
        windows.display(),
        folder.display(),
        folder.display(),
        windows.display()
    ));
    let mut info = ProcessInfo::default();
    let mut process = Owned(null_mut());
    let mut thread = Owned(null_mut());
    let mut job = WindowsJob::create(JobLimits {
        processes: 1,
        cpu_seconds: 10,
        ..Default::default()
    })?;
    let (mut output, mut error) = (Discard::default(), Discard::default());
    let started = Instant::now();
    let mut attempted = false;
    let mut creation_succeeded = false;
    let execution = (|| {
        require_host()?;
        ensure!(
            crate::identity::path_object_id(&image)? == identity,
            "SxS fixed tool replaced before creation"
        );
        attempted = true;
        *reaped = false;
        let success = unsafe {
            registry_authority::native::CreateProcessW(
                image_wide.as_ptr(),
                command.as_mut_ptr(),
                null_mut(),
                null_mut(),
                1,
                0x80000 | 0x400 | 0x08000000 | 4,
                environment.as_mut_ptr().cast(),
                cwd.as_ptr(),
                (&startup as *const StartupEx).cast(),
                (&mut info as *mut ProcessInfo).cast(),
            )
        };
        let creation = creation_result(
            success,
            !info.process.is_null()
                && info.process as usize != usize::MAX
                && !info.thread.is_null()
                && info.thread as usize != usize::MAX,
            "CreateProcessW(sxstrace)",
            || unsafe { GetLastError() },
        );
        creation_succeeded = success != 0;
        process = Owned::creation_output(info.process);
        thread = Owned::creation_output(info.thread);
        creation?;
        job.state.advance(Lifecycle::Suspended)?;
        ensure!(
            unsafe { AssignProcessToJobObject(job.handle, process.0) } != 0,
            "SxS fixed tool job assignment failed"
        );
        job.state.advance(Lifecycle::Attached)?;
        let mut member = 0;
        ensure!(
            unsafe { IsProcessInJob(process.0, job.handle, &mut member) } != 0 && member != 0,
            "SxS fixed tool membership differs"
        );
        job.state.advance(Lifecycle::Qualified)?;
        ensure!(
            unsafe { NtResumeProcess(process.0) } == 0,
            "SxS fixed tool resume failed"
        );
        job.state.advance(Lifecycle::Running)?;
        stdin.close()?;
        stdout_writer.close()?;
        stderr_writer.close()?;
        loop {
            output.drain(&stdout)?;
            error.drain(&stderr)?;
            let wait = unsafe { WaitForSingleObject(process.0, 10) };
            ensure!(wait == 0 || wait == 258, "SxS fixed tool wait failed");
            ensure!(
                started.elapsed() <= Duration::from_secs(10),
                "SxS fixed tool wall deadline exceeded"
            );
            if wait == 0 {
                break;
            }
        }
        let mut code = 0;
        ensure!(
            unsafe { GetExitCodeProcess(process.0, &mut code) } != 0,
            "SxS fixed tool exit query failed"
        );
        job.terminate()?;
        output.drain(&stdout)?;
        error.drain(&stderr)?;
        ensure!(
            code == 0 && error.bytes == 0 && output.eof && error.eof,
            "SxS fixed tool completion differs exit32={code:08X} stderr_present={}",
            error.bytes != 0
        );
        ensure!(
            crate::identity::path_object_id(&image)? == identity
                && crate::identity::object_id(&held)? == identity,
            "SxS fixed system tool identity changed"
        );
        Ok(())
    })();
    let mut errors = Vec::new();
    let mut signaled = !attempted;
    if !process.0.is_null() {
        let wait = unsafe { WaitForSingleObject(process.0, 0) };
        if wait == 0 {
            signaled = true;
        } else if wait == 258 {
            let killed = unsafe { TerminateProcess(process.0, 125) };
            let waited = unsafe { WaitForSingleObject(process.0, 2000) };
            if killed != 0 && waited == 0 {
                signaled = true;
            } else {
                errors.push(anyhow::anyhow!("SxS fixed tool process cleanup failed"));
            }
        } else {
            errors.push(anyhow::anyhow!("SxS fixed tool cleanup wait failed"));
        }
    }
    let job_reaped = match job.finish() {
        Ok(()) => true,
        Err(cause) => {
            errors.push(cause);
            false
        }
    };
    drop(job);
    if attempted && process.0.is_null() && execution.is_err() {
        signaled = !creation_succeeded && info.process.is_null();
    }
    *reaped = signaled && job_reaped;
    for owned in [
        &mut thread,
        &mut process,
        &mut stdin,
        &mut stdout_writer,
        &mut stderr_writer,
        &mut stdout,
        &mut stderr,
    ] {
        if let Err(cause) = owned.close() {
            errors.push(cause);
        }
    }
    drop(attributes);
    environment.fill(0);
    command.fill(0);
    let raw = held.into_raw_handle();
    if unsafe { CloseHandle(raw) } == 0 {
        errors.push(anyhow::anyhow!("SxS fixed tool held-image close failed"));
    }
    if errors.is_empty() {
        return execution;
    }
    if let Err(primary) = execution {
        errors.insert(0, primary);
    }
    Err(crate::windows_security::activation::Failures { errors }.into())
}
#[cfg(test)]
#[path = "sxs_tool_tests.rs"]
mod tests;
