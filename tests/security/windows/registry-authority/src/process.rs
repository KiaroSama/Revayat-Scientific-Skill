use crate::native::*;
use crate::protocol::{
    Failure, RestrictionQuery, Result, child_record, cleanup_failed, descendant_native,
    descendant_need, descendant_result, token_kind,
};
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::time::{Duration, Instant};

struct Child {
    process: Handle,
    thread: Handle,
    complete: bool,
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.complete {
            // SAFETY: exact owned child only; bounded reap also runs after termination failure.
            unsafe {
                let killed = TerminateProcess(self.process.raw, 125);
                let waited = WaitForSingleObject(self.process.raw, 2000);
                if killed == 0 || waited != 0 {
                    cleanup_failed();
                }
            }
        }
    }
}

struct AttributeList {
    data: Vec<u64>,
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: successfully initialized storage remains live until after deletion.
        unsafe { DeleteProcThreadAttributeList(self.data.as_mut_ptr().cast()) };
    }
}

fn checked_input<T>(
    owned: T,
    success: bool,
    error: Option<u32>,
    valid: impl FnOnce(&T) -> bool,
) -> Result<T> {
    descendant_result(success, error, "control-input-duplicate")?;
    descendant_need(valid(&owned), "control-input-handle")?;
    Ok(owned)
}

fn input() -> Result<Handle> {
    // SAFETY: borrowed host-provisioned read-only NUL, never owned, closed or changed here.
    let borrowed = unsafe { GetStdHandle((-10i32) as u32) };
    descendant_need(
        !borrowed.is_null() && borrowed as isize != -1 && unsafe { GetFileType(borrowed) } == 2,
        "control-input-handle",
    )?;
    // SAFETY: pseudo process handles are borrowed; only the new same-access duplicate is inheritable.
    let current = unsafe { GetCurrentProcess() };
    let mut raw = null_mut();
    let success = unsafe { DuplicateHandle(current, borrowed, current, &mut raw, 0, 1, 2) };
    let error = if success == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    let owned = Handle::new(raw, false);
    checked_input(owned, success != 0, error, |handle| {
        // SAFETY: query only the valid owned duplicate; no last-error inference from file type.
        handle.valid() && unsafe { GetFileType(handle.raw) } == 2
    })
}

fn collect(
    bytes: &mut Vec<u8>,
    limit: usize,
    final_drain: bool,
    mut peek: impl FnMut() -> Result<Option<usize>>,
    mut read: impl FnMut(&mut [u8]) -> Result<usize>,
) -> Result<()> {
    // Every iteration either finishes or consumes at least one byte from the fixed budget.
    for _ in 0..=limit {
        let Some(available) = peek()? else {
            return Ok(());
        };
        descendant_need(
            available <= limit.saturating_sub(bytes.len()),
            "control-capture-limit",
        )?;
        if available == 0 {
            return descendant_need(!final_drain, "control-capture-eof");
        }
        let mut buffer = [0u8; 1024];
        let capacity = available.min(buffer.len());
        let count = read(&mut buffer[..capacity]);
        match count {
            Ok(count) if count > 0 && count <= capacity => {
                bytes.extend_from_slice(&buffer[..count])
            }
            Ok(_) => {
                buffer.fill(0);
                return Err(Failure::new("descendant", "transport"));
            }
            Err(error) => {
                buffer.fill(0);
                return Err(error);
            }
        }
        buffer.fill(0);
    }
    Err(Failure::new("descendant", "transport"))
}

fn drain(handle: &Handle, bytes: &mut Vec<u8>, limit: usize, final_drain: bool) -> Result<()> {
    collect(
        bytes,
        limit,
        final_drain,
        || {
            let mut available = 0;
            // SAFETY: query the exact owned pipe, retaining immediate error on failure.
            let status = unsafe {
                PeekNamedPipe(
                    handle.raw,
                    null_mut(),
                    0,
                    null_mut(),
                    &mut available,
                    null_mut(),
                )
            };
            if status != 0 {
                return Ok(Some(available as usize));
            }
            // SAFETY: one immediate failed-peek error; broken pipe retains its existing EOF meaning.
            let error = unsafe { GetLastError() };
            descendant_result(
                error == 109,
                if error == 109 { None } else { Some(error) },
                "control-pipe-peek",
            )?;
            Ok(None)
        },
        |buffer| {
            let mut count = 0;
            // SAFETY: sole reader consumes only already available bytes into bounded writable storage.
            let status = unsafe {
                ReadFile(
                    handle.raw,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut count,
                    null_mut(),
                )
            };
            // SAFETY: GetLastError is read immediately only for the failed synchronous read.
            descendant_native(status != 0, "control-pipe-read", || unsafe {
                GetLastError()
            })?;
            Ok(count as usize)
        },
    )
}

fn child_failure(code: u32, errors: &[u8]) -> Failure {
    let mut result = Failure::new("descendant", "transport");
    result.child_exit = Some(code);
    if errors.len() <= 512
        && errors.is_ascii()
        && let Ok(text) = std::str::from_utf8(errors)
        && let Some(events) = text
            .strip_prefix("REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=")
            .and_then(|value| value.strip_suffix('\n'))
    {
        let (events, restrictions) = match events.split_once(" restrictions=") {
            Some((events, detail)) => {
                let Some(query) = RestrictionQuery::parse(detail) else {
                    return result;
                };
                (events, Some(query))
            }
            None => (events, None),
        };
        let mut parsed = Vec::new();
        for item in events.split(',') {
            let Some((phase, kind)) = item.split_once(':') else {
                return result;
            };
            let phases = [
                "start",
                "token",
                "root",
                "mutation",
                "inventory",
                "identity",
                "close",
                "report",
            ];
            let kinds = ["control", "timeout", "decode", "native", "cleanup", "other"];
            let Some(phase) = phases.into_iter().find(|value| *value == phase) else {
                return result;
            };
            let Some(kind) = kinds.into_iter().find(|value| *value == kind).or_else(|| {
                if phase == "token" {
                    token_kind(kind)
                } else {
                    None
                }
            }) else {
                return result;
            };
            parsed.push((phase, kind));
        }
        if !parsed.is_empty()
            && parsed.len() <= 7
            && (restrictions.is_none() || parsed.contains(&("token", "control-restrictions-query")))
        {
            result.events.extend(parsed);
            result.restrictions = restrictions;
        }
    }
    result
}

pub fn descendant(observed_exit: &mut Option<u32>) -> Result<String> {
    let image = std::env::current_exe().map_err(|_| Failure::new("descendant", "native"))?;
    let home = image
        .parent()
        .ok_or_else(|| Failure::new("descendant", "control-image-parent"))?;
    let image_units = image.as_os_str().encode_wide().collect::<Vec<_>>();
    descendant_need(
        image.is_absolute()
            && image_units.len() < 512
            && !image_units.contains(&0)
            && !image_units.contains(&34),
        "control-image-path",
    )?;
    let mut command = vec![34u16];
    command.extend(&image_units);
    command.extend("\" --descendant\0".encode_utf16());
    let executable = image_units
        .iter()
        .copied()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let cwd = home
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let (output, mut output_write) = crate::pipe::pair(true)?;
    let (error, mut error_write) = crate::pipe::pair(false)?;
    let input = input()?;
    let mut size = 0;
    // SAFETY: null list is documented size query; validate size before allocation.
    let initial = unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
    descendant_need(
        initial == 0 && (1..=65536).contains(&size),
        "control-attribute-size",
    )?;
    let mut storage = vec![0u64; size.div_ceil(8)];
    // SAFETY: aligned storage holds the complete requested attribute list.
    descendant_native(
        unsafe { InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 1, 0, &mut size) }
            != 0,
        "control-attribute-init",
        || unsafe { GetLastError() },
    )?;
    let mut attributes = AttributeList { data: storage };
    let mut inherited = [input.raw, output_write.raw, error_write.raw];
    // SAFETY: exact three live inheritable handles remain held through CreateProcessW.
    descendant_native(
        unsafe {
            UpdateProcThreadAttribute(
                attributes.data.as_mut_ptr().cast(),
                0,
                0x20002,
                inherited.as_mut_ptr().cast(),
                size_of_val(&inherited),
                null_mut(),
                null_mut(),
            )
        } != 0,
        "control-attribute-update",
        || unsafe { GetLastError() },
    )?;
    let startup = StartupEx {
        startup: Startup {
            size: size_of::<StartupEx>() as u32,
            flags: 0x100,
            input: input.raw,
            output: output_write.raw,
            error: error_write.raw,
            ..Startup::default()
        },
        attributes: attributes.data.as_mut_ptr().cast(),
    };
    let mut info = ProcessInfo::default();
    // SAFETY: same fixed image/argument, inherited bounded environment, detached suspended child.
    // No breakaway: kernel inherits the already assigned outer Job before resume.
    let created = unsafe {
        CreateProcessW(
            executable.as_ptr(),
            command.as_mut_ptr(),
            null_mut(),
            null_mut(),
            1,
            0x0808040C,
            null_mut(),
            cwd.as_ptr(),
            &startup,
            &mut info,
        )
    };
    // SAFETY: capture the failed call before any owner or diagnostic can affect last-error.
    let create_error = if created == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    let process = Handle::new(info.process, false);
    let thread = Handle::new(info.thread, false);
    descendant_result(created != 0, create_error, "control-create-process")?;
    descendant_need(process.valid() && thread.valid(), "control-process-handles")?;
    let mut child = Child {
        process,
        thread,
        complete: false,
    };
    let mut in_job = 0;
    // SAFETY: exact live suspended process/thread; no remote data writes.
    unsafe {
        descendant_native(
            IsProcessInJob(child.process.raw, null_mut(), &mut in_job) != 0,
            "control-job-query",
            || GetLastError(),
        )?;
        descendant_need(in_job != 0, "control-job-membership")?;
        descendant_native(
            ResumeThread(child.thread.raw) != u32::MAX,
            "control-resume",
            || GetLastError(),
        )?;
    }
    output_write.close()?;
    error_write.close()?;
    let clock = Instant::now();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    loop {
        drain(&output, &mut stdout, 1024, false)?;
        drain(&error, &mut stderr, 512, false)?;
        // SAFETY: exact owned process, bounded wait; no blind sleeps/full-pipe reads.
        let wait = unsafe { WaitForSingleObject(child.process.raw, 25) };
        if wait == 0 {
            break;
        }
        // SAFETY: only WAIT_FAILED permits an immediate native error, not timeout or other state.
        descendant_native(wait != u32::MAX, "control-wait-api", || unsafe {
            GetLastError()
        })?;
        descendant_need(wait == 0x102, "control-wait-state")?;
        if clock.elapsed() >= Duration::from_secs(5) {
            return Err(Failure::new("descendant", "timeout"));
        }
    }
    child.complete = true;
    let mut code = 0;
    // SAFETY: process was observed signaled; actual exit only, never an invented timeout exit.
    descendant_native(
        unsafe { GetExitCodeProcess(child.process.raw, &mut code) } != 0,
        "control-exit-query",
        || unsafe { GetLastError() },
    )?;
    *observed_exit = Some(code);
    let complete = (|| {
        drain(&output, &mut stdout, 1024, true)?;
        drain(&error, &mut stderr, 512, true)?;
        if code != 0 || !stderr.is_empty() {
            return Err(child_failure(code, &stderr));
        }
        child_record(&stdout)
    })();
    stdout.fill(0);
    stderr.fill(0);
    complete.map_err(|mut failure| {
        failure.child_exit = Some(code);
        failure
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn captured(payload: &[u8], chunk: usize, limit: usize, eof: bool) -> Result<Vec<u8>> {
        let position = Cell::new(0usize);
        let mut bytes = Vec::new();
        collect(
            &mut bytes,
            limit,
            true,
            || {
                let remaining = payload.len() - position.get();
                Ok(if remaining == 0 && eof {
                    None
                } else {
                    Some(remaining)
                })
            },
            |buffer| {
                let count = chunk.min(buffer.len()).min(payload.len() - position.get());
                buffer[..count].copy_from_slice(&payload[position.get()..position.get() + count]);
                position.set(position.get() + count);
                Ok(count)
            },
        )?;
        Ok(bytes)
    }

    #[test]
    fn owned_input_refusals_close_only_the_duplicate() {
        struct Owned<'a>(&'a Cell<u32>);
        impl Drop for Owned<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        for success in [false, true] {
            for valid in [false, true] {
                for code in [0, 5, u32::MAX] {
                    let closes = Cell::new(0);
                    let checks = Cell::new(0);
                    let result = checked_input(
                        Owned(&closes),
                        success,
                        if success { None } else { Some(code) },
                        |_| {
                            checks.set(checks.get() + 1);
                            valid
                        },
                    );
                    assert_eq!(checks.get(), u32::from(success));
                    assert_eq!(result.is_ok(), success && valid);
                    assert_eq!(closes.get(), u32::from(!(success && valid)));
                    if let Err(failure) = &result {
                        assert_eq!(
                            failure.events,
                            vec![(
                                "descendant",
                                if success {
                                    "control-input-handle"
                                } else {
                                    "control-input-duplicate"
                                }
                            )]
                        );
                        assert_eq!(
                            failure.native_error,
                            if success { None } else { Some(code) }
                        );
                    }
                    drop(result);
                    assert_eq!(closes.get(), 1);
                }
            }
        }
    }

    #[test]
    fn complete_capture_handles_short_reads_and_requires_eof() {
        let wire = crate::protocol::record("descendant", 2, 1).expect("wire");
        for chunk in [1, 2, 17, 1024] {
            let bytes = captured(wire.as_bytes(), chunk, 1024, true).expect("complete capture");
            assert_eq!(child_record(&bytes).expect("record"), wire);
            let trailer = format!("{wire}x");
            let bytes = captured(trailer.as_bytes(), chunk, 1024, true).expect("trailer captured");
            assert!(child_record(&bytes).is_err());
        }
        assert_eq!(
            captured(b"late-stderr", 1, 512, true).expect("stderr"),
            b"late-stderr"
        );
        assert!(captured(wire.as_bytes(), 1, 1024, false).is_err());
        assert!(captured(&vec![b'x'; 1025], 1, 1024, true).is_err());
        assert!(captured(b"x", 0, 1024, true).is_err());
        assert!(collect(&mut Vec::new(), 1024, true, || Ok(Some(1)), |_| Ok(2)).is_err());
        assert!(
            collect(
                &mut Vec::new(),
                1024,
                true,
                || Err(Failure::new("descendant", "native")),
                |_| Ok(1)
            )
            .is_err()
        );
        assert!(captured(b"", 1, 512, true).expect("empty EOF").is_empty());
    }

    #[test]
    fn child_errors_retain_actual_exit_and_closed_original_order() {
        let frame = b"REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=root:control,close:cleanup\n";
        let failure = child_failure(7, frame);
        assert_eq!(failure.child_exit, Some(7));
        assert_eq!(
            failure.events,
            vec![
                ("descendant", "transport"),
                ("root", "control"),
                ("close", "cleanup")
            ]
        );
        let failure = child_failure(0xC0000022, b"private-sentinel");
        assert_eq!(failure.child_exit, Some(0xC0000022));
        assert!(!failure.wire("primary").contains("private"));
        for &kind in crate::protocol::TOKEN_CHECKS {
            let frame = format!(
                "REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=token:{kind},close:cleanup\n"
            );
            let failure = child_failure(7, frame.as_bytes());
            assert_eq!(failure.child_exit, Some(7));
            assert_eq!(
                failure.events,
                vec![
                    ("descendant", "transport"),
                    ("token", kind),
                    ("close", "cleanup")
                ]
            );
        }
        for detail in [
            "0:00000004:00000005",
            "0:00000000:00000000",
            "1:00000000:none",
        ] {
            let frame = format!(
                "REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=token:control-restrictions-query,close:cleanup restrictions={detail}\n"
            );
            let failure = child_failure(7, frame.as_bytes());
            assert_eq!(failure.child_exit, Some(7));
            assert_eq!(
                failure.events,
                vec![
                    ("descendant", "transport"),
                    ("token", "control-restrictions-query"),
                    ("close", "cleanup")
                ]
            );
            assert_eq!(failure.restrictions, RestrictionQuery::parse(detail));
            assert!(
                failure
                    .wire("primary")
                    .ends_with(&format!(" restrictions={detail}\n"))
            );
        }
        for (event, detail) in [
            ("token:control-primary-fields", "0:00000004:00000005"),
            ("token:control-restrictions-query", "1:00000001:none"),
            ("token:control-restrictions-query", "1:00000004:none"),
            ("token:control-restrictions-query", "1:00000000:00000005"),
            (
                "token:control-restrictions-query",
                "0:00000004:private-sentinel",
            ),
            (
                "token:control-restrictions-query",
                "0:00000004:00000005 restrictions=0:00000004:00000005",
            ),
        ] {
            let frame = format!(
                "REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors={event} restrictions={detail}\n"
            );
            let failure = child_failure(7, frame.as_bytes());
            assert_eq!(failure.child_exit, Some(7));
            assert_eq!(failure.events, vec![("descendant", "transport")]);
            assert!(failure.restrictions.is_none());
            assert!(!failure.wire("primary").contains("private"));
        }
        for event in [
            "token:control-private-sentinel",
            "root:control-open",
            "descendant:control-create-process",
            "descendant:control-create-process native_error=00000005",
            "token:control-open native_error=00000005",
        ] {
            let frame = format!(
                "REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors={event}\n"
            );
            let failure = child_failure(7, frame.as_bytes());
            assert_eq!(failure.events, vec![("descendant", "transport")]);
            assert!(!failure.wire("primary").contains("private"));
        }
    }
}
