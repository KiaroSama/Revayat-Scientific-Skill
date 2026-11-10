//! Nonblocking browser stderr evidence. No reader thread or raw diagnostic output.
use std::{
    cell::RefCell,
    io::{self, Read},
    process::ChildStderr,
};
const LIMIT: usize = 64 * 1024;
const LINE_LIMIT: usize = 1024;

#[derive(Default)]
struct Capture {
    pipe: Option<ChildStderr>,
    bytes: usize,
    line: Vec<u8>,
    utf8: Vec<u8>,
    sandbox: bool,
    display: bool,
    permission: bool,
    unknown: bool,
    invalid_utf8: bool,
    overflow: bool,
    read_failed: bool,
    complete: bool,
}
impl Capture {
    fn accept(&mut self, bytes: &[u8]) {
        self.bytes = self.bytes.saturating_add(bytes.len());
        self.overflow |= self.bytes > LIMIT;
        self.utf8.extend_from_slice(bytes);
        let mut offset = 0;
        loop {
            match std::str::from_utf8(&self.utf8[offset..]) {
                Ok(_) => {
                    self.utf8.clear();
                    break;
                }
                Err(error) => {
                    offset += error.valid_up_to();
                    if let Some(length) = error.error_len() {
                        self.invalid_utf8 = true;
                        offset += length;
                    } else {
                        self.utf8.drain(..offset);
                        break;
                    }
                }
            }
        }
        for &byte in bytes {
            if byte == b'\n' {
                self.classify();
                self.line.clear();
            } else if self.line.len() < LINE_LIMIT {
                self.line.push(byte);
            } else {
                self.unknown = true;
            }
        }
    }
    fn classify(&mut self) {
        let has = |marker: &[u8]| self.line.windows(marker.len()).any(|part| part == marker);
        let sandbox = has(b"No usable sandbox!") || has(b"Running as root without --no-sandbox");
        let display = has(b"Missing X server or $DISPLAY") || has(b"cannot open display");
        let permission = has(b"Permission denied");
        self.sandbox |= sandbox;
        self.display |= display;
        self.permission |= permission;
        self.unknown |= !self.line.is_empty() && !(sandbox || display || permission);
    }
}

pub(super) struct Diagnostics(RefCell<Capture>);
impl Diagnostics {
    pub(super) fn start(pipe: ChildStderr) -> io::Result<Self> {
        prepare(&pipe)?;
        Ok(Self(RefCell::new(Capture {
            pipe: Some(pipe),
            ..Capture::default()
        })))
    }
    /// Poll between bounded protocol operations. One call consumes at most 68KiB,
    /// so even a continuously writable inherited pipe cannot monopolize cleanup.
    pub(super) fn poll(&self) {
        let mut state = self.0.borrow_mut();
        let mut buffer = [0; 4096];
        for _ in 0..17 {
            let Some(pipe) = state.pipe.as_mut() else {
                break;
            };
            match read_available(pipe, &mut buffer) {
                Ok(0) => {
                    state.pipe.take();
                    break;
                }
                Ok(count) => state.accept(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    state.read_failed = true;
                    state.pipe.take();
                    break;
                }
            }
            if state.overflow {
                break;
            }
        }
    }
    pub(super) fn failed(&self) -> bool {
        self.poll();
        let state = self.0.borrow();
        state.overflow || state.read_failed
    }
    /// Child/group/job cleanup precedes closing our read endpoint. No thread can
    /// detach and no EOF wait depends on a descendant outside this direct owner.
    pub(super) fn finish(&self) -> bool {
        self.poll();
        let mut state = self.0.borrow_mut();
        state.pipe.take();
        state.invalid_utf8 |= !state.utf8.is_empty();
        state.classify();
        state.line.clear();
        state.utf8.clear();
        state.complete = true;
        true
    }
    pub(super) fn report(&self, phase: &str, code: Option<i32>, signal: Option<i32>) -> String {
        let s = self.0.borrow();
        format!(
            "phase={phase} exit_code={} signal={} bytes={} sandbox={} display={} permission={} unknown={} invalid_utf8={} overflow={} read_failed={} reader_complete={}",
            code.map_or_else(|| "unknown".into(), |value| value.to_string()),
            signal.map_or_else(|| "unknown".into(), |value| value.to_string()),
            s.bytes,
            s.sandbox,
            s.display,
            s.permission,
            s.unknown,
            s.invalid_utf8,
            s.overflow,
            s.read_failed,
            s.complete
        )
    }
}

#[cfg(unix)]
fn prepare(pipe: &ChildStderr) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = pipe.as_raw_fd();
    // SAFETY: exclusively owned live read descriptor; no other reader exists.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(unix)]
fn read_available(pipe: &mut ChildStderr, buffer: &mut [u8]) -> io::Result<usize> {
    pipe.read(buffer)
}
#[cfg(windows)]
fn prepare(_: &ChildStderr) -> io::Result<()> {
    Ok(())
}
#[cfg(windows)]
fn read_available(pipe: &mut ChildStderr, buffer: &mut [u8]) -> io::Result<usize> {
    use std::{os::windows::io::AsRawHandle, ptr::null_mut};
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    let mut available = 0;
    // SAFETY: owned read handle and writable scalar; peek does not copy child data.
    if unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            &mut available,
            null_mut(),
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(109 | 232)) {
            return Ok(0);
        }
        return Err(error);
    }
    if available == 0 {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let count = buffer.len().min(available as usize);
    pipe.read(&mut buffer[..count])
}
