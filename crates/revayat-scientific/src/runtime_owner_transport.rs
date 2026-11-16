//! Socket readiness preserves absolute frame deadlines without a fixed sleep per buffer.
use anyhow::Result;
use std::{
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::Instant,
};

pub(super) fn ready(stream: &UnixStream, write: bool, deadline: Instant) -> Result<bool> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: if write { libc::POLLOUT } else { libc::POLLIN },
            revents: 0,
        };
        let milliseconds = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        // SAFETY: one initialized native pollfd borrows the live stream; poll
        // neither transfers its handle nor reads any protocol payload.
        let returned = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if returned < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if returned == 0 {
            return Ok(false);
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EBADF).into());
        }
        // EOF/error readiness must reach the actual read/write operation so
        // its existing disconnect and cleanup rules remain authoritative.
        return Ok(descriptor.revents & (descriptor.events | libc::POLLHUP | libc::POLLERR) != 0);
    }
}
