//! Actual small-buffer socket transport under the unchanged five-second frame deadline.
use super::*;
use std::{io::Read, os::fd::AsRawFd};

pub(super) fn check_backpressure() -> Result<()> {
    let (mut receiver, mut sender) = UnixStream::pair()?;
    for stream in [&receiver, &sender] {
        for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
            let capacity = 8192i32;
            // SAFETY: one live socket and exact integer option storage.
            ensure!(
                unsafe {
                    libc::setsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        option,
                        (&capacity as *const i32).cast(),
                        std::mem::size_of_val(&capacity) as libc::socklen_t,
                    )
                } == 0,
                "set bounded transport fixture buffer failed"
            );
        }
    }
    receiver.set_nonblocking(true)?;
    let sender = thread::spawn(move || {
        super::super::frame(
            &mut sender,
            &Event::Complete(Response {
                code: Some(0),
                stdout: vec![0; 8 * 1024 * 1024],
                stderr: Vec::new(),
                deadline_idle: None,
                termination_signal: None,
                cleanup_complete: true,
                error: None,
            }),
            LIMIT,
        )
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let received = (|| -> Result<Response> {
        let mut pending = Vec::new();
        loop {
            let mut buffer = [0; 8192];
            let mut eof = false;
            // Match the production incremental caller's bounded drain turn.
            for _ in 0..16 {
                match receiver.read(&mut buffer) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(count) => pending.extend_from_slice(&buffer[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }
            for event in decode_events(&mut pending)? {
                if let Event::Complete(response) = event {
                    ensure!(pending.is_empty(), "bounded transport left trailing bytes");
                    return Ok(response);
                }
            }
            ensure!(
                !eof,
                "bounded transport disconnected before complete cleanup frame"
            );
            ensure!(
                Instant::now() < deadline,
                "bounded transport fixture deadline exceeded"
            );
            wait_response(Some(&receiver), deadline)?;
        }
    })();
    drop(receiver);
    let sent = sender
        .join()
        .map_err(|_| anyhow::anyhow!("bounded transport sender panicked"))?;
    let response = crate::runtime::with_cleanup(received, sent)?;
    ensure!(
        response.code == Some(0)
            && response.cleanup_complete
            && response.error.is_none()
            && response.stdout.len() == 8 * 1024 * 1024
            && response.stdout.iter().all(|byte| *byte == 0)
            && response.stderr.is_empty(),
        "bounded transport changed the complete response"
    );
    let (receiver, peer) = UnixStream::pair()?;
    ensure!(
        !super::super::transport::ready(
            &receiver,
            false,
            Instant::now() + Duration::from_millis(20)
        )?,
        "silent peer unexpectedly became readable"
    );
    drop(peer);
    ensure!(
        super::super::transport::ready(
            &receiver,
            false,
            Instant::now() + Duration::from_millis(20)
        )?,
        "peer EOF was hidden by readiness wait"
    );
    Ok(())
}
