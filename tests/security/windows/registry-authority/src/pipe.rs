use crate::native::*;
use crate::protocol::{Result, descendant_native, descendant_need, descendant_result};
use std::ptr::null_mut;

const PREFIX: &str = r"\\.\pipe\LOCAL\RegistryAuthority-";
const SERVER_ACCESS: u32 = 1 | 0x80000;
const SERVER_MODE: u32 = 1 | 8;
const CLIENT_FLAGS: u32 = 0x100000;

fn name(nonce: &[u8; 16], output: bool) -> Vec<u16> {
    let mut text = String::from(PREFIX);
    for byte in nonce {
        use std::fmt::Write;
        write!(&mut text, "{byte:02X}").expect("writing to String");
    }
    text.push_str(if output { "-output" } else { "-error" });
    wide(&text)
}

fn connected(success: bool, error: Option<u32>) -> Result<()> {
    if !success && error == Some(535) {
        return Ok(());
    }
    descendant_result(
        false,
        if success { None } else { error },
        "control-pipe-connect",
    )
}

fn endpoint(client: u32, current: u32) -> Result<()> {
    descendant_need(client == current, "control-pipe-endpoint")
}

fn finish_pair<T>(
    server: T,
    open: impl FnOnce() -> Result<T>,
    connect: impl FnOnce(&T) -> Result<()>,
    endpoint: impl FnOnce(&T) -> Result<()>,
    noninherit: impl FnOnce(&T) -> Result<()>,
) -> Result<(T, T)> {
    let client = open()?;
    connect(&server)?;
    endpoint(&server)?;
    noninherit(&server)?;
    Ok((server, client))
}

pub fn pair(output: bool) -> Result<(Handle, Handle)> {
    let mut nonce = [0u8; 16];
    // SAFETY: fixed initialized writable buffer, system-preferred provider, no secret input.
    let status = unsafe { BCryptGenRandom(null_mut(), nonce.as_mut_ptr(), 16, 2) };
    descendant_need(status == 0, "control-pipe-rng")?;
    let mut path = name(&nonce, output);
    nonce.fill(0);
    let result = (|| {
        let server_security = Security {
            length: size_of::<Security>() as u32,
            descriptor: null_mut(),
            inherit: 0,
        };
        // SAFETY: private LOCAL name, first instance only, one inbound byte pipe, immediate connect mode.
        let raw = unsafe {
            CreateNamedPipeW(
                path.as_ptr(),
                SERVER_ACCESS,
                SERVER_MODE,
                1,
                4096,
                4096,
                0,
                &server_security,
            )
        };
        let error = if raw as isize == -1 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        let server = Handle::new(raw, false);
        descendant_result(raw as isize != -1, error, "control-pipe-server-create")?;
        descendant_need(server.valid(), "control-pipe-server-handle")?;
        finish_pair(
            server,
            || {
                let security = Security {
                    inherit: 1,
                    ..server_security
                };
                // SAFETY: same held private instance; write-only inherited endpoint, anonymous SQOS.
                let raw = unsafe {
                    CreateFileW(
                        path.as_ptr(),
                        0x40000000,
                        0,
                        &security,
                        3,
                        CLIENT_FLAGS,
                        null_mut(),
                    )
                };
                let error = if raw as isize == -1 {
                    Some(unsafe { GetLastError() })
                } else {
                    None
                };
                let client = Handle::new(raw, false);
                descendant_result(raw as isize != -1, error, "control-pipe-client-open")?;
                descendant_need(client.valid(), "control-pipe-client-handle")?;
                Ok(client)
            },
            |server| {
                // SAFETY: NOWAIT guarantees immediate return; the already opened client must yield 535.
                let success = unsafe { ConnectNamedPipe(server.raw, null_mut()) };
                let error = if success == 0 {
                    Some(unsafe { GetLastError() })
                } else {
                    None
                };
                connected(success != 0, error)
            },
            |server| {
                let mut client = 0;
                // SAFETY: server-created handle and writable PID scalar; failure error is immediate.
                descendant_native(
                    unsafe { GetNamedPipeClientProcessId(server.raw, &mut client) } != 0,
                    "control-pipe-endpoint-query",
                    || unsafe { GetLastError() },
                )?;
                // SAFETY: current live process identity is compared privately, never emitted.
                endpoint(client, unsafe { GetCurrentProcessId() })
            },
            |server| {
                // SAFETY: only the writer may enter the unchanged three-standard-handle allowlist.
                descendant_native(
                    unsafe { SetHandleInformation(server.raw, 1, 0) } != 0,
                    "control-pipe-server-inheritance",
                    || unsafe { GetLastError() },
                )
            },
        )
    })();
    path.fill(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn local_names_and_connection_are_fixed_and_fail_closed() {
        for output in [true, false] {
            let path = name(&[0xAB; 16], output);
            let text = String::from_utf16(&path[..path.len() - 1]).expect("fixed UTF-16");
            assert_eq!(
                text,
                format!(
                    "{PREFIX}{}-{}",
                    "AB".repeat(16),
                    if output { "output" } else { "error" }
                )
            );
            assert_eq!(path.last(), Some(&0));
            assert!(path.len() < 128 && !path[..path.len() - 1].contains(&0));
        }
        assert_eq!(SERVER_ACCESS, 0x80001);
        assert_eq!(SERVER_MODE, 9);
        assert_eq!(CLIENT_FLAGS, 0x100000);
        assert!(endpoint(7, 7).is_ok());
        for client in [0, 1, 6, 8, u32::MAX] {
            let failure = endpoint(client, 7).expect_err("foreign endpoint");
            assert_eq!(
                failure.events,
                vec![("descendant", "control-pipe-endpoint")]
            );
            assert!(failure.native_error.is_none());
        }
        assert!(connected(false, Some(535)).is_ok());
        for (success, error) in [
            (true, None),
            (true, Some(535)),
            (false, None),
            (false, Some(0)),
            (false, Some(5)),
            (false, Some(536)),
            (false, Some(u32::MAX)),
        ] {
            let failure = connected(success, error).expect_err("not an established connection");
            assert_eq!(failure.events, vec![("descendant", "control-pipe-connect")]);
            assert_eq!(failure.native_error, if success { None } else { error });
        }
    }

    #[test]
    fn pair_sequence_stops_before_handoff_and_closes_every_owner() {
        struct Owned(&'static str, Rc<RefCell<Vec<&'static str>>>);
        impl Drop for Owned {
            fn drop(&mut self) {
                self.1.borrow_mut().push(self.0);
            }
        }
        for fail in 0..=4 {
            let order = Rc::new(RefCell::new(Vec::new()));
            let step = |index, label| {
                order.borrow_mut().push(label);
                if fail != index {
                    return Ok(());
                }
                match index {
                    1 => descendant_result(false, Some(5), "control-pipe-client-open"),
                    2 => connected(false, Some(5)),
                    3 => endpoint(8, 7),
                    4 => descendant_result(false, Some(5), "control-pipe-server-inheritance"),
                    _ => unreachable!("fixed sequence"),
                }
            };
            let result = finish_pair(
                Owned("close-server", order.clone()),
                || {
                    step(1, "open")?;
                    Ok(Owned("close-client", order.clone()))
                },
                |_| step(2, "connect"),
                |_| step(3, "endpoint"),
                |_| step(4, "noninherit"),
            );
            assert_eq!(result.is_ok(), fail == 0);
            drop(result);
            let observed = order.borrow();
            let reached = if fail == 0 { 4 } else { fail };
            assert_eq!(
                &observed[..reached],
                &["open", "connect", "endpoint", "noninherit"][..reached]
            );
            assert_eq!(observed.iter().filter(|&&s| s == "close-server").count(), 1);
            assert_eq!(
                observed.iter().filter(|&&s| s == "close-client").count(),
                usize::from(fail != 1)
            );
        }
    }
}
