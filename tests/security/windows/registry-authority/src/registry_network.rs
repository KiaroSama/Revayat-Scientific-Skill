//! Four actual LPAC operations. Initialization/creation/cleanup refusal is fatal, never a denial.
//! Match the original CPython3.11 socketmodule.c os_init request (Winsock1.1).
//! A failed startup remains fatal; only four actual connect/sendto denials qualify.
use crate::protocol::{
    NetworkOperation, PanicPhase, Result, mark_panic_phase, network_denial, network_failure,
    network_finish, network_ports, network_socket, network_startup,
};
use std::{
    ffi::c_void,
    mem::{offset_of, size_of, zeroed},
    ptr::null_mut,
    time::{Duration, Instant},
};
#[path = "registry_network_diagnostic.rs"]
mod diagnostic;
#[repr(C)]
struct WsaData {
    version: u16,
    high: u16,
    max_sockets: u16,
    max_udp: u16,
    vendor: *mut u8,
    description: [u8; 257],
    status: [u8; 129],
}
#[repr(C)]
struct Address4 {
    family: u16,
    port: u16,
    address: [u8; 4],
    zero: [u8; 8],
}
#[repr(C)]
struct Address6 {
    family: u16,
    port: u16,
    flow: u32,
    address: [u8; 16],
    scope: u32,
}
#[repr(C)]
struct FdSet {
    count: u32,
    sockets: [usize; 64],
}
impl FdSet {
    fn one(socket: usize) -> Self {
        let mut value = Self {
            count: 1,
            sockets: [0; 64],
        };
        value.sockets[0] = socket;
        value
    }
    fn valid(&self, socket: usize) -> bool {
        self.count <= 1 && (self.count == 0 || self.sockets[0] == socket)
    }
}
#[repr(C)]
struct TimeVal {
    seconds: i32,
    micros: i32,
}
#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAStartup(version: u16, data: *mut WsaData) -> i32;
    fn WSACleanup() -> i32;
    fn WSAGetLastError() -> i32;
    fn socket(family: i32, kind: i32, protocol: i32) -> usize;
    fn closesocket(socket: usize) -> i32;
    fn ioctlsocket(socket: usize, command: i32, value: *mut u32) -> i32;
    fn select(
        nfds: i32,
        read: *mut FdSet,
        write: *mut FdSet,
        except: *mut FdSet,
        timeout: *const TimeVal,
    ) -> i32;
    fn getsockopt(socket: usize, level: i32, option: i32, value: *mut u8, length: *mut i32) -> i32;
    fn connect(socket: usize, address: *const c_void, length: i32) -> i32;
    fn sendto(
        socket: usize,
        data: *const u8,
        length: i32,
        flags: i32,
        address: *const c_void,
        address_length: i32,
    ) -> i32;
}
struct Winsock(bool);
impl Winsock {
    fn begin() -> Result<Self> {
        mark_panic_phase(PanicPhase::NetworkStartup);
        let mut data: WsaData = unsafe { zeroed() };
        // WSAStartup returns its error directly. WSAGetLastError is not its result channel.
        let status = unsafe { WSAStartup(0x0101, &mut data) };
        // Observational only: preserve it before any allocation/diagnostic API can replace it.
        let immediate_error = if status != 0 {
            unsafe { crate::native::GetLastError() }
        } else {
            0
        };
        let result = network_startup(status);
        let version = data.version;
        unsafe {
            std::ptr::write_bytes(
                (&mut data as *mut WsaData).cast::<u8>(),
                0,
                size_of::<WsaData>(),
            )
        };
        if let Err(mut failure) = result {
            match diagnostic::measure(immediate_error) {
                Some(diagnostic) => {
                    if diagnostic.cleanup_failed() {
                        failure
                            .events
                            .push(("mutation", "network-diagnostic-close"));
                    }
                    failure.network_diag = Some(Box::new(diagnostic));
                }
                None => failure
                    .events
                    .push(("mutation", "network-diagnostic-geometry")),
            }
            return Err(failure);
        }
        let mut owner = Self(true);
        if version != 0x0101 {
            return network_finish(Err(network_failure("network-version", None)), owner.close());
        }
        Ok(owner)
    }
    fn close(&mut self) -> Result<()> {
        if !std::mem::replace(&mut self.0, false) {
            return Ok(());
        }
        let status = unsafe { WSACleanup() };
        let error = if status != 0 {
            Some(unsafe { WSAGetLastError() })
        } else {
            None
        };
        if status == 0 {
            Ok(())
        } else {
            Err(network_failure("network-cleanup", error))
        }
    }
}
impl Drop for Winsock {
    fn drop(&mut self) {
        if self.close().is_err() {
            crate::protocol::cleanup_failed();
        }
    }
}
struct Socket(usize);
impl Socket {
    fn close(&mut self) -> Result<()> {
        let raw = std::mem::replace(&mut self.0, usize::MAX);
        if raw == usize::MAX {
            return Ok(());
        }
        let status = unsafe { closesocket(raw) };
        let error = if status != 0 {
            Some(unsafe { WSAGetLastError() })
        } else {
            None
        };
        if status == 0 {
            Ok(())
        } else {
            Err(network_failure("network-socket-close", error))
        }
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        if self.close().is_err() {
            crate::protocol::cleanup_failed();
        }
    }
}
fn wait(raw: usize, operation: NetworkOperation, started: Instant) -> Result<()> {
    let remaining = Duration::from_secs(1)
        .checked_sub(started.elapsed())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| network_failure(operation.wait_kind(), None))?;
    let timeout = TimeVal {
        seconds: remaining.as_secs() as i32,
        micros: remaining.subsec_micros() as i32,
    };
    let mut write = FdSet::one(raw);
    let mut except = FdSet::one(raw);
    let status = unsafe { select(0, null_mut(), &mut write, &mut except, &timeout) };
    let error = if status == -1 {
        Some(unsafe { WSAGetLastError() })
    } else {
        None
    };
    if status <= 0
        || status > 2
        || !write.valid(raw)
        || !except.valid(raw)
        || write.count + except.count == 0
    {
        return Err(network_failure(operation.wait_kind(), error));
    }
    Ok(())
}
fn attempt(raw: usize, operation: NetworkOperation, port: u16) -> Result<()> {
    let mut nonblocking = 1u32;
    let status = unsafe { ioctlsocket(raw, 0x8004667eu32 as i32, &mut nonblocking) };
    let error = if status != 0 {
        Some(unsafe { WSAGetLastError() })
    } else {
        None
    };
    if status != 0 {
        return Err(network_failure(operation.nonblock_kind(), error));
    }
    let a4 = Address4 {
        family: 2,
        port: port.to_be(),
        address: [127, 0, 0, 1],
        zero: [0; 8],
    };
    let mut loop6 = [0; 16];
    loop6[15] = 1;
    let a6 = Address6 {
        family: 23,
        port: port.to_be(),
        flow: 0,
        address: loop6,
        scope: 0,
    };
    let (address, length) = if operation.family() == 2 {
        (
            (&a4 as *const Address4).cast::<c_void>(),
            size_of::<Address4>() as i32,
        )
    } else {
        (
            (&a6 as *const Address6).cast::<c_void>(),
            size_of::<Address6>() as i32,
        )
    };
    let started = Instant::now();
    loop {
        let status = unsafe {
            if operation.tcp() {
                connect(raw, address, length)
            } else {
                sendto(raw, b"bounded dummy probe".as_ptr(), 19, 0, address, length)
            }
        };
        let error = if status == -1 {
            Some(unsafe { WSAGetLastError() })
        } else {
            None
        };
        if status != -1 || error != Some(10035) {
            return network_denial(operation, status, error);
        }
        wait(raw, operation, started)?;
        if operation.tcp() {
            let mut socket_error = 0i32;
            let mut returned = 4i32;
            let status = unsafe {
                getsockopt(
                    raw,
                    0xffff,
                    0x1007,
                    (&mut socket_error as *mut i32).cast(),
                    &mut returned,
                )
            };
            let error = if status != 0 {
                Some(unsafe { WSAGetLastError() })
            } else {
                None
            };
            if status != 0 || returned != 4 {
                return Err(network_failure("network-soerror", error));
            }
            // This is the final error of the actual pending connect, matching CPython's path.
            return network_denial(
                operation,
                if socket_error == 0 { 0 } else { -1 },
                if socket_error == 0 {
                    None
                } else {
                    Some(socket_error)
                },
            );
        }
        // A temporarily non-writable datagram retries its actual send within the same one-second call.
    }
}
fn observe(operation: NetworkOperation, port: u16) -> Result<()> {
    mark_panic_phase(match operation {
        NetworkOperation::Tcp4 => PanicPhase::NetworkTcp4,
        NetworkOperation::Udp4 => PanicPhase::NetworkUdp4Send,
        NetworkOperation::Tcp6 => PanicPhase::NetworkTcp6,
        NetworkOperation::Udp6 => PanicPhase::NetworkUdp6Send,
    });
    let raw = unsafe { socket(operation.family(), if operation.tcp() { 1 } else { 2 }, 0) };
    let error = if raw == usize::MAX {
        Some(unsafe { WSAGetLastError() })
    } else {
        None
    };
    let mut owner = Socket(raw);
    let result = network_socket(operation, raw, error).and_then(|_| attempt(raw, operation, port));
    network_finish(result, owner.close())
}
pub(super) fn controls(value: &str) -> Result<()> {
    mark_panic_phase(PanicPhase::NetworkConfig);
    let ports = network_ports(value)?;
    if size_of::<usize>() != 8
        || size_of::<WsaData>() != 408
        || offset_of!(WsaData, vendor) != 8
        || offset_of!(WsaData, description) != 16
        || offset_of!(WsaData, status) != 273
        || size_of::<Address4>() != 16
        || offset_of!(Address4, port) != 2
        || offset_of!(Address4, address) != 4
        || size_of::<Address6>() != 28
        || offset_of!(Address6, address) != 8
        || offset_of!(Address6, scope) != 24
        || size_of::<FdSet>() != 520
        || offset_of!(FdSet, sockets) != 8
        || size_of::<TimeVal>() != 8
        || offset_of!(TimeVal, micros) != 4
    {
        return Err(network_failure("network-abi", None));
    }
    let mut initialized = Winsock::begin()?;
    let result = (|| {
        for operation in NetworkOperation::ALL {
            observe(operation, ports[operation.port_index()])?;
        }
        Ok(())
    })();
    network_finish(result, initialized.close())
}
