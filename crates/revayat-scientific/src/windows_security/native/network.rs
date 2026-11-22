//! Host-positive loopback endpoints retained through the LPAC denial probes.
use anyhow::{Result, ensure};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::windows::io::{AsRawSocket, FromRawSocket};
use std::time::Duration;

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn getsockopt(socket: usize, level: i32, option: i32, value: *mut u8, length: *mut i32) -> i32;
    fn setsockopt(socket: usize, level: i32, option: i32, value: *const u8, length: i32) -> i32;
    fn socket(family: i32, kind: i32, protocol: i32) -> usize;
    fn closesocket(socket: usize) -> i32;
    fn bind(socket: usize, address: *const u8, length: i32) -> i32;
    fn listen(socket: usize, backlog: i32) -> i32;
}

#[repr(C)]
struct Address6 {
    family: u16,
    port: u16,
    flow: u32,
    address: [u8; 16],
    scope: u32,
}

/// std-created IPv6 sockets are dual-stack on Windows and `IPV6_V6ONLY`
/// cannot be changed after bind (WSAEINVAL), so the paired IPv6 controls
/// are created raw: set the option while unbound, then bind `::1`.
fn v6_socket(kind: i32, protocol: i32, port: u16) -> Result<usize> {
    let created = unsafe { socket(23, kind, protocol) };
    ensure!(
        created != usize::MAX,
        "host IPv6 kernel control socket creation failed"
    );
    let mut address = [0u8; 16];
    address[15] = 1;
    let address = Address6 {
        family: 23,
        port: port.to_be(),
        flow: 0,
        address,
        scope: 0,
    };
    let value = 1i32;
    let ready = unsafe {
        setsockopt(created, 41, 27, (&value as *const i32).cast(), 4) == 0
            && bind(created, (&address as *const Address6).cast(), 28) == 0
    };
    if !ready {
        unsafe {
            closesocket(created);
        }
        anyhow::bail!("host IPv6 kernel control could not be bound IPv6-only");
    }
    Ok(created)
}

fn v6_listener(port: u16) -> Result<TcpListener> {
    let created = v6_socket(1, 6, port)?;
    if unsafe { listen(created, 128) } != 0 {
        unsafe {
            closesocket(created);
        }
        anyhow::bail!("host IPv6 kernel control listener failed");
    }
    Ok(unsafe { TcpListener::from_raw_socket(created as u64) })
}

fn v6_udp(port: u16) -> Result<UdpSocket> {
    let created = v6_socket(2, 17, port)?;
    Ok(unsafe { UdpSocket::from_raw_socket(created as u64) })
}

pub(super) struct NetworkControls {
    _tcp: [TcpListener; 2],
    _udp: [UdpSocket; 2],
    pub ports: String,
}
impl NetworkControls {
    pub fn new() -> Result<Self> {
        let tcp = [
            TcpListener::bind(("127.0.0.1", 0))?,
            TcpListener::bind(("::1", 0))?,
        ];
        let udp = [
            UdpSocket::bind(("127.0.0.1", 0))?,
            UdpSocket::bind(("::1", 0))?,
        ];
        Self::qualify(tcp, udp)
    }
    /// The kernel contract has one paired TCP port and one paired UDP port.
    /// Keep the IPv4 owner held while binding IPv6 and verify actual IPv6-only policy.
    pub fn paired() -> Result<(Self, u16, u16)> {
        let tcp4 = TcpListener::bind(("127.0.0.1", 0))?;
        let tcp_port = tcp4.local_addr()?.port();
        let tcp6 = v6_listener(tcp_port)?;
        let udp4 = UdpSocket::bind(("127.0.0.1", 0))?;
        let udp_port = udp4.local_addr()?.port();
        let udp6 = v6_udp(udp_port)?;
        for socket in [tcp6.as_raw_socket(), udp6.as_raw_socket()] {
            let mut value = 0i32;
            let mut length = 4i32;
            let rc = unsafe {
                getsockopt(
                    socket as usize,
                    41,
                    27,
                    (&mut value as *mut i32).cast(),
                    &mut length,
                )
            };
            // Winsock reports this boolean as a DWORD for TCP sockets but
            // as a single byte for UDP sockets; either representation must
            // still encode exactly `1` (IPv6-only).
            let enabled = match length {
                1 => value.to_le_bytes()[0] == 1,
                4 => value == 1,
                _ => false,
            };
            ensure!(
                rc == 0 && enabled,
                "host IPv6 kernel control is not IPv6-only"
            );
        }
        Ok((
            Self::qualify([tcp4, tcp6], [udp4, udp6])?,
            tcp_port,
            udp_port,
        ))
    }
    fn qualify(tcp: [TcpListener; 2], udp: [UdpSocket; 2]) -> Result<Self> {
        for listener in &tcp {
            let connector =
                TcpStream::connect_timeout(&listener.local_addr()?, Duration::from_secs(1))?;
            let (accepted, peer) = listener.accept()?;
            ensure!(
                peer == connector.local_addr()?
                    && accepted.local_addr()? == listener.local_addr()?,
                "host TCP control endpoint differs"
            );
        }
        for (receiver, bind) in udp.iter().zip(["127.0.0.1", "::1"]) {
            let sender = UdpSocket::bind((bind, 0))?;
            let sent = sender.send_to(b"native host UDP control", receiver.local_addr()?)?;
            receiver.set_read_timeout(Some(Duration::from_secs(1)))?;
            let mut bytes = [0u8; 64];
            let (received, peer) = receiver.recv_from(&mut bytes)?;
            ensure!(
                sent == received
                    && &bytes[..received] == b"native host UDP control"
                    && peer == sender.local_addr()?,
                "host UDP control differs"
            );
        }
        let ports = format!(
            "{},{},{},{}",
            tcp[0].local_addr()?.port(),
            tcp[1].local_addr()?.port(),
            udp[0].local_addr()?.port(),
            udp[1].local_addr()?.port()
        );
        Ok(Self {
            _tcp: tcp,
            _udp: udp,
            ports,
        })
    }
}
