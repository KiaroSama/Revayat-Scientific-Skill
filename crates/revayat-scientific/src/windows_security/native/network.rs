//! Host-positive loopback endpoints retained through the LPAC denial probes.
use anyhow::{Result, ensure};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::time::Duration;

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn getsockopt(socket: usize, level: i32, option: i32, value: *mut u8, length: *mut i32) -> i32;
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
        let tcp6 = TcpListener::bind(("::1", tcp_port))?;
        let udp4 = UdpSocket::bind(("127.0.0.1", 0))?;
        let udp_port = udp4.local_addr()?.port();
        let udp6 = UdpSocket::bind(("::1", udp_port))?;
        for socket in [tcp6.as_raw_socket(), udp6.as_raw_socket()] {
            let mut value = 0i32;
            let mut length = 4i32;
            ensure!(
                unsafe {
                    getsockopt(
                        socket as usize,
                        41,
                        27,
                        (&mut value as *mut i32).cast(),
                        &mut length,
                    )
                } == 0
                    && length == 4
                    && value == 1,
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
