//! Host-positive loopback endpoints retained through the LPAC denial probes.
use anyhow::{Result, ensure};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

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
