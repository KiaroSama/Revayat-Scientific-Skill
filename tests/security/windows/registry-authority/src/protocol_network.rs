//! Closed diagnostic outcomes. Startup or socket creation never certifies an operation denial.
use super::{Failure, Result};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkOperation {
    Tcp4,
    Udp4,
    Tcp6,
    Udp6,
}
impl NetworkOperation {
    pub const ALL: [Self; 4] = [Self::Tcp4, Self::Udp4, Self::Tcp6, Self::Udp6];
    pub const fn family(self) -> i32 {
        if matches!(self, Self::Tcp4 | Self::Udp4) {
            2
        } else {
            23
        }
    }
    pub const fn tcp(self) -> bool {
        matches!(self, Self::Tcp4 | Self::Tcp6)
    }
    pub const fn port_index(self) -> usize {
        match self {
            Self::Tcp4 => 0,
            Self::Udp4 => 2,
            Self::Tcp6 => 1,
            Self::Udp6 => 3,
        }
    }
    pub const fn socket_kind(self) -> &'static str {
        match self {
            Self::Tcp4 => "network-tcp4-socket",
            Self::Udp4 => "network-udp4-socket",
            Self::Tcp6 => "network-tcp6-socket",
            Self::Udp6 => "network-udp6-socket",
        }
    }
    pub const fn nonblock_kind(self) -> &'static str {
        match self {
            Self::Tcp4 => "network-tcp4-nonblock",
            Self::Udp4 => "network-udp4-nonblock",
            Self::Tcp6 => "network-tcp6-nonblock",
            Self::Udp6 => "network-udp6-nonblock",
        }
    }
    pub const fn wait_kind(self) -> &'static str {
        match self {
            Self::Tcp4 => "network-tcp4-wait",
            Self::Udp4 => "network-udp4-wait",
            Self::Tcp6 => "network-tcp6-wait",
            Self::Udp6 => "network-udp6-wait",
        }
    }
    pub const fn result_kind(self) -> &'static str {
        match self {
            Self::Tcp4 => "network-tcp4-connect",
            Self::Udp4 => "network-udp4-send",
            Self::Tcp6 => "network-tcp6-connect",
            Self::Udp6 => "network-udp6-send",
        }
    }
}
pub const NETWORK_CHECKS: &[&str] = &[
    "network-config",
    "network-abi",
    "network-startup",
    "network-version",
    "network-soerror",
    "network-socket-close",
    "network-cleanup",
    "network-diagnostic-close",
    "network-diagnostic-geometry",
    "network-tcp4-socket",
    "network-tcp4-nonblock",
    "network-tcp4-wait",
    "network-tcp4-connect",
    "network-udp4-socket",
    "network-udp4-nonblock",
    "network-udp4-wait",
    "network-udp4-send",
    "network-tcp6-socket",
    "network-tcp6-nonblock",
    "network-tcp6-wait",
    "network-tcp6-connect",
    "network-udp6-socket",
    "network-udp6-nonblock",
    "network-udp6-wait",
    "network-udp6-send",
];
pub fn network_kind(value: &str) -> Option<&'static str> {
    NETWORK_CHECKS.iter().copied().find(|kind| *kind == value)
}
pub fn network_failure(kind: &str, code: Option<i32>) -> Failure {
    let Some(kind) = network_kind(kind) else {
        return Failure::new("mutation", "control");
    };
    let mut failure = Failure::new("mutation", kind);
    failure.native_error = code.map(|code| code as u32);
    failure
}
pub fn network_startup(code: i32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(network_failure("network-startup", Some(code)))
    }
}
pub fn network_denial(operation: NetworkOperation, status: i32, code: Option<i32>) -> Result<()> {
    if status == -1 && code == Some(10013) {
        Ok(())
    } else {
        Err(network_failure(operation.result_kind(), code))
    }
}
pub fn network_socket(operation: NetworkOperation, raw: usize, code: Option<i32>) -> Result<()> {
    if raw != usize::MAX && code.is_none() {
        Ok(())
    } else {
        Err(network_failure(operation.socket_kind(), code))
    }
}
pub fn network_ports(value: &str) -> Result<[u16; 4]> {
    let invalid = || network_failure("network-config", None);
    let mut ports = [0; 4];
    let mut parts = value.split(',');
    for port in &mut ports {
        let part = parts.next().ok_or_else(invalid)?;
        *port = part
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0 && part == port.to_string())
            .ok_or_else(invalid)?;
    }
    if parts.next().is_some() {
        return Err(invalid());
    }
    Ok(ports)
}
pub fn network_finish<T>(operation: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (operation, cleanup) {
        (Err(mut primary), Err(secondary)) => {
            for event in secondary.events {
                if primary.events.len() < 8 {
                    primary.events.push(event);
                }
            }
            if primary.native_error.is_none() {
                primary.native_error = secondary.native_error;
            }
            Err(primary)
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}
#[cfg(test)]
pub(super) fn check_diagnostics() {
    super::network_diagnostic::check_validation();
    assert_eq!(network_ports("1,2,3,65535").unwrap(), [1, 2, 3, 65535]);
    for value in [
        "",
        "0,2,3,4",
        "01,2,3,4",
        "1,2,3",
        "1,2,3,4,5",
        "1,2,3,65536",
        "1,2,3,private",
    ] {
        assert!(network_ports(value).is_err());
    }
    assert_eq!(
        NetworkOperation::ALL.map(NetworkOperation::port_index),
        [0, 2, 1, 3]
    );
    assert_eq!(
        NetworkOperation::ALL.map(NetworkOperation::family),
        [2, 2, 23, 23]
    );
    assert_eq!(
        NetworkOperation::ALL.map(NetworkOperation::tcp),
        [true, false, true, false]
    );
    for code in [1, 5, 10013, 10091, 10092, 10093, i32::MAX, -1] {
        assert!(network_startup(code).is_err());
    }
    network_startup(0).unwrap();
    for operation in NetworkOperation::ALL {
        network_socket(operation, 0, None).unwrap();
        for (raw, error) in [
            (usize::MAX, Some(10013)),
            (usize::MAX, None),
            (1, Some(10013)),
        ] {
            assert!(network_socket(operation, raw, error).is_err());
        }
        for kind in [
            operation.socket_kind(),
            operation.nonblock_kind(),
            operation.wait_kind(),
            operation.result_kind(),
        ] {
            assert!(network_kind(kind).is_some());
        }
        network_denial(operation, -1, Some(10013)).unwrap();
        for (status, code) in [
            (0, None),
            (19, None),
            (-1, None),
            (-1, Some(0)),
            (-1, Some(10035)),
            (-1, Some(10060)),
            (0, Some(10013)),
        ] {
            assert!(network_denial(operation, status, code).is_err());
        }
        let failure = network_failure(operation.socket_kind(), Some(10013));
        assert_eq!(failure.events, [("mutation", operation.socket_kind())]);
        assert_eq!(failure.native_error, Some(10013));
    }
    for &kind in NETWORK_CHECKS {
        let wire = network_failure(kind, Some(10013)).wire("primary");
        assert_eq!(
            super::failure_summary(&wire),
            Some(format!(
                "events=mutation:{kind} child_exit=none native_error=0000271D"
            ))
        );
        assert!(wire.len() <= 512 && wire.is_ascii());
    }
    let failure = network_finish::<()>(
        Err(network_failure("network-tcp4-connect", Some(10061))),
        Err(network_failure("network-socket-close", Some(10038))),
    )
    .unwrap_err();
    let failure = network_finish::<()>(
        Err(failure),
        Err(network_failure("network-cleanup", Some(10093))),
    )
    .unwrap_err();
    assert_eq!(
        failure.events,
        [
            ("mutation", "network-tcp4-connect"),
            ("mutation", "network-socket-close"),
            ("mutation", "network-cleanup")
        ]
    );
    assert_eq!(failure.native_error, Some(10061));
    for kind in ["network-private", "network-tcp4", "C:\\private"] {
        assert!(network_kind(kind).is_none());
        assert!(network_failure(kind, Some(5)).native_error.is_none());
    }
    for body in [
        "mutation:network-startup native_error=private",
        "mutation:network-startup native_error=0000271d",
        "mutation:network-startup native_error=00000271D",
        "mutation:network-private native_error=0000271D",
        "token:network-startup native_error=0000271D",
        "mutation:network-startup native_error=0000271D extra=private",
    ] {
        assert!(
            super::failure_summary(&format!(
                "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors={body}\n"
            ))
            .is_none()
        );
    }
}
