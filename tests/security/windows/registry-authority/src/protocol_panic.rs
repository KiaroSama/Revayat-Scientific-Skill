//! Panic diagnostics contain only the last selected closed worker operation.
//! They attest neither completion nor cleanup, and never inspect panic data.
use std::sync::atomic::{AtomicU8, Ordering};

macro_rules! phases {
    ($($variant:ident => $kind:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u8)]
        pub enum PanicPhase { $($variant),+ }

        pub const PANIC_CHECKS: &[&str] = &[$($kind),+];

        impl PanicPhase {
            #[cfg(test)]
            const ALL: &[Self] = &[$(Self::$variant),+];

            #[cfg(test)]
            const fn kind(self) -> &'static str {
                match self { $(Self::$variant => $kind),+ }
            }

            const fn frame(self, descendant: bool) -> &'static [u8] {
                match (self, descendant) {
                    $((Self::$variant, false) => concat!(
                        "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=panic:",
                        $kind, "\n"
                    ).as_bytes(),
                    (Self::$variant, true) => concat!(
                        "REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=panic:",
                        $kind, "\n"
                    ).as_bytes()),+
                }
            }
        }

        pub fn panic_frame(descendant: bool) -> &'static [u8] {
            let phase = PHASE.load(Ordering::Relaxed);
            match phase {
                $(value if value == PanicPhase::$variant as u8 =>
                    PanicPhase::$variant.frame(descendant)),+,
                _ => PanicPhase::Start.frame(descendant),
            }
        }
    };
}

phases! {
    Start => "start",
    Controls => "controls",
    Token => "token",
    Root => "root",
    Inventory => "inventory",
    Foreign => "foreign",
    Scratch => "scratch",
    NetworkConfig => "network-config",
    NetworkStartup => "network-startup",
    NetworkTcp4 => "network-tcp4",
    NetworkTcp6 => "network-tcp6",
    NetworkUdp4Bind => "network-udp4-bind",
    NetworkUdp4Send => "network-udp4-send",
    NetworkUdp6Bind => "network-udp6-bind",
    NetworkUdp6Send => "network-udp6-send",
    Baseline => "baseline",
    Record => "record",
    Descendant => "descendant",
    Report => "report",
    FailureReport => "failure-report",
}

static PHASE: AtomicU8 = AtomicU8::new(PanicPhase::Start as u8);

pub fn mark_panic_phase(phase: PanicPhase) {
    PHASE.store(phase as u8, Ordering::Relaxed);
}

pub fn panic_kind(value: &str) -> Option<&'static str> {
    PANIC_CHECKS.iter().copied().find(|kind| *kind == value)
}

#[cfg(test)]
pub(super) fn check_diagnostics() {
    for &phase in PanicPhase::ALL {
        mark_panic_phase(phase);
        assert_eq!(panic_kind(phase.kind()), Some(phase.kind()));
        for descendant in [false, true] {
            let frame = std::str::from_utf8(panic_frame(descendant)).expect("static ASCII frame");
            let role = if descendant { "descendant" } else { "primary" };
            assert_eq!(
                frame,
                format!(
                    "REGISTRY_AUTHORITY_FAILURE role={role} child_exit=none errors=panic:{}\n",
                    phase.kind()
                )
            );
            assert!(frame.is_ascii() && frame.len() <= 512);
            assert!(!frame.contains("cleanup"));
            assert_eq!(
                super::failure_summary(frame),
                (!descendant).then(|| format!("events=panic:{} child_exit=none", phase.kind()))
            );
        }
    }
    for private in [
        "private-path",
        "network-tcp",
        "network-tcp4/secret",
        "NETWORK-TCP4",
    ] {
        assert!(panic_kind(private).is_none());
        assert!(
            super::failure_summary(&format!(
                "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=panic:{private}\n"
            ))
            .is_none()
        );
    }
    mark_panic_phase(PanicPhase::Start);
}
