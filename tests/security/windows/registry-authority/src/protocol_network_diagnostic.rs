//! Data only: fixed numeric observations after a FAILED WSAStartup, never a denial proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkDiagnostic([u32; 21]);
impl NetworkDiagnostic {
    pub const WORDS: usize = 21;
    // schema, request, immediate GetLastError, thread-open/close, actual output/BOOL mask,
    // six fixed catalog open results, six corresponding closes, SPI result/errno/size.
    pub fn measured(values: [u32; 21]) -> Option<Self> {
        if values[0] != 1 || values[1] != 0x0101 || values[5] & !0xe000_003f != 0 {
            return None;
        }
        if values[5] & 0x2000_0000 != 0 && values[3] != 0 {
            return None;
        }
        if values[5] & 0x4000_0000 != 0 && (values[5] & 0x8000_0000 == 0 || values[4] != 0) {
            return None;
        }
        if values[5] & 0x8000_0000 == 0 && values[4] != 0 {
            return None;
        }
        for index in 0..6 {
            if values[5] & (1 << index) == 0 && values[12 + index] != 0 {
                return None;
            }
        }
        Some(Self(values))
    }
    pub fn wire(self) -> String {
        self.0.map(|value| format!("{value:08X}")).join(":")
    }
    pub fn parse(text: &str) -> Option<Self> {
        let mut values = [0; Self::WORDS];
        let mut parts = text.split(':');
        for value in &mut values {
            let part = parts.next()?;
            if part.len() != 8
                || !part
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'A'..=b'F').contains(&v))
            {
                return None;
            }
            *value = u32::from_str_radix(part, 16).ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        Self::measured(values)
    }
    pub fn cleanup_failed(self) -> bool {
        self.0[5] & 0x8000_0000 != 0 && self.0[5] & 0x4000_0000 == 0
            || self.0[4] != 0
            || self.0[12..18].iter().any(|code| *code != 0)
    }
}
#[cfg(test)]
pub(super) fn check_validation() {
    use super::{Failure, network_failure};
    let mut values = [0u32; NetworkDiagnostic::WORDS];
    values[0] = 1;
    values[1] = 0x0101;
    values[2] = 5;
    values[3] = 1008;
    values[6..12].fill(5);
    values[18] = u32::MAX;
    values[19] = 10107;
    let diagnostic = NetworkDiagnostic::measured(values).unwrap();
    let encoded = diagnostic.wire();
    assert_eq!(encoded.len(), 21 * 8 + 20);
    assert_eq!(NetworkDiagnostic::parse(&encoded), Some(diagnostic));
    assert!(!diagnostic.cleanup_failed());
    for (index, value) in [
        (0, 2),
        (1, 0x0202),
        (5, 64),
        (5, 0x4000_0000),
        (5, 0x2000_0000),
        (4, 5),
        (12, 5),
    ] {
        let mut invalid = values;
        invalid[index] = value;
        assert!(NetworkDiagnostic::measured(invalid).is_none());
    }
    let mut cleanup = values;
    cleanup[5] = 0x8000_0001;
    cleanup[4] = 6;
    cleanup[12] = 5;
    assert!(
        NetworkDiagnostic::measured(cleanup)
            .unwrap()
            .cleanup_failed()
    );
    cleanup[4] = 0;
    cleanup[12] = 0;
    assert!(
        NetworkDiagnostic::measured(cleanup)
            .unwrap()
            .cleanup_failed()
    );
    cleanup[3] = 0;
    cleanup[5] |= 0x6000_0000;
    assert!(
        !NetworkDiagnostic::measured(cleanup)
            .unwrap()
            .cleanup_failed()
    );
    for invalid in [
        encoded.to_lowercase(),
        format!("{encoded}:00000000"),
        encoded[..encoded.len() - 1].to_owned(),
        encoded.replace(':', " "),
        encoded.replacen("00000005", "private!", 1),
    ] {
        assert!(NetworkDiagnostic::parse(&invalid).is_none());
    }
    let mut failure = network_failure("network-startup", Some(10107));
    failure.network_diag = Some(Box::new(diagnostic));
    let frame = failure.wire("primary");
    let expected = format!(
        "events=mutation:network-startup child_exit=none native_error=0000277B network_diag={encoded}"
    );
    assert_eq!(super::failure_summary(&frame), Some(expected));
    assert!(frame.len() <= 512 && frame.is_ascii());
    assert!(!failure.wire("descendant").contains("network_diag="));
    for invalid in [
        frame.replace("native_error=0000277B", "native_error=00000000"),
        frame.replace("mutation:network-startup", "mutation:network-tcp4-connect"),
        frame.replace("native_error=0000277B ", ""),
        frame.replace(" network_diag=", " extra=00000000 network_diag="),
        frame.replace('\n', &format!(" network_diag={encoded}\n")),
        frame.replace(" network_diag=", " network_diagx="),
    ] {
        assert!(super::failure_summary(&invalid).is_none());
    }
    failure
        .events
        .extend([("mutation", "network-diagnostic-geometry"); 7]);
    let bounded = failure.wire("primary");
    assert!(bounded.len() <= 512 && !bounded.contains("network_diag="));
    assert_eq!(bounded.matches("mutation:").count(), 8);
    assert!(super::failure_summary(&bounded).is_some());
    let mut unrelated = Failure::new("mutation", "network-tcp4-connect");
    unrelated.native_error = Some(10013);
    unrelated.network_diag = Some(Box::new(diagnostic));
    assert!(!unrelated.wire("primary").contains("network_diag="));
}
