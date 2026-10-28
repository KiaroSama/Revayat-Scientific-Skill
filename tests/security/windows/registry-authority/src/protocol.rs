use std::cell::Cell;

pub const KEY: &str = r"\Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide";
pub const DENIED: u32 = 0xC0000022;
pub const READ: u32 = 0x20019;
pub type Result<T> = std::result::Result<T, Failure>;
pub const TOKEN_CHECKS: &[&str] = &[
    "control-console",
    "control-stdin",
    "control-stdout",
    "control-stderr",
    "control-job",
    "control-open",
    "control-type-query",
    "control-elevation-query",
    "control-restrictions-query",
    "control-primary-fields",
    "control-lpac-abi",
    "control-lpac-query",
    "control-lpac-header",
    "control-lpac-entry",
    "control-lpac-type",
    "control-lpac-name-length",
    "control-lpac-name-span",
    "control-lpac-value-span",
    "control-lpac-value",
    "control-app-size",
    "control-app-read",
    "control-app-bounds",
    "control-app-value",
    "control-caps-size",
    "control-caps-read",
    "control-caps-bounds",
    "control-caps-value",
    "control-traversal",
    "control-priv-size",
    "control-priv-read",
    "control-priv-bounds",
    "control-priv-count",
    "control-priv-value",
    "control-groups-size",
    "control-groups-read",
    "control-groups-bounds",
    "control-groups-count",
    "control-sid-head-span",
    "control-sid-header",
    "control-sid-span",
    "control-admin",
];

pub fn token_kind(value: &str) -> Option<&'static str> {
    TOKEN_CHECKS.iter().copied().find(|kind| *kind == value)
}

pub fn token_need(value: bool, kind: &'static str) -> Result<()> {
    match token_kind(kind) {
        Some(_) if value => Ok(()),
        Some(kind) => Err(Failure::new("token", kind)),
        None => Err(Failure::new("token", "control")),
    }
}

pub const DESCENDANT_CHECKS: &[&str] = &[
    "control-image-parent",
    "control-image-path",
    "control-output-pipe-create",
    "control-output-pipe-handles",
    "control-output-pipe-inheritance",
    "control-error-pipe-create",
    "control-error-pipe-handles",
    "control-error-pipe-inheritance",
    "control-input-open",
    "control-input-handle",
    "control-attribute-size",
    "control-attribute-init",
    "control-attribute-update",
    "control-create-process",
    "control-process-handles",
    "control-job-query",
    "control-job-membership",
    "control-resume",
    "control-pipe-peek",
    "control-pipe-read",
    "control-wait-api",
    "control-wait-state",
    "control-exit-query",
    "control-capture-limit",
    "control-capture-eof",
];

pub const NATIVE_CHECKS: &[&str] = &[
    "control-output-pipe-create",
    "control-output-pipe-inheritance",
    "control-error-pipe-create",
    "control-error-pipe-inheritance",
    "control-input-open",
    "control-attribute-init",
    "control-attribute-update",
    "control-create-process",
    "control-job-query",
    "control-resume",
    "control-pipe-peek",
    "control-pipe-read",
    "control-wait-api",
    "control-exit-query",
];

pub fn descendant_need(value: bool, kind: &'static str) -> Result<()> {
    if !DESCENDANT_CHECKS.contains(&kind) {
        return Err(Failure::new("descendant", "control"));
    }
    if value {
        Ok(())
    } else {
        Err(Failure::new("descendant", kind))
    }
}

pub fn descendant_result(success: bool, error: Option<u32>, kind: &'static str) -> Result<()> {
    if !NATIVE_CHECKS.contains(&kind) {
        return Err(Failure::new("descendant", "control"));
    }
    if success && error.is_none() {
        return Ok(());
    }
    let mut failure = Failure::new("descendant", kind);
    if !success {
        failure.native_error = error;
    }
    Err(failure)
}

pub fn descendant_native(
    success: bool,
    kind: &'static str,
    error: impl FnOnce() -> u32,
) -> Result<()> {
    let error = if success { None } else { Some(error()) };
    descendant_result(success, error, kind)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestrictionQuery {
    succeeded: bool,
    returned: u32,
    error: Option<u32>,
}

impl RestrictionQuery {
    pub fn wire(self) -> String {
        let error = self
            .error
            .map_or_else(|| "none".into(), |code| format!("{code:08X}"));
        format!("{}:{:08X}:{error}", u8::from(self.succeeded), self.returned)
    }

    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split(':');
        let succeeded = match parts.next()? {
            "0" => false,
            "1" => true,
            _ => return None,
        };
        let hex = |text: &str| {
            if text.len() == 8
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
            {
                u32::from_str_radix(text, 16).ok()
            } else {
                None
            }
        };
        let returned = hex(parts.next()?)?;
        let error = parts.next()?;
        let error = if succeeded {
            if matches!(returned, 1 | 4) || error != "none" {
                return None;
            }
            None
        } else {
            Some(hex(error)?)
        };
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            succeeded,
            returned,
            error,
        })
    }
}

pub fn restriction_need(success: i32, returned: u32, error: impl FnOnce() -> u32) -> Result<()> {
    // Read the failed call's thread-local error before allocating or formatting; never read it on success.
    let error = if success == 0 { Some(error()) } else { None };
    if success != 0 && matches!(returned, 1 | 4) {
        return Ok(());
    }
    let mut failure = Failure::new("token", "control-restrictions-query");
    failure.restrictions = Some(RestrictionQuery {
        succeeded: success != 0,
        returned,
        error,
    });
    Err(failure)
}

pub fn restriction_value(bytes: &[u8]) -> Result<u32> {
    match bytes {
        [value] => Ok(u32::from(*value)),
        [a, b, c, d] => Ok(u32::from_le_bytes([*a, *b, *c, *d])),
        _ => Err(Failure::new("token", "control-restrictions-query")),
    }
}

#[derive(Debug)]
pub struct Failure {
    pub events: Vec<(&'static str, &'static str)>,
    pub child_exit: Option<u32>,
    pub restrictions: Option<RestrictionQuery>,
    pub native_error: Option<u32>,
}

thread_local! { static CLEANUP_FAILED: Cell<bool> = const { Cell::new(false) }; }

pub fn cleanup_failed() {
    CLEANUP_FAILED.with(|value| value.set(true));
}

pub fn take_cleanup_failure() -> bool {
    CLEANUP_FAILED.with(|value| value.replace(false))
}

impl Failure {
    pub fn new(phase: &'static str, kind: &'static str) -> Self {
        Self {
            events: vec![(phase, kind)],
            child_exit: None,
            restrictions: None,
            native_error: None,
        }
    }

    pub fn wire(&self, role: &str) -> String {
        let code = self
            .child_exit
            .map_or_else(|| "none".into(), |value| format!("{value:08X}"));
        let events = self
            .events
            .iter()
            .take(8)
            .map(|(phase, kind)| format!("{phase}:{kind}"))
            .collect::<Vec<_>>()
            .join(",");
        let restrictions = self
            .restrictions
            .filter(|_| {
                self.native_error.is_none()
                    && self
                        .events
                        .iter()
                        .take(8)
                        .any(|event| *event == ("token", "control-restrictions-query"))
            })
            .map_or_else(String::new, |query| {
                format!(" restrictions={}", query.wire())
            });
        let native =
            self.native_error
                .filter(|_| {
                    role == "primary"
                        && self.restrictions.is_none()
                        && self.events.iter().take(8).any(|(phase, kind)| {
                            *phase == "descendant" && NATIVE_CHECKS.contains(kind)
                        })
                })
                .map_or_else(String::new, |error| format!(" native_error={error:08X}"));
        format!(
            "REGISTRY_AUTHORITY_FAILURE role={role} child_exit={code} errors={events}{restrictions}{native}\n"
        )
    }
}

pub fn need(value: bool, phase: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(Failure::new(phase, "control"))
    }
}

pub fn token_fields(kind: u32, elevated: u32, filtered: u32) -> bool {
    kind == 1 && elevated == 0 && filtered == 1
}

pub fn denied(status: u32, handle: usize) -> bool {
    status == DENIED && handle == 0
}

pub fn basic(status: u32, returned: u32, attributes: u32, granted: u32) -> bool {
    status == 0 && returned == 56 && attributes == 0 && granted == READ
}

pub fn identity(status: u32, returned: usize, data: &[u8], expected: usize) -> Result<String> {
    need(
        status == 0 && (4..=4096).contains(&returned) && returned <= data.len(),
        "identity",
    )?;
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    need(
        count == expected && count.is_multiple_of(2) && count <= returned - 4,
        "identity",
    )?;
    let units = data[4..4 + count]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let text = String::from_utf16(&units).map_err(|_| Failure::new("identity", "decode"))?;
    need(!text.contains('\0'), "identity")?;
    Ok(text)
}

pub fn record(role: &str, subkeys: u32, accessible: u32) -> Result<String> {
    need(
        matches!(role, "primary" | "descendant") && accessible <= subkeys && subkeys <= 256,
        "report",
    )?;
    Ok(format!(
        "{{\"accessible\":{accessible},\"capabilities\":0,\"granted_access\":131097,\"lpac\":true,\"mutation_denied\":true,\"no_reparse\":true,\"read\":true,\"read_surface_approved\":false,\"restricted\":true,\"role\":\"{role}\",\"subkeys\":{subkeys},\"version\":1,\"x64\":true}}\n"
    ))
}

pub fn child_record(bytes: &[u8]) -> Result<String> {
    need(bytes.len() <= 1024 && bytes.is_ascii(), "descendant")?;
    let text = std::str::from_utf8(bytes).map_err(|_| Failure::new("descendant", "decode"))?;
    let tail = text
        .strip_prefix("{\"accessible\":")
        .ok_or_else(|| Failure::new("descendant", "transport"))?;
    let (accessible, _) = tail
        .split_once(',')
        .ok_or_else(|| Failure::new("descendant", "transport"))?;
    let tail = text
        .split_once("\"subkeys\":")
        .ok_or_else(|| Failure::new("descendant", "transport"))?
        .1;
    let subkeys = tail
        .split_once(',')
        .ok_or_else(|| Failure::new("descendant", "transport"))?
        .0;
    let accessible = accessible
        .parse::<u32>()
        .map_err(|_| Failure::new("descendant", "transport"))?;
    let subkeys = subkeys
        .parse::<u32>()
        .map_err(|_| Failure::new("descendant", "transport"))?;
    need(
        text == record("descendant", subkeys, accessible)?,
        "descendant",
    )?;
    Ok(text.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("fixture ASCII"), 16)
                    .expect("fixture hex")
            })
            .collect()
    }

    #[test]
    fn source_generated_oracle() {
        let path =
            std::env::var("REGISTRY_AUTHORITY_ORACLE").expect("CI must generate the Python oracle");
        let source = std::fs::read_to_string(path).expect("oracle UTF-8");
        let mut count = 0;
        for line in source.lines() {
            let row = line.split('\t').collect::<Vec<_>>();
            let n = |index: usize| row[index].parse::<u32>().expect("oracle integer");
            let actual = match row[0] {
                "token" => token_fields(n(1), n(2), n(3)),
                "denied" => denied(n(1), n(2) as usize),
                "basic" => basic(n(1), n(2), n(3), n(4)),
                "identity" => identity(n(1), n(2) as usize, &hex(row[3]), n(4) as usize).is_ok(),
                "wire" => {
                    assert_eq!(
                        record(row[1], n(2), n(3))
                            .expect("valid source record")
                            .as_bytes(),
                        hex(row[4])
                    );
                    count += 1;
                    continue;
                }
                _ => panic!("unknown oracle case"),
            };
            assert_eq!(actual, row[row.len() - 1] == "1", "{line}");
            count += 1;
        }
        assert_eq!(count, 41);
    }

    #[test]
    fn token_stages_are_closed_and_fit_complete_failure_frames() {
        for &kind in TOKEN_CHECKS {
            assert!(token_need(true, kind).is_ok());
            let error = token_need(false, kind).expect_err("predicate refused");
            assert_eq!(error.events, vec![("token", kind)]);
            assert!(
                error
                    .wire("primary")
                    .ends_with(&format!("errors=token:{kind}\n"))
            );
        }
        for value in [true, false] {
            let error = token_need(value, "private-sentinel").expect_err("unknown stage");
            assert_eq!(error.events, vec![("token", "control")]);
            assert!(!error.wire("primary").contains("private"));
        }
        let longest = TOKEN_CHECKS
            .iter()
            .copied()
            .max_by_key(|kind| kind.len())
            .expect("stages");
        for role in ["primary", "descendant"] {
            let error = Failure {
                events: vec![("token", longest); 8],
                child_exit: Some(u32::MAX),
                restrictions: None,
                native_error: None,
            };
            let wire = error.wire(role);
            assert!(wire.is_ascii() && wire.len() <= 512);
            assert_eq!(wire.matches("token:").count(), 8);
            assert!(wire.contains("child_exit=FFFFFFFF"));
        }
    }

    #[test]
    fn descendant_stages_and_native_errors_are_closed() {
        for &stage in DESCENDANT_CHECKS {
            assert!(descendant_need(true, stage).is_ok());
            assert_eq!(
                descendant_need(false, stage).expect_err("refused").events,
                vec![("descendant", stage)]
            );
        }
        for &stage in NATIVE_CHECKS {
            for success in [true, false] {
                for code in [0, 5, u32::MAX] {
                    let calls = Cell::new(0);
                    let result = descendant_native(success, stage, || {
                        calls.set(calls.get() + 1);
                        code
                    });
                    assert_eq!(calls.get(), u32::from(!success));
                    assert_eq!(result.is_ok(), success);
                    if let Err(mut failure) = result {
                        assert_eq!(failure.native_error, Some(code));
                        assert_eq!(failure.events, vec![("descendant", stage)]);
                        failure
                            .events
                            .extend(vec![("token", "control-restrictions-query"); 7]);
                        failure.child_exit = Some(u32::MAX);
                        let wire = failure.wire("primary");
                        assert!(wire.is_ascii() && wire.len() <= 512);
                        assert!(wire.ends_with(&format!(" native_error={code:08X}\n")));
                        assert!(!failure.wire("descendant").contains("native_error="));
                        failure.events.insert(0, ("close", "cleanup"));
                        failure.events.swap(1, 8);
                        assert!(!failure.wire("primary").contains("native_error="));
                    }
                }
            }
            for (success, error) in [(false, None), (true, Some(5))] {
                let failure = descendant_result(success, error, stage).expect_err("inconsistent");
                assert!(failure.native_error.is_none());
            }
        }
        for stage in ["private-sentinel", "control-image-path"] {
            let failure = descendant_result(false, Some(5), stage).expect_err("not native");
            assert!(failure.native_error.is_none());
            assert!(!failure.wire("primary").contains("private"));
        }
        let mut failure = descendant_result(false, Some(5), "control-create-process")
            .expect_err("native refusal");
        failure.restrictions = RestrictionQuery::parse("0:00000004:00000005");
        failure.events.push(("token", "control-restrictions-query"));
        let wire = failure.wire("primary");
        assert!(!wire.contains("native_error=") && !wire.contains(" restrictions="));
    }

    #[test]
    fn restriction_query_retains_only_immediate_failed_result() {
        use std::cell::Cell;
        for success in [0, 1, -1] {
            for returned in [0, 1, 2, 3, 4, 5, u32::MAX] {
                let calls = Cell::new(0);
                let result = restriction_need(success, returned, || {
                    calls.set(calls.get() + 1);
                    5
                });
                assert_eq!(calls.get(), u32::from(success == 0));
                assert_eq!(result.is_ok(), success != 0 && matches!(returned, 1 | 4));
                if let Err(mut failure) = result {
                    assert_eq!(
                        failure.events,
                        vec![("token", "control-restrictions-query")]
                    );
                    let detail = failure.restrictions.expect("query result");
                    let expected = if success == 0 {
                        format!("0:{returned:08X}:00000005")
                    } else {
                        format!("1:{returned:08X}:none")
                    };
                    assert_eq!(detail.wire(), expected);
                    assert_eq!(RestrictionQuery::parse(&expected), Some(detail));
                    failure.events.push(("close", "cleanup"));
                    assert!(failure.wire("primary").ends_with(&format!(
                        "errors=token:control-restrictions-query,close:cleanup restrictions={expected}\n"
                    )));
                }
            }
        }
        assert!(RestrictionQuery::parse("0:00000004:00000000").is_some());
        for bad in [
            "1:00000001:none",
            "1:00000004:none",
            "1:00000000:00000005",
            "0:00000004:none",
            "2:00000000:none",
            "0:ffffffff:00000005",
            "0:000000004:00000005",
            "0:00000004:private",
            "0:00000004:00000005:extra",
            "0:00000004:00000005\n",
        ] {
            assert!(RestrictionQuery::parse(bad).is_none(), "{bad}");
        }
        let longest = TOKEN_CHECKS
            .iter()
            .copied()
            .max_by_key(|kind| kind.len())
            .expect("stages");
        for role in ["primary", "descendant"] {
            let mut failure = restriction_need(0, u32::MAX, || u32::MAX).expect_err("failed query");
            failure.events.extend(vec![("token", longest); 7]);
            failure.child_exit = Some(u32::MAX);
            let wire = failure.wire(role);
            assert!(wire.is_ascii() && wire.len() <= 512);
            assert!(wire.ends_with(" restrictions=0:FFFFFFFF:FFFFFFFF\n"));
        }
    }

    #[test]
    fn restriction_representations_preserve_exact_true_and_returned_span() {
        for bytes in [[1, 0, 0, 0], [1, 2, 3, 4], [1, 255, 254, 253]] {
            let filtered = restriction_value(&bytes[..1]).expect("byte representation");
            assert_eq!(filtered, 1);
            assert!(token_fields(1, 0, filtered));
        }
        for value in [0u32, 1, 2, 255, 0x101] {
            let bytes = value.to_le_bytes();
            let filtered = restriction_value(&bytes).expect("DWORD representation");
            assert_eq!(filtered, value);
            assert_eq!(token_fields(1, 0, filtered), value == 1);
        }
        for value in [0u8, 2, 255] {
            let filtered = restriction_value(&[value]).expect("byte representation");
            let failure = token_need(token_fields(1, 0, filtered), "control-primary-fields")
                .expect_err("not exact true");
            assert_eq!(failure.events, vec![("token", "control-primary-fields")]);
            assert!(failure.restrictions.is_none());
        }
        for length in [0, 2, 3, 5] {
            assert!(restriction_value(&[1; 5][..length]).is_err());
        }
    }

    #[test]
    fn descendant_wire_refuses_partial_or_permissive_records() {
        let wire = record("descendant", 2, 1).expect("record");
        assert_eq!(child_record(wire.as_bytes()).expect("valid child"), wire);
        for bad in [
            wire.replace("descendant", "primary"),
            wire.replace(":true", ":false"),
            wire.replace("\"subkeys\":2", "\"subkeys\":0"),
            format!("{wire}\n"),
            wire.replace("\"accessible\":1", "\"accessible\":01"),
        ] {
            assert!(child_record(bad.as_bytes()).is_err());
        }
    }
}
