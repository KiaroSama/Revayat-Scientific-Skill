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

#[derive(Debug)]
pub struct Failure {
    pub events: Vec<(&'static str, &'static str)>,
    pub child_exit: Option<u32>,
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
        format!("REGISTRY_AUTHORITY_FAILURE role={role} child_exit={code} errors={events}\n")
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
            };
            let wire = error.wire(role);
            assert!(wire.is_ascii() && wire.len() <= 512);
            assert_eq!(wire.matches("token:").count(), 8);
            assert!(wire.contains("child_exit=FFFFFFFF"));
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
