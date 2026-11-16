//! Original bounded bootstrap/nonzero descendant receipts. Unknown raw diagnostics stay private.
use super::{
    failure::Events,
    wire::{Loader, Text},
};
fn hex(text: &str) -> Option<u32> {
    if text.len() != 8
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        return None;
    }
    let mut result = 0u32;
    for byte in text.bytes() {
        result = result * 16
            + if byte <= b'9' {
                (byte - b'0') as u32
            } else {
                (byte - b'A' + 10) as u32
            };
    }
    if result != 0 { Some(result) } else { None }
}
pub fn loader(text: &str) -> Option<Loader> {
    match text {
        "loader:unqualified" => Some(Loader::Unqualified),
        "loader:loaded,loader-release:released" => Some(Loader::Released),
        _ => text
            .strip_prefix("loader:win32-")
            .and_then(hex)
            .map(Loader::Failed)
            .or_else(|| {
                text.strip_prefix("loader:loaded,loader-release:win32-")
                    .and_then(hex)
                    .map(Loader::ReleaseFailed)
            }),
    }
}
fn push_loader(events: &mut Events, loader: Loader) {
    match loader {
        Loader::Unqualified => events.label("loader", "unqualified"),
        Loader::Failed(code) => events.loader("loader", code),
        Loader::Released => {
            events.label("loader", "loaded");
            events.label("loader-release", "released");
        }
        Loader::ReleaseFailed(code) => {
            events.label("loader", "loaded");
            events.loader("loader-release", code);
        }
    }
}
pub fn bootstrap(bytes: &[u8]) -> Option<Events> {
    let first = bytes.get(..bytes.len().min(512))?;
    let newline = first.iter().position(|byte| *byte == b'\n')?;
    let head = super::ascii::text(first.get(..newline)?)?;
    let head = head.strip_suffix('\r').unwrap_or(head);
    if head.len() + 1 > 128 {
        return None;
    }
    let category = head.strip_prefix(
        "REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=import-ctypes:",
    )?;
    let allowed = [
        "import-ctypes-native",
        "import-ctypes-denied",
        "import-ctypes-module",
        "import-ctypes-procedure",
        "import-ctypes-init",
        "import-ctypes-memory",
        "import-ctypes-format",
    ];
    let category = allowed.into_iter().find(|item| *item == category)?;
    let mut events = Events::new();
    events.label("import-ctypes", category);
    let tail = bytes.get(newline + 1..)?;
    if tail.is_empty() && bytes.len() <= 512 {
        return Some(events);
    }
    let mut normalized = Text::<512>::new();
    let mut index = 0;
    while index < tail.len() {
        if tail.get(index) == Some(&b'\r') && tail.get(index + 1) == Some(&b'\n') {
            index += 1;
        }
        if !tail.get(index)?.is_ascii()
            || normalized
                .push(super::ascii::text(tail.get(index..index + 1)?)?)
                .is_err()
        {
            push_loader(&mut events, Loader::Unqualified);
            return Some(events);
        }
        index += 1;
    }
    let parsed = normalized
        .text()
        .strip_prefix("REGISTRY_LOADER_FOLLOWUP role=descendant errors=")
        .and_then(|tail| tail.strip_suffix('\n'))
        .and_then(loader)
        .filter(|_| bytes.len() <= 512);
    push_loader(&mut events, parsed.unwrap_or(Loader::Unqualified));
    Some(events)
}
fn phase(value: &str) -> Option<&'static str> {
    const SIMPLE: &[&str] = &[
        "start",
        "token",
        "root",
        "mutation",
        "inventory",
        "identity",
        "close",
        "descendant",
        "report",
        "import-ctypes",
        "import-ctypes-wintypes",
        "import-json",
        "import-os",
        "import-pathlib",
        "import-runpy",
        "import-subprocess",
        "import-time",
    ];
    if let Some(label) = SIMPLE.iter().copied().find(|label| *label == value) {
        return Some(label);
    }
    const TOKEN: &[&str] = &[
        "ti-platform",
        "tf-platform",
        "ti-x64",
        "tf-x64",
        "ti-version",
        "tf-version",
        "ti-abi",
        "tf-abi",
        "ti-import",
        "tf-import",
        "ti-detached",
        "tf-detached",
        "ti-open",
        "tf-open",
        "ti-type-query",
        "tf-type-query",
        "ti-type-length",
        "tf-type-length",
        "ti-elevation-query",
        "tf-elevation-query",
        "ti-elevation-length",
        "tf-elevation-length",
        "ti-restrictions-query",
        "tf-restrictions-query",
        "ti-restrictions-length",
        "tf-restrictions-length",
        "ti-restrictions-len1",
        "tf-restrictions-len1",
        "ti-primary-fields",
        "tf-primary-fields",
        "ti-lpac-query",
        "tf-lpac-query",
        "ti-lpac-value",
        "tf-lpac-value",
        "ti-app-read",
        "tf-app-read",
        "ti-app-value",
        "tf-app-value",
        "ti-caps-read",
        "tf-caps-read",
        "ti-caps-value",
        "tf-caps-value",
        "ti-traversal",
        "tf-traversal",
        "ti-priv-read",
        "tf-priv-read",
        "ti-priv-count",
        "tf-priv-count",
        "ti-priv-value",
        "tf-priv-value",
        "ti-groups-read",
        "tf-groups-read",
        "ti-groups-count",
        "tf-groups-count",
        "ti-sid-read",
        "tf-sid-read",
        "ti-admin",
        "tf-admin",
        "ti-libraries",
        "tf-libraries",
        "ti-prototypes",
        "tf-prototypes",
        "ti-job-query",
        "tf-job-query",
        "ti-job-value",
        "tf-job-value",
        "ti-deadline",
        "tf-deadline",
    ];
    TOKEN.iter().copied().find(|label| *label == value)
}
fn kind(value: &str, phase: &str) -> Option<&'static str> {
    const BASIC: &[&str] = &[
        "control",
        "timeout",
        "decode",
        "encode",
        "native",
        "transport",
        "other",
        "cleanup",
    ];
    if let Some(label) = BASIC.iter().copied().find(|label| *label == value) {
        return Some(label);
    }
    if phase.starts_with("ti-") || phase.starts_with("tf-") {
        return None;
    }
    const IMPORT: &[&str] = &[
        "import",
        "import-ctypes-denied",
        "import-ctypes-module",
        "import-ctypes-procedure",
        "import-ctypes-init",
        "import-ctypes-memory",
        "import-ctypes-format",
        "import-ctypes",
        "missing-ctypes",
        "import-ctypes-native",
        "missing-ctypes-native",
        "import-struct",
        "missing-struct",
        "import-struct-native",
        "missing-struct-native",
        "import-endian",
        "missing-endian",
        "import-os",
        "missing-os",
        "import-types",
        "missing-types",
        "import-absent",
        "missing-absent",
        "import-unrecognized",
        "missing-unrecognized",
    ];
    IMPORT.iter().copied().find(|label| *label == value)
}
pub fn allowed_event(label: &str, category: &str) -> bool {
    phase(label).is_some() && kind(category, label).is_some()
}
pub fn nonzero(bytes: &[u8]) -> Events {
    let mut result = Events::new();
    result.label("descendant", "transport");
    let candidate = || -> Option<Events> {
        if bytes.len() > 512 || !bytes.is_ascii() {
            return None;
        }
        let text = super::ascii::text(bytes)?;
        let fields = text
            .strip_prefix("REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=")?
            .strip_suffix('\n')?;
        if !fields.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || [b':', b',', b'-'].contains(&byte)
        }) {
            return None;
        }
        if !(1..=7).contains(&super::ascii::split(fields, b',').count()) {
            return None;
        }
        let mut events = Events::new();
        for field in super::ascii::split(fields, b',') {
            let (left, right) = super::ascii::split_once(field, b':')?;
            let phase = phase(left)?;
            events.label(phase, kind(right, phase)?);
        }
        Some(events)
    };
    if let Some(events) = candidate() {
        result.append_fault(super::object::Fault::Events(events), "descendant");
    }
    result
}
pub fn captured(bytes: &[u8], code: Option<u32>) -> Option<Events> {
    if let Some(events) = bootstrap(bytes) {
        return Some(events);
    }
    let code = code?;
    if !bytes.is_ascii() {
        return None;
    }
    let mut normalized = Text::<512>::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = if bytes[index] == b'\r' {
            if bytes.get(index + 1) == Some(&b'\n') {
                index += 1;
            }
            b'\n'
        } else {
            bytes[index]
        };
        normalized.push(super::ascii::text(&[byte])?).ok()?;
        index += 1;
    }
    if code != 0 {
        Some(nonzero(normalized.text().as_bytes()))
    } else if !normalized.text().is_empty() {
        let mut events = Events::new();
        events.label("descendant", "transport");
        Some(events)
    } else {
        None
    }
}
