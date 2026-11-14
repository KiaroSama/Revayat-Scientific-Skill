//! Exact machine-key authority records and bounded failure receipts. Never trusts raw child text.
use super::{Condition, StartupObservation};
use crate::windows_security::activation::{Failures, dispatch::QualifiedFailure};
use anyhow::{Result, ensure};
use registry_authority::protocol;
use std::fmt;

pub const PYTHON_TOKEN_STAGES: &str = "platform|x64|version|abi|import|detached|open|type-query|type-length|elevation-query|elevation-length|restrictions-query|restrictions-length|restrictions-len1|primary-fields|lpac-query|lpac-value|app-read|app-value|caps-read|caps-value|traversal|priv-read|priv-count|priv-value|groups-read|groups-count|sid-read|admin|libraries|prototypes|job-query|job-value|deadline";
fn hex(value: &str) -> bool {
    value.len() == 8
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c))
}
fn import_category(value: &str) -> bool {
    value.strip_prefix("import-ctypes-").is_some_and(|part| {
        [
            "native",
            "denied",
            "module",
            "procedure",
            "init",
            "memory",
            "format",
        ]
        .contains(&part)
    })
}
pub fn loader_tail(value: &str) -> bool {
    if [
        "loader:unqualified",
        "loader:loaded,loader-release:released",
    ]
    .contains(&value)
    {
        return true;
    }
    let code = value
        .strip_prefix("loader:win32-")
        .or_else(|| value.strip_prefix("loader:loaded,loader-release:win32-"));
    code.is_some_and(|code| hex(code) && code != "00000000")
}
fn original_import(line: &str) -> Option<&str> {
    let event = line
        .strip_prefix("REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=")?
        .strip_suffix('\n')?;
    if import_category(event.strip_prefix("import-ctypes:")?) {
        Some(event)
    } else {
        None
    }
}
pub fn from_prefix(bytes: &[u8], truncated: bool) -> Option<String> {
    if bytes.len() > 512 {
        return None;
    }
    let newline = bytes.iter().position(|byte| *byte == b'\n')?;
    if newline >= 128 || !bytes[..=newline].is_ascii() {
        return None;
    }
    let first = std::str::from_utf8(&bytes[..=newline])
        .ok()?
        .replace("\r\n", "\n");
    let event = original_import(&first)?;
    let detail = format!("child_exit=none errors={event}");
    if newline + 1 == bytes.len() && !truncated {
        return Some(format!("{detail} followup=none"));
    }
    if !truncated && bytes[newline + 1..].is_ascii() {
        let rest = std::str::from_utf8(&bytes[newline + 1..])
            .ok()?
            .replace("\r\n", "\n");
        if let Some(tail) = rest
            .strip_prefix("REGISTRY_LOADER_FOLLOWUP role=primary errors=")
            .and_then(|r| r.strip_suffix('\n'))
            && loader_tail(tail)
        {
            return Some(format!("{detail} followup={tail}"));
        }
    }
    Some(format!("{detail} followup=unqualified"))
}
pub fn loader_detail(text: &str) -> Option<String> {
    if text.len() > 512 || !text.is_ascii() {
        let prefix = &text.as_bytes()[..text.len().min(128)];
        return from_prefix(prefix, true);
    }
    if let Some(body) = text
        .strip_prefix("REGISTRY_AUTHORITY_FAILURE role=primary child_exit=")
        .and_then(|r| r.strip_suffix('\n'))
        && let Some((child, events)) = body.split_once(" errors=")
        && (child == "none" || hex(child))
        && let Some((first, tail)) = events.split_once(',')
        && first
            .strip_prefix("import-ctypes:")
            .is_some_and(import_category)
        && let Some((loader, last)) = tail.rsplit_once(',')
        && ["descendant:transport", "descendant:timeout"].contains(&last)
    {
        return Some(format!(
            "child_exit={child} errors={first},{},{last}",
            if loader_tail(loader) {
                loader
            } else {
                "loader:unqualified"
            }
        ));
    }
    from_prefix(text.as_bytes(), false)
}
fn event(value: &str) -> bool {
    let Some((phase, kind)) = value.split_once(':') else {
        return false;
    };
    if phase == "panic" {
        return protocol::panic_kind(kind).is_some();
    }
    if phase == "mutation" && protocol::network_kind(kind).is_some() {
        return true;
    }
    if phase == "token" && protocol::TOKEN_CHECKS.contains(&kind)
        || phase == "descendant" && protocol::DESCENDANT_CHECKS.contains(&kind)
    {
        return true;
    }
    if let Some(label) = phase
        .strip_prefix("ti-")
        .or_else(|| phase.strip_prefix("tf-"))
    {
        return PYTHON_TOKEN_STAGES.split('|').any(|part| part == label)
            && [
                "control",
                "timeout",
                "decode",
                "encode",
                "native",
                "transport",
                "other",
                "cleanup",
            ]
            .contains(&kind);
    }
    if ![
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
    ]
    .contains(&phase)
    {
        return false;
    }
    if [
        "control",
        "timeout",
        "decode",
        "encode",
        "native",
        "transport",
        "other",
        "cleanup",
        "import",
    ]
    .contains(&kind)
        || import_category(kind)
    {
        return true;
    }
    kind.strip_prefix("import-")
        .or_else(|| kind.strip_prefix("missing-"))
        .is_some_and(|label| {
            [
                "ctypes",
                "ctypes-native",
                "struct",
                "struct-native",
                "endian",
                "os",
                "types",
                "absent",
                "unrecognized",
            ]
            .contains(&label)
        })
}
pub fn failure_detail(errors: &str) -> Option<String> {
    if let Some(detail) = loader_detail(errors) {
        return Some(detail);
    }
    if errors.len() > 512 || !errors.is_ascii() {
        return None;
    }
    let normalized = errors.replace("\r\n", "\n");
    let body = normalized
        .strip_prefix("REGISTRY_AUTHORITY_FAILURE role=primary child_exit=")?
        .strip_suffix('\n')?;
    let (child, rest) = body.split_once(" errors=")?;
    if child != "none" && !hex(child) {
        return None;
    }
    let (events, suffix) = match rest.split_once(' ') {
        Some((events, suffix)) => (events, Some(suffix)),
        None => (rest, None),
    };
    let entries = events.split(',').collect::<Vec<_>>();
    if entries.is_empty() || entries.len() > 8 || !entries.iter().all(|value| event(value)) {
        return None;
    }
    if let Some(suffix) = suffix {
        if let Some(query) = suffix.strip_prefix("restrictions=") {
            if !entries.contains(&"token:control-restrictions-query")
                || protocol::RestrictionQuery::parse(query).is_none()
            {
                return None;
            }
        } else {
            let code = suffix.strip_prefix("native_error=")?;
            let (code, network_diag) = match code.split_once(" network_diag=") {
                Some((code, diagnostic)) => (code, Some(diagnostic)),
                None => (code, None),
            };
            if !hex(code)
                || !entries.iter().any(|entry| {
                    entry
                        .strip_prefix("descendant:")
                        .is_some_and(|kind| protocol::NATIVE_CHECKS.contains(&kind))
                        || entry
                            .strip_prefix("mutation:")
                            .is_some_and(|kind| protocol::network_kind(kind).is_some())
                })
            {
                return None;
            }
            if let Some(diagnostic) = network_diag
                && (code == "00000000"
                    || !entries.contains(&"mutation:network-startup")
                    || protocol::NetworkDiagnostic::parse(diagnostic).is_none())
            {
                return None;
            }
        }
    }
    Some(format!(
        "child_exit={child} errors={events}{}",
        suffix.map_or(String::new(), |value| format!(" {value}"))
    ))
}
pub struct ReceiptFailure {
    exit: Option<u32>,
    detail: String,
}
impl fmt::Display for ReceiptFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fixed registry authority failed primary_exit={} {} raw_error_withheld=True",
            self.exit
                .map_or("none".into(), |code| format!("0x{code:08X}")),
            self.detail
        )
    }
}
impl fmt::Debug for ReceiptFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for ReceiptFailure {}
pub fn transport_failure(code: u32, errors: Option<&str>) -> anyhow::Error {
    ReceiptFailure {
        exit: Some(code),
        detail: errors
            .and_then(failure_detail)
            .unwrap_or_else(|| "unqualified".into()),
    }
    .into()
}
pub fn validate_success(code: u32, text: Option<&str>, errors: Option<&str>) -> Result<()> {
    let text = text.ok_or_else(|| anyhow::anyhow!("registry authority output is missing"))?;
    ensure!(
        code == 0 && errors == Some("") && text.len() <= 2048 && text.is_ascii(),
        "registry authority transport is incomplete"
    );
    let normalized = text.replace("\r\n", "\n");
    let lines = normalized.split('\n').collect::<Vec<_>>();
    ensure!(
        lines.len() == 3 && lines[2].is_empty(),
        "registry authority requires two exact records"
    );
    for (index, role) in ["primary", "descendant"].into_iter().enumerate() {
        let value: serde_json::Value = serde_json::from_str(lines[index])?;
        let accessible = u32::try_from(
            value["accessible"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("registry authority count missing"))?,
        )?;
        let subkeys = u32::try_from(
            value["subkeys"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("registry authority count missing"))?,
        )?;
        let expected = protocol::record(role, subkeys, accessible)
            .map_err(|_| anyhow::anyhow!("registry authority count out of bounds"))?;
        ensure!(
            expected == format!("{}\n", lines[index]),
            "registry authority record is not canonical"
        );
    }
    Ok(())
}
pub fn validate_wire(code: u32, text: Option<&str>, errors: Option<&str>) -> Result<()> {
    validate_success(code, text, errors).map_err(|_| transport_failure(code, errors))
}
pub fn require_root_only(text: &str) -> Result<()> {
    validate_success(0, Some(text), Some(""))?;
    for line in text.replace("\r\n", "\n").lines() {
        ensure!(
            line.starts_with("{\"accessible\":0,"),
            "supported registry grant reached an immediate child"
        );
    }
    Ok(())
}
pub struct AuthorityObservation {
    preparation: StartupObservation,
    recorded: bool,
    wire: Option<String>,
}
impl Default for AuthorityObservation {
    fn default() -> Self {
        Self {
            preparation: StartupObservation::new(Condition::Readable),
            recorded: false,
            wire: None,
        }
    }
}
impl AuthorityObservation {
    pub fn require_role(
        &self,
        expected: Option<i32>,
        trusted_preflight: bool,
        conflict_flags: u32,
    ) -> Result<()> {
        ensure!(
            expected == Some(0) && trusted_preflight && conflict_flags == 0,
            "registry authority requires its fixed undebugged pass-code role"
        );
        self.require_fresh()
    }
    pub fn require_fresh(&self) -> Result<()> {
        self.preparation.require_fresh()?;
        ensure!(
            !self.recorded && self.wire.is_none(),
            "registry authority observation was reused"
        );
        Ok(())
    }
    pub fn prepare(&mut self, a: &[u8], b: &[u8]) -> Result<()> {
        self.preparation.prepare(a, b)
    }
    pub fn require_policy(&self, a: &[u8], b: &[u8]) -> Result<()> {
        self.preparation.require_policy(a, b)
    }
    pub fn read_control(&mut self, status: i32) -> Result<()> {
        self.preparation.read_control(status)
    }
    pub fn stage(&mut self, code: u32, text: Option<&str>, errors: Option<&str>) -> Result<()> {
        validate_wire(code, text, errors)?;
        self.preparation.stage(code, Some(""), Some(""))?;
        self.wire = text.map(str::to_owned);
        Ok(())
    }
    pub fn complete(&mut self) -> Result<()> {
        self.preparation.complete()?;
        ensure!(
            self.wire.is_some() && !self.recorded,
            "registry authority completion missing wire"
        );
        self.recorded = true;
        Ok(())
    }
    pub fn recorded(&self) -> bool {
        self.recorded
    }
    pub fn wire(&self) -> Option<&str> {
        self.wire.as_deref()
    }
}

pub struct PrivateFailure {
    original: anyhow::Error,
    category: &'static str,
}
impl PrivateFailure {
    pub fn original(&self) -> &anyhow::Error {
        &self.original
    }
}
impl fmt::Display for PrivateFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fixed registry authority failure category={} raw_error_withheld=True",
            self.category
        )
    }
}
impl fmt::Debug for PrivateFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for PrivateFailure {}
pub fn sanitize(error: anyhow::Error) -> anyhow::Error {
    if error.is::<PrivateFailure>()
        || error.is::<ReceiptFailure>()
        || error.is::<crate::windows_security::activation::diagnostics::AuthoredFailure>()
        || error.is::<crate::windows_security::sxs::PrivateFailure>()
        || error.is::<std::sync::Arc<crate::windows_security::sxs::PrivateFailure>>()
    {
        return error;
    }
    let error = match error.downcast::<Failures>() {
        Ok(group) => {
            return Failures {
                errors: group.errors.into_iter().map(sanitize).collect(),
            }
            .into();
        }
        Err(error) => error,
    };
    let error = match error.downcast::<QualifiedFailure>() {
        Ok(error) => return error.map_original(sanitize).into(),
        Err(error) => error,
    };
    let category = if error.is::<super::surface::NameEncoding>() {
        "encode"
    } else if error.is::<std::string::FromUtf16Error>()
        || error.is::<std::str::Utf8Error>()
        || error.is::<std::string::FromUtf8Error>()
    {
        "decode"
    } else if error.is::<crate::runtime::DeadlineExceeded>()
        || error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
    {
        "timeout"
    } else if error.is::<std::io::Error>() {
        "native"
    } else {
        "control"
    };
    PrivateFailure {
        original: error,
        category,
    }
    .into()
}

#[path = "registry_wire_checks.rs"]
mod checks;
pub use checks::check_validation;
pub fn preserve(
    operation: Option<anyhow::Error>,
    exit: Option<u32>,
    prefix: &[u8],
    truncated: bool,
) -> Option<anyhow::Error> {
    let Some(detail) = from_prefix(prefix, truncated) else {
        return operation;
    };
    let receipt: anyhow::Error = ReceiptFailure { exit, detail }.into();
    Some(match operation {
        Some(operation) => Failures {
            errors: vec![receipt, operation],
        }
        .into(),
        None => receipt,
    })
}

/// Render only source-closed receipt/private nodes. Unknown raw Display/Debug and
/// Error::source chains are deliberately withheld, including inside aggregate errors.
pub fn safe_report(error: &anyhow::Error) -> String {
    fn visit(error: &anyhow::Error, depth: usize, out: &mut String) {
        if depth >= 32 || out.len() >= 4096 {
            return;
        }
        let text = if let Some(group) = error.downcast_ref::<Failures>() {
            out.push_str("fixed registry authority operation/cleanup failed");
            for error in &group.errors {
                out.push_str("; ");
                visit(error, depth + 1, out);
            }
            return;
        } else if let Some(qualified) = error.downcast_ref::<QualifiedFailure>() {
            out.push_str("fixed entry diagnostic failed after qualified cleanup; ");
            visit(qualified.original(), depth + 1, out);
            return;
        } else if error.is::<crate::windows_security::activation::diagnostics::AuthoredFailure>() {
            crate::windows_security::activation::diagnostics::summary(error)
        } else if error.is::<ReceiptFailure>()
            || error.is::<PrivateFailure>()
            || error.is::<crate::windows_security::sxs::PrivateFailure>()
            || error.is::<std::sync::Arc<crate::windows_security::sxs::PrivateFailure>>()
        {
            error.to_string()
        } else {
            "fixed registry authority failure category=other raw_error_withheld=True".into()
        };
        out.push_str(&text);
    }
    let mut output = String::new();
    visit(error, 0, &mut output);
    if output.len() > 4096 {
        let mut end = 4096;
        while !output.is_char_boundary(end) {
            end -= 1;
        }
        output.truncate(end);
    }
    output
}
