//! Original capture orchestration and closed failure projections shared with the native owner.
use super::{
    PrivateFailure, safe, safe_stage,
    storage_policy::{PolicyFailure, Predicate},
};
use crate::windows_security::activation::Failures;
use anyhow::{Result, ensure};
#[path = "capture_checks.rs"]
mod checks;
pub use checks::check_capture_validation;
fn b(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}
fn combine(first: Option<anyhow::Error>, later: anyhow::Error) -> anyhow::Error {
    match first {
        None => later,
        Some(first) => Failures {
            errors: vec![first, later],
        }
        .into(),
    }
}
#[derive(Clone, Copy, Debug)]
pub enum BoundaryStage {
    PrepareStorage,
    AfterSeal,
    Enter,
}
impl TryFrom<i32> for BoundaryStage {
    type Error = anyhow::Error;
    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::PrepareStorage),
            1 => Ok(Self::AfterSeal),
            2 => Ok(Self::Enter),
            _ => anyhow::bail!("unsupported fixed SxS storage boundary"),
        }
    }
}
pub fn boundary(raw: i32, operation: impl FnOnce() -> Result<()>) -> Result<()> {
    let label = match BoundaryStage::try_from(raw)? {
        BoundaryStage::PrepareStorage => "storage-initialize",
        BoundaryStage::AfterSeal => "storage-after-seal",
        BoundaryStage::Enter => "storage-enter",
    };
    operation().map_err(|error| safe(error, label))
}
#[derive(Clone, Copy, Debug)]
pub enum StorageStage {
    Path,
    Host,
    Policy,
    Create,
    Canary,
    DirectoryReadback,
    FileReadback,
    Seed,
}
impl StorageStage {
    pub fn label(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Host => "host",
            Self::Policy => "policy",
            Self::Create => "create",
            Self::Canary => "canary",
            Self::DirectoryReadback => "directory-readback",
            Self::FileReadback => "file-readback",
            Self::Seed => "seed",
        }
    }
}
impl TryFrom<i32> for StorageStage {
    type Error = anyhow::Error;
    fn try_from(value: i32) -> Result<Self> {
        Ok(match value {
            0 => Self::Path,
            1 => Self::Host,
            2 => Self::Policy,
            3 => Self::Create,
            4 => Self::Canary,
            5 => Self::DirectoryReadback,
            6 => Self::FileReadback,
            7 => Self::Seed,
            _ => anyhow::bail!("unsupported fixed SxS storage stage"),
        })
    }
}
#[derive(Clone, Copy, Debug)]
pub enum ParseStage {
    EtlPolicy,
    EtlLength,
    TextAbsent,
    ParseTool,
    TextPolicy,
    TextRead,
    EvidenceOutput,
}
impl ParseStage {
    pub fn label(self) -> &'static str {
        match self {
            Self::EtlPolicy => "etl-policy",
            Self::EtlLength => "etl-length",
            Self::TextAbsent => "text-absent",
            Self::ParseTool => "parse-tool",
            Self::TextPolicy => "text-policy",
            Self::TextRead => "text-read",
            Self::EvidenceOutput => "evidence-output",
        }
    }
}
impl TryFrom<i32> for ParseStage {
    type Error = anyhow::Error;
    fn try_from(value: i32) -> Result<Self> {
        Ok(match value {
            0 => Self::EtlPolicy,
            1 => Self::EtlLength,
            2 => Self::TextAbsent,
            3 => Self::ParseTool,
            4 => Self::TextPolicy,
            5 => Self::TextRead,
            6 => Self::EvidenceOutput,
            _ => anyhow::bail!("unsupported fixed SxS parse stage"),
        })
    }
}
#[derive(Clone, Copy, Debug)]
pub enum ExceptionKind {
    Win32(u32),
    IoHresult(u32),
    DerivedWin32(u32),
}
pub struct StorageException {
    pub kind: ExceptionKind,
    original: anyhow::Error,
}
impl StorageException {
    pub fn new(kind: ExceptionKind, original: anyhow::Error) -> Self {
        Self { kind, original }
    }
    pub fn original(&self) -> &anyhow::Error {
        &self.original
    }
}
impl std::fmt::Display for StorageException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fixed storage exception")
    }
}
impl std::fmt::Debug for StorageException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for StorageException {}
fn details(error: &anyhow::Error) -> (u32, Option<u32>, Option<Predicate>) {
    if let Some(error) = error.downcast_ref::<StorageException>() {
        return match error.kind {
            ExceptionKind::Win32(code) => (0x80004005, Some(code), None),
            ExceptionKind::IoHresult(code) => (code, None, None),
            ExceptionKind::DerivedWin32(_) => (0x80004005, None, None),
        };
    }
    if let Some(error) = error.downcast_ref::<PolicyFailure>() {
        return (0x80131509, None, Some(error.predicate));
    }
    if let Some(error) = error.downcast_ref::<std::io::Error>()
        && let Some(code) = error.raw_os_error()
    {
        return (0x80070000 | (code as u32 & 0xffff), None, None);
    }
    (0x80004005, None, None)
}
pub fn storage_step<T>(raw: i32, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let stage = StorageStage::try_from(raw)?;
    operation().map_err(|error| {
        if error.is::<PrivateFailure>() {
            return error;
        }
        let (hresult, native, predicate) = details(&error);
        safe_stage(
            error,
            format!(
                "storage-{} exception_hresult={hresult:08X} exception_win32={} policy_predicate={}",
                stage.label(),
                native
                    .map(|code| format!("{code:08X}"))
                    .unwrap_or_else(|| "unavailable".into()),
                predicate.map(Predicate::label).unwrap_or("unavailable")
            ),
        )
    })
}
pub fn at_parse<T>(raw: i32, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let stage = ParseStage::try_from(raw)?;
    operation().map_err(|error| {
        if error.is::<PrivateFailure>() {
            return error;
        }
        let predicate = error
            .downcast_ref::<PolicyFailure>()
            .map(|error| error.predicate);
        safe_stage(
            error,
            format!(
                "{}{}",
                stage.label(),
                predicate
                    .map(|predicate| format!(" policy_predicate={}", predicate.label()))
                    .unwrap_or_default()
            ),
        )
    })
}
pub fn same_inputs(expected: &[Option<&str>], actual: &[Option<&str>]) -> Result<()> {
    ensure!(
        expected.len() == 5
            && actual.len() == 5
            && expected
                .iter()
                .zip(actual)
                .all(|(a, b)| a.is_some() && a == b),
        "fixed SxS capture inputs differ"
    );
    Ok(())
}
pub fn acquired<H>(
    acquire: impl FnOnce() -> Result<Option<H>>,
    initialize: impl FnOnce() -> Result<()>,
    execute: impl FnOnce() -> Result<()>,
    close: impl FnOnce(H) -> Result<()>,
) -> Result<()> {
    let mut held = None;
    let acquisition = acquire().and_then(|value| {
        held = value;
        initialize()
    });
    let mut primary = match acquisition {
        Err(error) => Some(safe(error, "acquire")),
        Ok(()) => execute().err(),
    };
    if let Some(held) = held
        && let Err(error) = close(held)
    {
        primary = Some(combine(primary, safe(error, "release")));
    }
    match primary {
        None => Ok(()),
        Some(error) => Err(error),
    }
}
pub fn start_sequence(
    mut remaining: impl FnMut() -> Result<f64>,
    intent: impl FnOnce() -> Result<()>,
    start: impl FnOnce() -> Result<()>,
    reaped: impl FnOnce() -> Result<bool>,
    bind: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let at = |label, operation: Result<()>| operation.map_err(|error| safe(error, label));
    at(
        "initial",
        remaining().and_then(|value| {
            ensure!(value > 0.0, "fixed SxS start deadline expired");
            Ok(())
        }),
    )?;
    at("intent", intent())?;
    at(
        "start-tool",
        remaining().and_then(|value| {
            ensure!(value > 0.0, "fixed SxS start deadline expired");
            start()
        }),
    )?;
    at(
        "post-tool",
        reaped().and_then(|reaped| {
            ensure!(
                reaped && remaining()? > 0.0,
                "fixed SxS starter was not reaped before deadline"
            );
            Ok(())
        }),
    )?;
    at("bind", bind())?;
    at(
        "post-bind",
        remaining().and_then(|value| {
            ensure!(value > 0.0, "fixed SxS start deadline expired");
            Ok(())
        }),
    )?;
    Ok(())
}
pub fn tool_arguments(etl: &str, text: &str, parse: bool) -> Vec<String> {
    if parse {
        vec![
            "parse".into(),
            format!("-logfile:{etl}"),
            format!("-outfile:{text}"),
        ]
    } else {
        vec!["trace".into(), format!("-logfile:{etl}"), "-nostop".into()]
    }
}
pub fn require_sxs_completion(exit: u32, stderr: bool, remaining: f64, elapsed: f64) -> Result<()> {
    let expired = remaining <= 0.0;
    let overrun = elapsed > 10.0;
    if expired || overrun || exit != 0 || stderr {
        return Err(safe_stage(
            CompletionContract.into(),
            format!(
                "tool-result exit32={exit:08X} stderr_present={} deadline_expired={} wall_exceeded={}",
                b(stderr),
                b(expired),
                b(overrun)
            ),
        ));
    }
    Ok(())
}
#[derive(Debug)]
pub struct CompletionContract;
impl std::fmt::Display for CompletionContract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fixed SxS tool did not complete cleanly")
    }
}
impl std::error::Error for CompletionContract {}
