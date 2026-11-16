//! Shared bounded text-read, decoding diagnostics and private failure ownership.
use super::super::{PrivateFailure, safe_stage};
use crate::windows_security::activation::Failures;
use anyhow::{Result, ensure};

pub const TEXT_MAXIMUM: i64 = 1_048_576;
#[derive(Debug)]
pub(super) struct ContractFailure;
impl std::fmt::Display for ContractFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fixed SxS evidence predicate rejected")
    }
}
impl std::error::Error for ContractFailure {}
pub(super) fn private(
    original: anyhow::Error,
    stage: impl Into<std::borrow::Cow<'static, str>>,
) -> anyhow::Error {
    PrivateFailure {
        stage: stage.into(),
        original,
    }
    .into()
}
#[derive(Clone, Copy)]
pub(super) enum Predicate {
    ReadComplete,
    Bom,
    Nul,
    LineCount,
    LineWidth,
    Cr,
    Framing,
    Nested,
    BlockCount,
    End,
    SelectedCount,
    ManifestCount,
    Unsupported,
    Empty,
    Final,
    Output,
}
impl Predicate {
    pub(super) fn from_index(index: i32) -> Result<Self> {
        Ok(match index {
            0 => Self::ReadComplete,
            1 => Self::Bom,
            2 => Self::Nul,
            3 => Self::LineCount,
            4 => Self::LineWidth,
            5 => Self::Cr,
            6 => Self::Framing,
            7 => Self::Nested,
            8 => Self::BlockCount,
            9 => Self::End,
            10 => Self::SelectedCount,
            11 => Self::ManifestCount,
            12 => Self::Unsupported,
            13 => Self::Empty,
            14 => Self::Final,
            15 => Self::Output,
            _ => anyhow::bail!("unsupported fixed SxS evidence predicate"),
        })
    }
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::ReadComplete => "evidence-read-complete",
            Self::Bom => "evidence-bom",
            Self::Nul => "evidence-nul",
            Self::LineCount => "evidence-line-count",
            Self::LineWidth => "evidence-line-width",
            Self::Cr => "evidence-cr",
            Self::Framing => "evidence-framing",
            Self::Nested => "evidence-nested",
            Self::BlockCount => "evidence-block-count",
            Self::End => "evidence-end",
            Self::SelectedCount => "evidence-selected-count",
            Self::ManifestCount => "evidence-manifest-count",
            Self::Unsupported => "evidence-unsupported",
            Self::Empty => "evidence-empty",
            Self::Final => "evidence-final",
            Self::Output => "evidence-output",
        }
    }
}
pub(super) fn check_stage(value: bool, stage: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(private(ContractFailure.into(), stage))
    }
}
pub(super) fn check(value: bool, predicate: Predicate) -> Result<()> {
    check_stage(value, predicate.label())
}
#[derive(Clone, Copy)]
pub enum LengthPhase {
    FileBound,
    ReadShape,
    InputShape,
}
impl LengthPhase {
    pub(super) fn from_index(index: i32) -> Result<Self> {
        Ok(match index {
            0 => Self::FileBound,
            1 => Self::ReadShape,
            2 => Self::InputShape,
            _ => anyhow::bail!("unsupported fixed SxS length phase"),
        })
    }
    fn label(self) -> &'static str {
        match self {
            Self::FileBound => "file-bound",
            Self::ReadShape => "read-shape",
            Self::InputShape => "input-shape",
        }
    }
}
pub(super) fn length_failure(
    phase: &'static str,
    comparison: &'static str,
    observed: Option<i64>,
    maximum: i64,
    even: Option<bool>,
) -> anyhow::Error {
    let observed = observed.map_or_else(|| "absent".into(), |value| value.to_string());
    let even = even.map_or(
        "not-evaluated",
        |value| if value { "True" } else { "False" },
    );
    private(
        ContractFailure.into(),
        format!(
            "evidence-length-{phase} comparison={comparison} observed_bytes={observed} maximum_bytes={maximum} even={even}"
        ),
    )
}
/// Retains each short-circuited native length observation, including a changing file.
pub fn require_length(
    mut length: impl FnMut() -> Result<i64>,
    maximum: i64,
    phase: LengthPhase,
) -> Result<()> {
    let observed = length()?;
    if match phase {
        LengthPhase::FileBound => observed <= 0,
        _ => observed < 2,
    } {
        return Err(length_failure(
            phase.label(),
            "minimum",
            Some(observed),
            maximum,
            None,
        ));
    }
    let observed = length()?;
    if observed > maximum {
        return Err(length_failure(
            phase.label(),
            "maximum",
            Some(observed),
            maximum,
            None,
        ));
    }
    Ok(())
}
pub(super) fn allocation_length(observed: i64) -> Result<usize> {
    if observed < 2 {
        return Err(length_failure(
            "allocation",
            "minimum",
            Some(observed),
            TEXT_MAXIMUM,
            None,
        ));
    }
    if observed > TEXT_MAXIMUM {
        return Err(length_failure(
            "allocation",
            "maximum",
            Some(observed),
            TEXT_MAXIMUM,
            None,
        ));
    }
    Ok(observed as usize)
}
fn signature(bytes: Option<&[u8]>, count: usize) -> Result<&'static str> {
    ensure!(
        count <= 3 && bytes.map_or(count == 0, |bytes| count <= bytes.len()),
        "fixed SxS prefix count differs"
    );
    Ok(if count == 0 {
        "absent"
    } else if count >= 3 && bytes.is_some_and(|bytes| bytes[..3] == [239, 187, 191]) {
        "utf8-bom"
    } else if count >= 2 && bytes.is_some_and(|bytes| bytes[..2] == [255, 254]) {
        "utf16le-prefix"
    } else {
        "other"
    })
}
pub(super) struct PrefixObservation {
    pub(super) report: anyhow::Error,
}
fn prefix_report(
    status: &'static str,
    signature: &'static str,
    transferred: Option<usize>,
    original: Option<anyhow::Error>,
) -> PrefixObservation {
    let transferred = transferred.map_or_else(|| "unavailable".into(), |count| count.to_string());
    PrefixObservation {
        report: private(
            original.unwrap_or_else(|| ContractFailure.into()),
            format!(
                "evidence-prefix status={status} signature={signature} transferred_bytes={transferred}"
            ),
        ),
    }
}
pub(super) fn inspect_array(bytes: Option<&[u8]>) -> Result<Option<PrefixObservation>> {
    let count = bytes.map_or(0, |bytes| bytes.len().min(3));
    Ok(Some(prefix_report(
        "array",
        signature(bytes, count)?,
        Some(count),
        None,
    )))
}
pub(super) fn combine_private(
    first: anyhow::Error,
    second: anyhow::Error,
    stage: &'static str,
) -> anyhow::Error {
    let left = safe_stage(first, "text-read");
    let right = safe_stage(second, stage);
    let label = format!(
        "{} {}",
        left.downcast_ref::<PrivateFailure>()
            .expect("private left")
            .stage(),
        right
            .downcast_ref::<PrivateFailure>()
            .expect("private right")
            .stage()
    );
    private(
        Failures {
            errors: vec![left, right],
        }
        .into(),
        label,
    )
}
pub(super) fn supplement(
    original: anyhow::Error,
    inspect: impl FnOnce() -> Result<Option<PrefixObservation>>,
) -> anyhow::Error {
    let observation = match inspect() {
        Ok(Some(value)) => value,
        Ok(None) => prefix_report("unavailable", "unavailable", None, None),
        Err(error) => prefix_report("unavailable", "unavailable", None, Some(error)),
    };
    combine_private(original, observation.report, "evidence-prefix")
}

/// A held, already admitted stream. The native adapter retains path/handle identity authority.
pub trait EvidenceRead {
    fn length(&mut self) -> Result<i64>;
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize>;
    fn close(&mut self) -> Result<()>;
    /// Read-only observation after the complete allocation has been cleared, before close.
    fn bytes_cleared(&mut self, _bytes: &[u8]) {}
}
impl<T: EvidenceRead + ?Sized> EvidenceRead for &mut T {
    fn length(&mut self) -> Result<i64> {
        (**self).length()
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize> {
        (**self).read(bytes)
    }
    fn close(&mut self) -> Result<()> {
        (**self).close()
    }
    fn bytes_cleared(&mut self, bytes: &[u8]) {
        (**self).bytes_cleared(bytes)
    }
}
pub fn read_owned<S: EvidenceRead>(
    open: impl FnOnce() -> Result<S>,
    parse: impl FnOnce(&[u8]) -> Result<String>,
) -> Result<String> {
    let mut file = open()?;
    let mut bytes = None;
    let operation = (|| {
        require_length(|| file.length(), TEXT_MAXIMUM, LengthPhase::ReadShape)?;
        let length = allocation_length(file.length()?)?;
        bytes = Some(vec![0u8; length]);
        let bytes = bytes.as_mut().expect("allocated evidence buffer");
        let mut offset = 0;
        while offset < bytes.len() {
            let remaining = bytes.len() - offset;
            let n = file.read(&mut bytes[offset..])?;
            check(n > 0 && n <= remaining, Predicate::ReadComplete)?;
            offset += n;
        }
        parse(bytes)
    })();
    if let Some(bytes) = &mut bytes {
        bytes.fill(0);
        file.bytes_cleared(bytes);
    }
    match (operation, file.close()) {
        (value, Ok(())) => value,
        (Ok(_), Err(error)) => Err(private(error, "evidence-close")),
        (Err(primary), Err(error)) => Err(combine_private(
            primary,
            private(error, "evidence-close"),
            "evidence-close",
        )),
    }
}
pub(super) fn decode_optional(bytes: Option<&[u8]>) -> Result<Vec<String>> {
    let length = match bytes {
        Some(bytes) => require_length(
            || Ok(bytes.len() as i64),
            TEXT_MAXIMUM,
            LengthPhase::InputShape,
        ),
        None => Err(length_failure(
            "input-shape",
            "present",
            None,
            TEXT_MAXIMUM,
            None,
        )),
    };
    if let Err(original) = length {
        return Err(supplement(original, || inspect_array(bytes)));
    }
    let bytes = bytes.expect("checked present bounded evidence");
    let utf16 = bytes.starts_with(&[255, 254]);
    let utf8 = bytes.starts_with(&[239, 187, 191]);
    let framing = (|| {
        check(utf16 || utf8, Predicate::Bom)?;
        if utf16 && !bytes.len().is_multiple_of(2) {
            return Err(length_failure(
                "utf16-shape",
                "even",
                Some(bytes.len() as i64),
                TEXT_MAXIMUM,
                Some(false),
            ));
        }
        Ok(())
    })();
    if let Err(original) = framing {
        return Err(supplement(original, || inspect_array(Some(bytes))));
    }
    let text = if utf16 {
        let mut units = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect::<Vec<_>>();
        let result =
            String::from_utf16(&units).map_err(|error| safe_stage(error.into(), "evidence-utf16"));
        units.fill(0);
        result?
    } else {
        std::str::from_utf8(&bytes[3..])
            .map_err(|error| safe_stage(error.into(), "evidence-utf8"))?
            .to_owned()
    };
    check(!text.contains('\0'), Predicate::Nul)?;
    let lines = text
        .replace("\r\n", "\n")
        .split('\n')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    check(lines.len() <= 4096, Predicate::LineCount)?;
    for line in &lines {
        check(line.encode_utf16().count() <= 2048, Predicate::LineWidth)?;
        check(!line.contains('\r'), Predicate::Cr)?;
    }
    Ok(lines)
}
