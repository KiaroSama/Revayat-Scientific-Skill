//! Closed authored stages and numeric outcomes. Nested raw errors remain private.
use super::{Failures, dispatch::QualifiedFailure};
use std::{error::Error, fmt};
#[derive(Clone, Copy, Debug)]
pub enum Stage {
    DebugCreate,
    DebugAttach,
    DebugResume,
    DebugEvent,
    DebugDispatchLoad,
    DebugKernelProfile,
    DebugNtdllExport,
    DebugSystemIdentity,
    DebugExecutable,
    DebugDispatchTarget,
    DebugCaptureState,
    DebugCaptureRead,
    DebugCaptureCause,
    DebugCaptureSite,
    DebugCaptureOwnership,
    DebugCaptureControl,
    DebugPairCall,
    DebugPairReturn,
    DebugExitWait,
    DebugRetire,
    DebugTransport,
    DebugCleanup,
    EvtClock,
    EvtQuery,
    EvtNext,
    EvtSize,
    EvtRender,
    EvtAllocate,
    EvtRead,
    EvtRelease,
    EvtClose,
    EvtClassify,
    SxsToolCreate,
    SxsToolResume,
    SxsToolExit,
    SxsStart,
    SxsBind,
    SxsAuthority,
    SxsControl,
    SxsStop,
    SxsParse,
    SxsStorage,
    SxsStorageDrive,
    SxsStorageCreate,
    SxsStoragePolicy,
    SxsStorageDeny,
}
impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::DebugCreate => "debug-create",
            Self::DebugAttach => "debug-attach",
            Self::DebugResume => "debug-resume",
            Self::DebugEvent => "debug-event",
            Self::DebugDispatchLoad => "debug-dispatch-load",
            Self::DebugKernelProfile => "debug-kernel-profile",
            Self::DebugNtdllExport => "debug-ntdll-export",
            Self::DebugSystemIdentity => "debug-system-identity",
            Self::DebugExecutable => "debug-executable",
            Self::DebugDispatchTarget => "debug-dispatch-target",
            Self::DebugCaptureState => "debug-capture-state",
            Self::DebugCaptureRead => "debug-capture-read",
            Self::DebugCaptureCause => "debug-capture-cause",
            Self::DebugCaptureSite => "debug-capture-site",
            Self::DebugCaptureOwnership => "debug-capture-ownership",
            Self::DebugCaptureControl => "debug-capture-control",
            Self::DebugPairCall => "debug-pair-call",
            Self::DebugPairReturn => "debug-pair-return",
            Self::DebugExitWait => "debug-exit-wait",
            Self::DebugRetire => "debug-retire",
            Self::DebugTransport => "debug-transport",
            Self::DebugCleanup => "debug-cleanup",
            Self::EvtClock => "evt-clock",
            Self::EvtQuery => "evt-query",
            Self::EvtNext => "evt-next",
            Self::EvtSize => "evt-size",
            Self::EvtRender => "evt-render",
            Self::EvtAllocate => "evt-allocate",
            Self::EvtRead => "evt-read",
            Self::EvtRelease => "evt-release",
            Self::EvtClose => "evt-close",
            Self::EvtClassify => "evt-classify",
            Self::SxsToolCreate => "sxs-tool-create",
            Self::SxsToolResume => "sxs-tool-resume",
            Self::SxsToolExit => "sxs-tool-exit",
            Self::SxsStart => "sxs-start",
            Self::SxsBind => "sxs-bind",
            Self::SxsAuthority => "sxs-authority",
            Self::SxsControl => "sxs-control",
            Self::SxsStop => "sxs-stop",
            Self::SxsParse => "sxs-parse",
            Self::SxsStorage => "sxs-storage",
            Self::SxsStorageDrive => "sxs-storage-drive",
            Self::SxsStorageCreate => "sxs-storage-create",
            Self::SxsStoragePolicy => "sxs-storage-policy",
            Self::SxsStorageDeny => "sxs-storage-deny",
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Numbers {
    pub native_error: Option<u32>,
    pub result: Option<u32>,
    pub count: Option<u32>,
    pub bytes: Option<u32>,
    pub properties: Option<u32>,
    pub dr6: Option<u64>,
    pub dr7: Option<u64>,
}
pub struct AuthoredFailure {
    pub stage: Stage,
    pub numbers: Numbers,
    original: anyhow::Error,
}
impl AuthoredFailure {
    pub fn original(&self) -> &anyhow::Error {
        &self.original
    }
}
impl fmt::Display for AuthoredFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fixed native operation failed stage={}",
            self.stage.label()
        )?;
        for (name, value) in [
            ("native_error", self.numbers.native_error),
            ("result", self.numbers.result),
            ("count", self.numbers.count),
            ("bytes", self.numbers.bytes),
            ("properties", self.numbers.properties),
        ] {
            if let Some(value) = value {
                write!(f, " {name}=0x{value:08X}")?;
            }
        }
        for (name, value) in [("raw_dr6", self.numbers.dr6), ("raw_dr7", self.numbers.dr7)] {
            if let Some(value) = value {
                write!(f, " {name}=0x{value:016X}")?;
            }
        }
        Ok(())
    }
}
impl fmt::Debug for AuthoredFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Error for AuthoredFailure {}
pub fn annotate(error: anyhow::Error, stage: Stage, numbers: Numbers) -> anyhow::Error {
    AuthoredFailure {
        stage,
        numbers,
        original: error,
    }
    .into()
}
pub fn at(error: anyhow::Error, stage: Stage) -> anyhow::Error {
    annotate(error, stage, Numbers::default())
}
pub fn native(stage: Stage, numbers: Numbers) -> anyhow::Error {
    annotate(
        anyhow::anyhow!("fixed native API outcome refused"),
        stage,
        numbers,
    )
}
/// The diagnostic projection visits only known private carriers and never formats a raw cause.
pub fn summary(error: &anyhow::Error) -> String {
    fn visit(error: &anyhow::Error, depth: usize, lines: &mut Vec<String>) {
        if depth >= 16 || lines.len() >= 16 {
            return;
        }
        if let Some(value) = error.downcast_ref::<AuthoredFailure>() {
            lines.push(value.to_string());
            visit(value.original(), depth + 1, lines);
        } else if let Some(value) = error.downcast_ref::<Failures>() {
            lines.push(format!(
                "fixed activation failure_group count={}",
                value.errors.len()
            ));
            for error in &value.errors {
                visit(error, depth + 1, lines);
            }
        } else if let Some(value) =
            error.downcast_ref::<crate::windows_security::sxs::PrivateFailure>()
        {
            lines.push(value.to_string());
            visit(value.original(), depth + 1, lines);
        } else if let Some(value) = error.downcast_ref::<QualifiedFailure>() {
            lines.push("fixed activation cleanup_qualified=True diagnostic_failed=True".into());
            visit(value.original(), depth + 1, lines);
        } else if let Some(value) = error.downcast_ref::<std::io::Error>() {
            lines.push(format!(
                "fixed native I/O failure native_error={:?}",
                value.raw_os_error()
            ));
        } else {
            lines.push("fixed native diagnostic detail_withheld=True".into());
        }
    }
    let mut lines = Vec::new();
    visit(error, 0, &mut lines);
    let mut result = String::new();
    for line in lines {
        let separator = usize::from(!result.is_empty());
        if line.len() + separator > 4096usize.saturating_sub(result.len()) {
            break;
        }
        if separator != 0 {
            result.push('\n');
        }
        result.push_str(&line);
    }
    result
}
/// Inspect retained typed causes in tests/owners without exposing their Display or Debug text.
pub fn find<T: Error + Send + Sync + 'static>(error: &anyhow::Error) -> Option<&T> {
    fn visit<T: Error + Send + Sync + 'static>(error: &anyhow::Error, depth: usize) -> Option<&T> {
        if depth >= 32 {
            return None;
        }
        if let Some(value) = error.downcast_ref::<T>() {
            return Some(value);
        }
        if let Some(value) = error.downcast_ref::<AuthoredFailure>() {
            return visit(value.original(), depth + 1);
        }
        if let Some(value) = error.downcast_ref::<Failures>() {
            return value
                .errors
                .iter()
                .find_map(|error| visit(error, depth + 1));
        }
        if let Some(value) = error.downcast_ref::<crate::windows_security::sxs::PrivateFailure>() {
            return visit(value.original(), depth + 1);
        }
        if let Some(value) = error.downcast_ref::<QualifiedFailure>() {
            return visit(value.original(), depth + 1);
        }
        None
    }
    visit(error, 0)
}
pub fn check_validation() -> anyhow::Result<()> {
    let raw = std::io::Error::other("C:\\private-path\\secret event payload");
    let retained = annotate(
        raw.into(),
        Stage::EvtRender,
        Numbers {
            native_error: Some(5),
            result: Some(0),
            bytes: Some(128),
            properties: Some(0),
            ..Default::default()
        },
    );
    let carrier = crate::windows_security::sxs::safe(retained, "event-evidence");
    let error: anyhow::Error = Failures {
        errors: vec![carrier],
    }
    .into();
    let report = summary(&error);
    anyhow::ensure!(
        report.contains("stage=evt-render")
            && report.contains("native_error=0x00000005")
            && report.contains("bytes=0x00000080")
            && !report.contains("private-path")
            && !report.contains("secret")
            && !report.contains("event payload")
            && report.len() <= 4096,
        "closed native diagnostic projection differs"
    );
    anyhow::ensure!(
        find::<std::io::Error>(&error)
            .is_some_and(|error| error.to_string().contains("private-path")),
        "private diagnostic original was not retained"
    );
    let mut nested = error;
    for _ in 0..40 {
        nested = Failures {
            errors: vec![nested],
        }
        .into();
    }
    anyhow::ensure!(
        summary(&nested).lines().count() <= 16 && summary(&nested).len() <= 4096,
        "native diagnostic recursion budget differs"
    );
    Ok(())
}
