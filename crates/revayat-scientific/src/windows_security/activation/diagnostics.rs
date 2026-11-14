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
    DebugDispatchRegion,
    DebugDispatchLength,
    DebugDispatchPointer,
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
    ScratchPrepare,
    ScratchPrivilege,
    ScratchState,
    ScratchCreate,
    ScratchProvider,
    ScratchImage,
    ScratchAttach,
    ScratchLayout,
    ScratchDeviceControl,
    ScratchDiskIdentity,
    ScratchRawLayout,
    ScratchRawProvider,
    ScratchFormat,
    ScratchMount,
    ScratchQuota,
    ScratchPrivate,
    ScratchSeal,
    ScratchReady,
    FixtureDiscover,
    FixtureHost,
    FixtureState,
    FixtureWindowsRoot,
    FixtureProgramFiles,
    FixtureVswhere,
    FixtureVswhereRun,
    FixtureVsInstall,
    FixturePathShape,
    FixtureVcMetadata,
    FixtureVcVersion,
    FixtureVcBin,
    FixtureLinker,
    FixtureVcDlls,
    FixtureSdkRoot,
    FixtureSdkLibraries,
    FixtureSdkSelect,
    FixtureKernel32,
    FixtureRustupRoot,
    FixtureRustSysroot,
    FixtureRustBin,
    FixtureRustc,
    FixtureRustDlls,
    FixtureRustVersion,
    FixtureTargetLibdir,
    FixtureTargetIdentity,
    FixtureCore,
    FixtureBuiltins,
    FixturePinsVerify,
    FixturePinsClose,
    FixturePinPath,
    FixturePinCanonical,
    FixturePinOpen,
    FixturePinIdentity,
    FixturePinFingerprint,
    FixturePinRead,
    FixtureBuild,
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
            Self::DebugDispatchRegion => "debug-dispatch-region",
            Self::DebugDispatchLength => "debug-dispatch-length",
            Self::DebugDispatchPointer => "debug-dispatch-pointer",
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
            Self::ScratchPrepare => "scratch-prepare",
            Self::ScratchPrivilege => "scratch-privilege",
            Self::ScratchState => "scratch-state",
            Self::ScratchCreate => "scratch-create",
            Self::ScratchProvider => "scratch-provider",
            Self::ScratchImage => "scratch-image",
            Self::ScratchAttach => "scratch-attach",
            Self::ScratchLayout => "scratch-layout",
            Self::ScratchDeviceControl => "scratch-device-control",
            Self::ScratchDiskIdentity => "scratch-disk-identity",
            Self::ScratchRawLayout => "scratch-raw-layout",
            Self::ScratchRawProvider => "scratch-raw-provider",
            Self::ScratchFormat => "scratch-format",
            Self::ScratchMount => "scratch-mount",
            Self::ScratchQuota => "scratch-quota",
            Self::ScratchPrivate => "scratch-private",
            Self::ScratchSeal => "scratch-seal",
            Self::ScratchReady => "scratch-ready",
            Self::FixtureDiscover => "fixture-discover",
            Self::FixtureHost => "fixture-host",
            Self::FixtureState => "fixture-state",
            Self::FixtureWindowsRoot => "fixture-windows-root",
            Self::FixtureProgramFiles => "fixture-program-files",
            Self::FixtureVswhere => "fixture-vswhere",
            Self::FixtureVswhereRun => "fixture-vswhere-run",
            Self::FixtureVsInstall => "fixture-vs-install",
            Self::FixturePathShape => "fixture-path-shape",
            Self::FixtureVcMetadata => "fixture-vc-metadata",
            Self::FixtureVcVersion => "fixture-vc-version",
            Self::FixtureVcBin => "fixture-vc-bin",
            Self::FixtureLinker => "fixture-linker",
            Self::FixtureVcDlls => "fixture-vc-dlls",
            Self::FixtureSdkRoot => "fixture-sdk-root",
            Self::FixtureSdkLibraries => "fixture-sdk-libraries",
            Self::FixtureSdkSelect => "fixture-sdk-select",
            Self::FixtureKernel32 => "fixture-kernel32",
            Self::FixtureRustupRoot => "fixture-rustup-root",
            Self::FixtureRustSysroot => "fixture-rust-sysroot",
            Self::FixtureRustBin => "fixture-rust-bin",
            Self::FixtureRustc => "fixture-rustc",
            Self::FixtureRustDlls => "fixture-rust-dlls",
            Self::FixtureRustVersion => "fixture-rust-version",
            Self::FixtureTargetLibdir => "fixture-target-libdir",
            Self::FixtureTargetIdentity => "fixture-target-identity",
            Self::FixtureCore => "fixture-core",
            Self::FixtureBuiltins => "fixture-builtins",
            Self::FixturePinsVerify => "fixture-pins-verify",
            Self::FixturePinsClose => "fixture-pins-close",
            Self::FixturePinPath => "fixture-pin-path",
            Self::FixturePinCanonical => "fixture-pin-canonical",
            Self::FixturePinOpen => "fixture-pin-open",
            Self::FixturePinIdentity => "fixture-pin-identity",
            Self::FixturePinFingerprint => "fixture-pin-fingerprint",
            Self::FixturePinRead => "fixture-pin-read",
            Self::FixtureBuild => "fixture-build",
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
    pub stdout_bytes: Option<u32>,
    pub stderr_bytes: Option<u32>,
    pub exact_prefix: Option<bool>,
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
struct ClosedHeader<'a>(&'a AuthoredFailure);
impl fmt::Display for ClosedHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fixed native operation failed stage={}",
            self.0.stage.label()
        )?;
        for (name, value) in [
            ("native_error", self.0.numbers.native_error),
            ("result", self.0.numbers.result),
            ("count", self.0.numbers.count),
            ("bytes", self.0.numbers.bytes),
            ("properties", self.0.numbers.properties),
            ("stdout_bytes", self.0.numbers.stdout_bytes),
            ("stderr_bytes", self.0.numbers.stderr_bytes),
        ] {
            if let Some(value) = value {
                write!(f, " {name}=0x{value:08X}")?;
            }
        }
        if let Some(exact) = self.0.numbers.exact_prefix {
            write!(f, " exact_prefix={}", if exact { "True" } else { "False" })?;
        }
        for (name, value) in [
            ("raw_dr6", self.0.numbers.dr6),
            ("raw_dr7", self.0.numbers.dr7),
        ] {
            if let Some(value) = value {
                write!(f, " {name}=0x{value:016X}")?;
            }
        }
        Ok(())
    }
}
impl fmt::Display for AuthoredFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Preserve nested authored stages in ordinary CLI formatting. The same
        // closed visitor bounds depth and bytes and never formats a raw cause.
        f.write_str(&project(Some(self), &self.original))
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
/// Retain an authored phase and typed numeric API cause without formatting its raw text.
pub fn operation(error: anyhow::Error, stage: Stage) -> anyhow::Error {
    let native_error = error
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::raw_os_error)
        .map(|code| code as u32);
    #[cfg(windows)]
    let result = error
        .downcast_ref::<windows::core::Error>()
        .map(|error| error.code().0 as u32);
    #[cfg(not(windows))]
    let result = None;
    annotate(
        error,
        stage,
        Numbers {
            native_error,
            result,
            ..Default::default()
        },
    )
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
    project(None, error)
}
fn project(prefix: Option<&AuthoredFailure>, error: &anyhow::Error) -> String {
    fn visit(error: &anyhow::Error, depth: usize, lines: &mut Vec<String>) {
        if depth >= 16 || lines.len() >= 16 {
            return;
        }
        if let Some(value) = error.downcast_ref::<AuthoredFailure>() {
            lines.push(ClosedHeader(value).to_string());
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
    if let Some(value) = prefix {
        lines.push(ClosedHeader(value).to_string());
    }
    visit(error, usize::from(prefix.is_some()), &mut lines);
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
    let inner = operation(
        std::io::Error::from_raw_os_error(5).into(),
        Stage::ScratchCreate,
    );
    let nested = at(inner, Stage::ScratchPrepare);
    let displayed = nested.to_string();
    anyhow::ensure!(
        displayed.contains("stage=scratch-prepare")
            && displayed.contains("stage=scratch-create")
            && displayed.contains("native_error=0x00000005")
            && displayed.len() <= 4096,
        "CLI Display discarded nested closed native operation stages"
    );
    let typed = annotate(
        anyhow::anyhow!("private fixture path and compiler output"),
        Stage::DebugCreate,
        Numbers {
            native_error: Some(5),
            ..Default::default()
        },
    );
    let sanitized = crate::windows_security::policy::registry_comparison::wire::sanitize(typed);
    let projected =
        crate::windows_security::policy::registry_comparison::wire::safe_report(&sanitized);
    anyhow::ensure!(
        projected.contains("stage=debug-create")
            && projected.contains("native_error=0x00000005")
            && !projected.contains("private fixture")
            && !projected.contains("compiler output"),
        "closed native stage was discarded by registry failure projection"
    );
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
    for exact in [false, true] {
        let error = annotate(
            anyhow::anyhow!("private child output must never be formatted"),
            Stage::DebugTransport,
            Numbers {
                stdout_bytes: Some(if exact { 25 } else { 0 }),
                stderr_bytes: Some(0),
                exact_prefix: Some(exact),
                ..Default::default()
            },
        );
        let nested = at(error, Stage::DebugDispatchTarget);
        let report = summary(&nested);
        anyhow::ensure!(
            report.contains("stage=debug-dispatch-target")
                && report.contains("stage=debug-transport")
                && report.contains(if exact {
                    "stdout_bytes=0x00000019"
                } else {
                    "stdout_bytes=0x00000000"
                })
                && report.contains("stderr_bytes=0x00000000")
                && report.contains(if exact {
                    "exact_prefix=True"
                } else {
                    "exact_prefix=False"
                })
                && !report.contains("private child output"),
            "closed pre-call transport diagnostic differs"
        );
    }
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
