//! Same-held-file binding and bounded private static-inspection failure reports.
//! Parsing an identity never attests a LOAD event or authorizes a supported profile.
use crate::windows_security::{
    image::{KernelImage, StaticSlice, StaticView},
    scratch::{self, OperationResult, SharedError},
};
use anyhow::{Result, ensure};
use std::{
    error::Error,
    fmt,
    io::{Read, Seek, SeekFrom},
    sync::{Arc, Mutex},
};
#[path = "static_kernel_checks.rs"]
mod checks;
pub use checks::check_static_kernel_inspection_validation;

pub struct ActivationFailure {
    pub phase: &'static str,
    pub original: SharedError,
    pub reporting_failures: Mutex<Vec<SharedError>>,
}
impl ActivationFailure {
    pub fn new(phase: &'static str, original: SharedError) -> Result<Self> {
        ensure!(
            [
                "input-path",
                "held-open",
                "held-read",
                "image",
                "identity",
                "slice",
                "fixed-export",
                "tool-discovery",
                "tool",
                "post-path",
                "posthash",
                "qualifier",
                "observation-profile",
                "module-callback-profile",
                "evidence-output",
                "held-close"
            ]
            .contains(&phase),
            "unsupported static inspection phase"
        );
        Ok(Self {
            phase,
            original,
            reporting_failures: Mutex::new(Vec::new()),
        })
    }
}
impl fmt::Display for ActivationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fixed activation-worker static inspection failed; details withheld")
    }
}
impl fmt::Debug for ActivationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Error for ActivationFailure {}
#[derive(Debug)]
pub struct ContractFailure;
impl fmt::Display for ContractFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fixed static profile contract failed")
    }
}
impl Error for ContractFailure {}
struct RetainedContractFailure {
    original: SharedError,
}
impl fmt::Display for RetainedContractFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fixed static inspection contract failed; details withheld")
    }
}
impl fmt::Debug for RetainedContractFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Error for RetainedContractFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}
fn retained(error: anyhow::Error) -> SharedError {
    match error.downcast::<std::io::Error>() {
        Ok(error) => Arc::new(error),
        Err(error) => Arc::new(RetainedContractFailure {
            original: SharedError::from(error.into_boxed_dyn_error()),
        }),
    }
}

fn find<'a>(mut error: &'a (dyn Error + 'static)) -> Option<&'a ActivationFailure> {
    for wrappers in 0..=4 {
        if let Some(carrier) = error.downcast_ref::<ActivationFailure>() {
            return Some(carrier);
        }
        if wrappers == 4 {
            return None;
        }
        error = error.source()?;
    }
    None
}
pub fn retain_activation_reporting_failure(
    error: &(dyn Error + 'static),
    reporting: Option<SharedError>,
) -> Result<()> {
    let carrier = find(error).ok_or_else(|| {
        anyhow::anyhow!("fixed activation reporting failure has no owning operation")
    })?;
    let reporting = reporting.ok_or_else(|| {
        anyhow::anyhow!("fixed activation reporting failure has no owning operation")
    })?;
    carrier
        .reporting_failures
        .lock()
        .map_err(|_| anyhow::anyhow!("fixed reporting ownership lock failed"))?
        .push(reporting);
    Ok(())
}
pub fn activation_failure_report(error: &(dyn Error + 'static)) -> Option<String> {
    let carrier = find(error)?;
    let mut output = format!(
        "WINDOWS_STATIC_ACTIVATION failure_phase={}\n",
        carrier.phase
    );
    let mut pending = vec![(carrier.original.as_ref(), 0)];
    let mut visited = 0;
    let mut causes = 0;
    let mut truncated = false;
    while !pending.is_empty() && visited < 32 && causes < 16 {
        let (error, depth) = pending.pop()?;
        visited += 1;
        if let Some(group) = error.downcast_ref::<scratch::Failures>()
            && !group.errors.is_empty()
        {
            if depth >= 4 {
                truncated = true;
                continue;
            }
            let count = group.errors.len().min(32 - visited - pending.len());
            if count != group.errors.len() {
                truncated = true;
            }
            for error in group.errors[..count].iter().rev() {
                pending.push((error.as_ref(), depth + 1));
            }
            continue;
        }
        let io = error.downcast_ref::<std::io::Error>();
        let category = match io {
            Some(error) if error.raw_os_error().is_some() => "os_error",
            Some(error) if error.kind() == std::io::ErrorKind::TimedOut => "timeout",
            Some(error) if error.kind() == std::io::ErrorKind::PermissionDenied => "access_error",
            Some(_) => "io_error",
            None if error.is::<ContractFailure>() || error.is::<RetainedContractFailure>() => {
                "contract_error"
            }
            _ => "unknown_failure",
        };
        output.push_str(&format!(
            "WINDOWS_STATIC_ACTIVATION cause_index={causes} category={category}"
        ));
        if let Some(code) = io.and_then(std::io::Error::raw_os_error) {
            output.push_str(&format!(" winerror={}", code as u32));
        }
        output.push('\n');
        causes += 1;
    }
    output.push_str(&format!(
        "WINDOWS_STATIC_ACTIVATION failure_causes={causes} truncated={}",
        super::boolean(truncated || !pending.is_empty())
    ));
    Some(output)
}
pub fn require_same(expected: Option<&str>, actual: Option<&str>) -> Result<()> {
    ensure!(
        expected.is_some_and(|value| !value.is_empty()) && expected == actual,
        "static same-run file identity is unavailable or changed"
    );
    Ok(())
}
pub fn read_held(stream: &mut (impl Read + Seek)) -> Result<Vec<u8>> {
    let length = stream.seek(SeekFrom::End(0))?;
    ensure!(
        (256..=16 * 1024 * 1024).contains(&length),
        "static held file exceeds fixed image bound"
    );
    stream.seek(SeekFrom::Start(0))?;
    let mut bytes = vec![0; length as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + 65536).min(bytes.len());
        let read = stream.read(&mut bytes[offset..end])?;
        ensure!(read != 0, "static held file read was truncated");
        offset += read;
    }
    ensure!(
        stream.read(&mut [0])? == 0 && stream.seek(SeekFrom::End(0))? == length,
        "static held file length changed"
    );
    Ok(bytes)
}
pub fn report_observation_failure(
    primary: SharedError,
    identity: &str,
    emit: impl FnOnce(&str) -> OperationResult<()>,
    activation: bool,
) -> OperationResult<()> {
    let prefix = if activation {
        "WINDOWS_STATIC_ACTIVATION"
    } else {
        "WINDOWS_STATIC_KERNEL"
    };
    if let Err(reporting) = emit(&format!("{prefix} profile_accepted=False {identity}")) {
        return Err(Arc::new(scratch::Failures {
            errors: vec![primary, reporting],
        }));
    }
    Ok(())
}
pub fn qualify_activation(
    qualify: impl FnOnce() -> OperationResult<()>,
    identity: &str,
    emit: impl FnOnce(&str) -> OperationResult<()>,
    bind: impl FnOnce() -> OperationResult<()>,
) -> OperationResult<()> {
    if let Err(primary) = qualify() {
        report_observation_failure(primary.clone(), identity, emit, true)?;
        return Err(primary);
    }
    bind()
}
#[derive(Default)]
pub struct SameRunBinding {
    kernel: Option<String>,
    activation: Option<String>,
}
impl SameRunBinding {
    pub fn bind_kernel(
        &mut self,
        image: &KernelImage<'_>,
        view: &crate::windows_security::image::StaticView,
    ) -> Result<()> {
        ensure!(
            self.kernel.is_none(),
            "static KernelBase inspection is already bound for this run"
        );
        image.require_observation_static(view)?;
        self.kernel = Some(image.kernelbase_identity()?);
        Ok(())
    }
    pub fn bind_load(&self, image: &KernelImage<'_>) -> Result<u32> {
        require_same(self.kernel.as_deref(), Some(&image.kernelbase_identity()?))?;
        image.require_observation_profile()
    }
    /// Original RunActivationWorker ordering inside an already-owned held file:
    /// read, identity, fixed export, tool, same-descriptor posthash, static view,
    /// exact callback profile, then bind. A successful tool callback cannot bind.
    /// The native owner supplies approved dumpbin execution and path checks,
    /// keeps the file held through evidence output, and handles close.
    pub fn inspect_activation_worker(
        &mut self,
        held: &mut (impl Read + Seek),
        inspect: impl FnOnce(StaticSlice) -> OperationResult<String>,
        post_path: impl FnOnce() -> OperationResult<()>,
        emit_refusal: impl FnOnce(&str) -> OperationResult<()>,
    ) -> OperationResult<StaticView> {
        let mut phase = "held-read";
        let result = (|| {
            let bytes = read_held(held).map_err(retained)?;
            let image = KernelImage::from_activation_worker(&bytes).map_err(retained)?;
            phase = "identity";
            let identity = image.kernel32_identity().map_err(retained)?;
            phase = "fixed-export";
            let slice = image.activation_worker_slice().map_err(retained)?;
            phase = "tool";
            let text = inspect(slice)?;
            if text.len() > 1048576 {
                return Err(retained(anyhow::anyhow!(
                    "static worker tool output exceeded 1 MiB"
                )));
            }
            phase = "post-path";
            post_path()?;
            phase = "posthash";
            let after = read_held(held).map_err(retained)?;
            let actual = KernelImage::from_activation_worker(&after)
                .map_err(retained)?
                .kernel32_identity()
                .map_err(retained)?;
            require_same(Some(&identity), Some(&actual)).map_err(retained)?;
            phase = "qualifier";
            let view = image.qualify_static_slice(&text, slice).map_err(retained)?;
            phase = "module-callback-profile";
            qualify_activation(
                || image.require_module_callback_profile().map_err(retained),
                &identity,
                emit_refusal,
                || {
                    self.activation = Some(identity.clone());
                    Ok(())
                },
            )?;
            Ok(view)
        })();
        result.map_err(|original| {
            Arc::new(ActivationFailure {
                phase,
                original,
                reporting_failures: Mutex::new(Vec::new()),
            }) as SharedError
        })
    }
    /// The debug-event owner must construct `image` from its actual LOAD file
    /// handle. This check compares same-run file identity; it does not attest an
    /// event or substitute cached static bytes for a real LOAD observation.
    pub fn bind_activation_load(&self, image: &KernelImage<'_>) -> Result<()> {
        require_same(
            self.activation.as_deref(),
            Some(&image.kernel32_identity()?),
        )
    }
}
