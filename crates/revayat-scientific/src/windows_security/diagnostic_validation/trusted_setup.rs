//! Closed preparation-launch contracts from TrustedSetup.cs; no process is launched here.
use crate::windows_security::{
    activation::self_result::SelfRole,
    scratch::{OperationResult, SharedError},
};
use anyhow::{Result, ensure};
use std::{cell::RefCell, io::Write, path::Path, sync::Arc};
#[path = "trusted_setup_checks.rs"]
mod checks;
pub use checks::check_trusted_setup_validation;

pub const SELF_CREATION_FLAGS: u32 = 0x0008040c;
pub const TOOLS: [&str; 17] = [
    "cl.exe",
    "link.exe",
    "vswhere.exe",
    "dumpbin.exe",
    "rc.exe",
    "git.exe",
    "icacls.exe",
    "fsutil.exe",
    "csc.exe",
    "pwsh.exe",
    "sxstrace.exe",
    "startup-self-activation.exe",
    "startup-manual-activation.exe",
    "startup-explicit-id2.exe",
    "startup-dll-resource.exe",
    "startup-module.exe",
    "python.exe",
];
pub const STAGES: [&str; 14] = [
    "prepare",
    "create-before",
    "create-after",
    "assign-before",
    "assign-after",
    "resume-before",
    "resume-after",
    "wait-first",
    "wait-complete",
    "reap-before",
    "reap-after",
    "capture-after",
    "cleanup-before",
    "cleanup-after",
];
pub fn stage(tool: &str, stage: &str) -> Result<String> {
    ensure!(
        TOOLS.contains(&tool) && STAGES.contains(&stage),
        "unsupported trusted setup stage label"
    );
    Ok(format!("WINDOWS_SETUP_STAGE tool={tool} stage={stage}"))
}
pub fn emit_stage(tool: &str, phase: &str, writer: &mut impl Write) -> OperationResult<()> {
    let writer = RefCell::new(writer);
    emit_stage_with(
        tool,
        phase,
        |line| {
            writeln!(writer.borrow_mut(), "{line}").map_err(|error| Arc::new(error) as SharedError)
        },
        || {
            writer
                .borrow_mut()
                .flush()
                .map_err(|error| Arc::new(error) as SharedError)
        },
    )
}
pub fn emit_stage_with(
    tool: &str,
    phase: &str,
    mut write_line: impl FnMut(&str) -> OperationResult<()>,
    flush: impl FnOnce() -> OperationResult<()>,
) -> OperationResult<()> {
    let line =
        stage(tool, phase).map_err(|error| SharedError::from(error.into_boxed_dyn_error()))?;
    write_line(&line)?;
    flush()
}
fn require_launch(
    executable: &Path,
    arguments: Option<&[String]>,
    cwd: &Path,
    name: &str,
    folder: &str,
) -> Result<()> {
    ensure!(
        executable.is_absolute()
            && cwd.is_absolute()
            && arguments.is_some_and(<[String]>::is_empty)
            && executable.file_name().and_then(|v| v.to_str()) == Some(name)
            && executable.parent() == Some(cwd)
            && cwd.file_name().and_then(|v| v.to_str()) == Some(folder),
        "unsupported fixed host activation launch"
    );
    Ok(())
}
pub fn require_self_launch(
    executable: &Path,
    arguments: Option<&[String]>,
    cwd: &Path,
    role: i32,
) -> Result<()> {
    require_launch(
        executable,
        arguments,
        cwd,
        &SelfRole::try_from(role)?.image_name(),
        "python",
    )
}
pub fn require_dll_launch(
    executable: &Path,
    arguments: Option<&[String]>,
    cwd: &Path,
) -> Result<()> {
    require_launch(
        executable,
        arguments,
        cwd,
        "startup-dll-resource.exe",
        "python",
    )
}
pub fn require_module_dispatch_launch(
    executable: &Path,
    arguments: Option<&[String]>,
    cwd: &Path,
) -> Result<()> {
    require_launch(
        executable,
        arguments,
        cwd,
        "startup-module.exe",
        "module-id2",
    )
}
/// The public preparation route cannot promote a fixture image to a tool. The
/// internal DLL route must arrive before self-activation transport is enabled.
pub fn require_route(
    executable: &Path,
    arguments: Option<&[String]>,
    cwd: &Path,
    self_activation: bool,
    role: i32,
    dll_request: bool,
) -> Result<()> {
    let _ = SelfRole::try_from(role)?;
    if dll_request {
        ensure!(
            !self_activation && role == 0,
            "unsupported fixed DLL request launch role"
        );
        return require_dll_launch(executable, arguments, cwd);
    }
    if self_activation {
        return require_self_launch(executable, arguments, cwd, role);
    }
    ensure!(
        role == 0
            && executable.is_absolute()
            && cwd.is_absolute()
            && executable
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| [
                    "cl.exe",
                    "link.exe",
                    "vswhere.exe",
                    "dumpbin.exe",
                    "rc.exe",
                    "git.exe",
                    "icacls.exe",
                    "fsutil.exe",
                    "csc.exe",
                    "pwsh.exe"
                ]
                .contains(&v)),
        "unsupported trusted CI preparation tool"
    );
    Ok(())
}
/// Finally-block semantics: all actions run; successful cleanup preserves the
/// caller's primary error, while cleanup failures retain primary-first identity.
pub fn finish_cleanup<'a>(
    primary: Option<SharedError>,
    actions: Vec<Box<dyn FnMut() -> OperationResult<()> + 'a>>,
) -> OperationResult<()> {
    super::startup_image::release_image(primary, actions)
}
