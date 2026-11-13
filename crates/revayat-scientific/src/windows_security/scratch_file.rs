//! Exact create-only scratch positive/negative comparison and bound cleanup operations.
use super::{FileIdentity, OperationResult, attempt, finish, need, valid_handle};
use anyhow::{Result, ensure};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileCreateRequest<'a> {
    pub path: &'a str,
    pub access: u32,
    pub share: u32,
    pub security: usize,
    pub disposition: u32,
    pub flags: u32,
    pub template: usize,
}
#[derive(Debug, Default)]
pub struct FileObservation {
    pub handle: usize,
    pub pin: usize,
    pub error: u32,
    pub identity: FileIdentity,
}
pub fn file_create_request(
    path: &str,
    value: &mut FileObservation,
    mut create: impl FnMut(FileCreateRequest<'_>) -> usize,
    last_error: impl FnOnce() -> u32,
) {
    value.handle = create(FileCreateRequest {
        path,
        access: 0x40000000,
        share: 3,
        security: 0,
        disposition: 1,
        flags: 0x80,
        template: 0,
    });
    value.error = if valid_handle(value.handle) {
        0
    } else {
        last_error()
    };
}
pub fn require_file_absent(attributes: u32, error: u32) -> Result<()> {
    ensure!(
        attributes == u32::MAX && error == 2,
        "fixed scratch file absence is unqualified"
    );
    Ok(())
}
pub fn require_supported_creation(errors: &[u32]) -> Result<()> {
    ensure!(
        errors == [0, 0],
        "supported scratch file creation was not qualified"
    );
    Ok(())
}
pub struct FileCalls<'a> {
    pub create: &'a mut dyn FnMut(&mut FileObservation) -> OperationResult<()>,
    pub enter: &'a mut dyn FnMut() -> OperationResult<()>,
    pub check: &'a mut dyn FnMut() -> OperationResult<()>,
    // Native restoration must abort the process on failure and never return in an LPAC identity.
    pub leave: &'a mut dyn FnMut(),
    pub bind: &'a mut dyn FnMut(&mut FileObservation) -> OperationResult<()>,
    pub close: &'a mut dyn FnMut(usize) -> OperationResult<()>,
    pub remove: &'a mut dyn FnMut(&mut FileObservation) -> OperationResult<()>,
    pub absent: &'a mut dyn FnMut() -> OperationResult<()>,
    pub release: &'a mut dyn FnMut(&mut FileObservation) -> OperationResult<()>,
}
pub fn file_creation(host: bool, calls: FileCalls<'_>) -> OperationResult<u32> {
    let mut value = FileObservation::default();
    let mut entered = false;
    let result = (|| {
        (calls.absent)()?;
        (calls.enter)()?;
        entered = true;
        (calls.check)()?;
        (calls.create)(&mut value)?;
        (calls.check)()?;
        need(if valid_handle(value.handle) {
            value.error == 0
        } else {
            value.handle == usize::MAX && value.error == 5
        })?;
        need(!host || valid_handle(value.handle))
    })();
    let mut errors = Vec::new();
    if entered {
        (calls.leave)();
    }
    let (mut bound, mut closed, mut removed) = (false, false, false);
    if valid_handle(value.handle) {
        attempt(&mut errors, || {
            (calls.bind)(&mut value)?;
            bound = true;
            Ok(())
        });
        attempt(&mut errors, || {
            (calls.close)(value.handle)?;
            closed = true;
            Ok(())
        });
        if bound && closed {
            attempt(&mut errors, || {
                (calls.remove)(&mut value)?;
                removed = true;
                Ok(())
            });
        }
    }
    attempt(&mut errors, || (calls.release)(&mut value));
    if removed || !valid_handle(value.handle) && result.is_ok() {
        attempt(&mut errors, calls.absent);
    }
    finish(result.map(|()| value.error), errors)
}
pub fn creation_frames(phase: &str, errors: &[u32]) -> Result<[String; 2]> {
    ensure!(
        matches!(phase, "supported" | "baseline" | "modified" | "restored")
            && errors.len() == 2
            && errors[0] == 0
            && matches!(errors[1], 0 | 5),
        "scratch file creation result differs"
    );
    Ok(std::array::from_fn(|role| {
        format!(
            "WINDOWS_SCRATCH_FILE phase={phase} role={} opened={} win32_error=0x{:08X} cleanup_qualified=True contents_written=False cause_claimed=False admission=False",
            if role == 0 { "host" } else { "lpac" },
            super::truth(errors[role] == 0),
            errors[role]
        )
    }))
}
pub fn file_policy_result(policy: &[i32], errors: &[u32]) -> Result<Vec<i32>> {
    creation_frames("baseline", errors)?;
    ensure!(
        policy.len() == 2 + super::volume::MASKS.len() * 5,
        "scratch file policy shape differs"
    );
    let mut result = policy.to_vec();
    result.extend(errors.iter().map(|v| *v as i32));
    Ok(result)
}
pub fn file_policy_frames(phase: &str, result: &[i32]) -> Result<Vec<String>> {
    let count = 2 + super::volume::MASKS.len() * 5;
    ensure!(
        result.len() == count + 2,
        "scratch file policy frame shape differs"
    );
    let mut frames = super::volume::frames(phase, &result[..count])?;
    frames.extend(creation_frames(
        phase,
        &[result[count] as u32, result[count + 1] as u32],
    )?);
    Ok(frames)
}
pub fn reject_file_policy(result: &[i32]) -> Result<bool> {
    ensure!(
        result.len() == 4 + super::volume::MASKS.len() * 5,
        "scratch file policy rejection shape differs"
    );
    Ok(super::volume::MASKS
        .iter()
        .enumerate()
        .any(|(index, mask)| mask & 0xc0003 != 0 && result[2 + index] == 0))
}
