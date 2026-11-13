//! Shared original/readable/restored registry observations and transactional comparison.
use super::child_acl_equal;
use crate::windows_security::activation::{Failures, dispatch::QualifiedFailure};
use anyhow::{Result, ensure};

pub const DENIED: i32 = 0xc0000022u32 as i32;
pub const ACTIVATION_DENIED: &str = "WINDOWS_CHILD_ACTIVATION created=False win32_error=0x00000005 cause_claimed=False child_equivalence_claimed=False";
fn combine(first: Option<anyhow::Error>, later: Option<anyhow::Error>) -> Option<anyhow::Error> {
    match (first, later) {
        (None, value) | (value, None) => value,
        (Some(first), Some(later)) => Some(
            Failures {
                errors: vec![first, later],
            }
            .into(),
        ),
    }
}
fn unqualify(error: anyhow::Error) -> (bool, anyhow::Error) {
    match error.downcast::<QualifiedFailure>() {
        Ok(error) => (true, error.into_original()),
        Err(error) => (false, error),
    }
}
pub struct Trial<'a> {
    pub restore: Box<dyn FnMut() -> Result<()> + 'a>,
    pub defer: Box<dyn FnMut() -> Result<()> + 'a>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    Original,
    Readable,
    Restored,
}
impl Condition {
    pub fn from_index(value: usize) -> Result<Self> {
        match value {
            0 => Ok(Self::Original),
            1 => Ok(Self::Readable),
            2 => Ok(Self::Restored),
            _ => anyhow::bail!("unsupported registry startup condition"),
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Readable => "readable",
            Self::Restored => "restored",
        }
    }
    pub fn expected(self) -> i32 {
        if self == Self::Readable { 0 } else { DENIED }
    }
}
pub struct StartupObservation {
    condition: Condition,
    policy: Option<Vec<u8>>,
    read_qualified: bool,
    staged: bool,
    recorded: bool,
    exit: u32,
}
impl StartupObservation {
    pub fn condition(&self) -> Condition {
        self.condition
    }
    pub fn new(condition: Condition) -> Self {
        Self {
            condition,
            policy: None,
            read_qualified: false,
            staged: false,
            recorded: false,
            exit: 0,
        }
    }
    pub fn require_fresh(&self) -> Result<()> {
        ensure!(
            self.policy.is_none() && !self.read_qualified && !self.staged && !self.recorded,
            "registry observation is not fresh"
        );
        Ok(())
    }
    pub fn prepare(&mut self, primary: &[u8], duplicate: &[u8]) -> Result<()> {
        self.require_fresh()?;
        ensure!(
            child_acl_equal(primary, duplicate)?,
            "registry primary/duplicate default DACL differs"
        );
        self.policy = Some(primary.into());
        Ok(())
    }
    pub fn require_policy(&self, primary: &[u8], duplicate: &[u8]) -> Result<()> {
        ensure!(
            !self.staged && !self.recorded,
            "registry observation policy is already staged"
        );
        let policy = self
            .policy
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("registry observation policy missing"))?;
        ensure!(
            child_acl_equal(policy, primary)? && child_acl_equal(policy, duplicate)?,
            "registry startup default DACL changed"
        );
        Ok(())
    }
    pub fn read_control(&mut self, status: i32) -> Result<()> {
        ensure!(
            self.policy.is_some() && !self.read_qualified && !self.staged && !self.recorded,
            "registry read control order differs"
        );
        ensure!(
            if self.condition == Condition::Readable {
                status >= 0
            } else {
                status == DENIED
            },
            "registry read control condition differs"
        );
        self.read_qualified = true;
        Ok(())
    }
    pub fn stage(&mut self, exit: u32, text: Option<&str>, errors: Option<&str>) -> Result<()> {
        ensure!(
            self.policy.is_some()
                && self.read_qualified
                && !self.staged
                && !self.recorded
                && text == Some("")
                && errors == Some(""),
            "registry startup output or stage order differs"
        );
        self.exit = exit;
        self.staged = true;
        Ok(())
    }
    pub fn complete(&mut self) -> Result<()> {
        ensure!(
            self.policy.is_some() && self.read_qualified && self.staged && !self.recorded,
            "registry observation completion order differs"
        );
        self.recorded = true;
        Ok(())
    }
    pub fn equal_policy(&self, other: &Self) -> Result<()> {
        ensure!(
            self.recorded
                && other.recorded
                && child_acl_equal(
                    self.policy.as_deref().unwrap(),
                    other.policy.as_deref().unwrap()
                )?,
            "registry comparison changed default DACL"
        );
        Ok(())
    }
    pub fn recorded(&self) -> bool {
        self.recorded
    }
    pub fn exit(&self) -> u32 {
        self.exit
    }
    pub fn metadata(&self) -> Result<String> {
        ensure!(
            self.recorded,
            "unrecorded registry observation cannot be reported"
        );
        Ok(format!(
            "WINDOWS_REGISTRY_STARTUP condition={} key_readable={} raw_process_exit=0x{:08X} pass_code_completed={} stdout_empty=True stderr_empty=True default_dacl_unchanged=True process_job_handle_cleanup=True cause_claimed=False target_admitted=False production_grant=False",
            self.condition.label(),
            boolean(self.condition == Condition::Readable),
            self.exit,
            boolean(self.exit == 0)
        ))
    }
}
impl Drop for StartupObservation {
    fn drop(&mut self) {
        if let Some(policy) = self.policy.as_mut() {
            policy.fill(0);
        }
    }
}
fn boolean(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}
pub fn require_role(
    observation: &StartupObservation,
    expected: Option<i32>,
    trusted_preflight: bool,
    conflict_flags: u32,
) -> Result<()> {
    ensure!(
        trusted_preflight
            && conflict_flags == 0
            && expected == Some(observation.condition.expected()),
        "registry observation requires the fixed undebugged pass-code role"
    );
    observation.require_fresh()
}
pub struct BoundedEmitter<'a> {
    bytes: usize,
    emit: &'a mut dyn FnMut(&str) -> Result<()>,
}
impl<'a> BoundedEmitter<'a> {
    pub fn new(emit: &'a mut dyn FnMut(&str) -> Result<()>) -> Self {
        Self { bytes: 0, emit }
    }
    pub fn emit(&mut self, line: &str) -> Result<()> {
        let next = self
            .bytes
            .checked_add(line.len())
            .ok_or_else(|| anyhow::anyhow!("registry report overflow"))?;
        ensure!(next <= 4096, "registry report exceeds bound");
        self.bytes = next;
        (self.emit)(line)
    }
}
fn report(
    value: &StartupObservation,
    first: Option<&StartupObservation>,
    diagnostic: &mut Option<anyhow::Error>,
    emitter: &mut BoundedEmitter<'_>,
) -> Result<()> {
    ensure!(
        value.recorded,
        "registry observation did not finish owned cleanup"
    );
    let mismatch = match value.condition {
        Condition::Original => value.exit == 0,
        Condition::Readable => value.exit != 0,
        Condition::Restored => value.exit == 0 || value.exit != first.unwrap().exit,
    };
    if mismatch {
        *diagnostic = combine(
            diagnostic.take(),
            Some(anyhow::anyhow!(
                "fixed registry startup exit mismatch condition={} raw_process_exit=0x{:08X}",
                value.condition.label(),
                value.exit
            )),
        );
    }
    if let Some(first) = first {
        first.equal_policy(value)?;
    }
    emitter.emit(&value.metadata()?)
}
pub fn execute_startup<'a>(
    mut observe: impl FnMut(&mut StartupObservation) -> Result<()>,
    begin: impl FnOnce() -> Result<Trial<'a>>,
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<Option<anyhow::Error>> {
    let mut emitter = BoundedEmitter::new(&mut emit);
    let mut diagnostic = None;
    let mut original = StartupObservation::new(Condition::Original);
    let mut middle = StartupObservation::new(Condition::Readable);
    let mut restored = StartupObservation::new(Condition::Restored);
    let operation = (|| {
        observe(&mut original)?;
        report(&original, None, &mut diagnostic, &mut emitter)?;
        let mut lease = begin()?;
        let (clean, operation) = match observe(&mut middle) {
            Ok(()) => (
                true,
                report(&middle, Some(&original), &mut diagnostic, &mut emitter),
            ),
            Err(error) => {
                let (qualified, error) = unqualify(error);
                (qualified, Err(error))
            }
        };
        let cleanup = if clean {
            (lease.restore)()
        } else {
            (lease.defer)()
        };
        if let Some(error) = combine(operation.err(), cleanup.err()) {
            return Err(error);
        }
        observe(&mut restored)?;
        report(&restored, Some(&original), &mut diagnostic, &mut emitter)?;
        emitter.emit(&format!("WINDOWS_REGISTRY_STARTUP_COMPARISON baseline_failed={} readable_passed={} restored_exit_equal={} baseline_policy_equal=True key_restored=True conditional_sufficiency={} cache_reset_claimed=False cause_claimed=False target_admitted=False production_grant=False",boolean(original.exit!=0),boolean(middle.exit==0),boolean(restored.exit==original.exit),boolean(original.exit!=0&&middle.exit==0&&restored.exit==original.exit)))
    })();
    match operation {
        Ok(()) => Ok(diagnostic),
        Err(error) => Err(combine(diagnostic, Some(unqualify(error).1)).unwrap()),
    }
}

#[derive(Default)]
pub struct StartupComparison {
    started: bool,
    retained: Option<anyhow::Error>,
}
impl StartupComparison {
    pub fn run<'a>(
        &mut self,
        observe: impl FnMut(&mut StartupObservation) -> Result<()>,
        begin: impl FnOnce() -> Result<Trial<'a>>,
        emit: impl FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            !self.started && self.retained.is_none(),
            "registry startup comparison was already started"
        );
        self.started = true;
        self.retained = execute_startup(observe, begin, emit)?;
        Ok(())
    }
    pub fn preserve_failure(&mut self, later: Option<anyhow::Error>) -> Option<anyhow::Error> {
        combine(self.retained.take(), later)
    }
}

pub fn execute_authority<'a>(
    observe: impl FnOnce() -> Result<()>,
    begin: impl FnOnce() -> Result<Trial<'a>>,
    before: impl FnOnce() -> Result<()>,
    after: impl FnOnce() -> Result<()>,
    emit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    before()?;
    let mut lease = begin()?;
    let (clean, operation) = match observe() {
        Ok(()) => (true, Ok(())),
        Err(error) => {
            let (qualified, error) = unqualify(error);
            (qualified, Err(error))
        }
    };
    let cleanup = if clean {
        (lease.restore)()
    } else {
        (lease.defer)()
    };
    if let Some(error) = combine(operation.err(), cleanup.err()) {
        return Err(error);
    }
    after()?;
    emit()
}
pub struct CausalObservation {
    pub activation: String,
    pub exit: u32,
}
fn baseline(value: &CausalObservation) -> Result<()> {
    ensure!(
        value.activation == ACTIVATION_DENIED && value.exit == DENIED as u32,
        "registry original/restored denial differs"
    );
    Ok(())
}
pub fn execute_causal<'a>(
    mut observe: impl FnMut(i32) -> Result<CausalObservation>,
    begin: impl FnOnce() -> Result<Trial<'a>>,
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<u32> {
    let original = observe(DENIED)?;
    baseline(&original)?;
    let mut lease = begin()?;
    let modified = observe(0);
    let cleanup = if modified.is_ok() {
        (lease.restore)()
    } else {
        (lease.defer)()
    };
    let modified = match (modified, cleanup) {
        (Ok(value), Ok(())) => value,
        (Err(primary), cleanup) => return Err(combine(Some(primary), cleanup.err()).unwrap()),
        (_, Err(error)) => return Err(error),
    };
    let restored = observe(DENIED)?;
    baseline(&restored)?;
    emit(&format!(
        "WINDOWS_REGISTRY_DIFFERENTIAL original_python_exit=0x{:08X} modified_python_exit=0x{:08X} restored_python_exit=0x{:08X} activation_changed={} python_exit_changed={} restored_baseline=True target_admitted=False cause_claimed=False production_grant=False",
        original.exit,
        modified.exit,
        restored.exit,
        boolean(original.activation != modified.activation),
        boolean(original.exit != modified.exit)
    ))?;
    Ok(original.exit)
}
pub fn after_restoration(
    comparison: impl FnOnce() -> Result<u32>,
    evidence: impl FnOnce() -> Result<()>,
) -> Result<u32> {
    let value = comparison()?;
    evidence()?;
    Ok(value)
}

#[derive(Default)]
pub struct SupportedState {
    active: bool,
    moniker: String,
    runs: usize,
    qualified: bool,
    uncertain: bool,
    closed: bool,
}
impl SupportedState {
    pub fn require_available(&self) -> Result<()> {
        ensure!(!self.active, "supported registry trial already active");
        Ok(())
    }
    pub fn activate(&mut self, moniker: &str) -> Result<()> {
        self.require_available()?;
        *self = Self {
            active: true,
            moniker: moniker.into(),
            ..Self::default()
        };
        Ok(())
    }
    pub fn enter_run(&mut self, moniker: Option<&str>) -> Result<bool> {
        if !self.active {
            return Ok(false);
        }
        ensure!(
            moniker == Some(self.moniker.as_str())
                && !self.closed
                && !self.uncertain
                && self.runs == 0,
            "supported registry run is nested, foreign or uncertain"
        );
        self.runs = 1;
        Ok(true)
    }
    pub fn end_run(&mut self, cleanup_qualified: bool) -> Result<()> {
        ensure!(
            self.active && self.runs == 1,
            "supported registry run completion differs"
        );
        self.runs = 0;
        self.uncertain |= !cleanup_qualified;
        Ok(())
    }
    pub fn qualify(&mut self) -> Result<()> {
        ensure!(
            self.active && !self.closed && !self.uncertain && self.runs == 0,
            "supported registry qualification incomplete"
        );
        self.qualified = true;
        Ok(())
    }
    pub fn require_readable(&self) -> Result<i32> {
        ensure!(
            self.active && self.qualified && !self.closed && !self.uncertain,
            "supported registry read is unqualified"
        );
        Ok(0)
    }
    pub fn ordinary_condition(&self) -> Result<Option<i32>> {
        if self.active {
            self.require_readable().map(Some)
        } else {
            Ok(None)
        }
    }
    pub fn scratch_qualified(&self, moniker: &str) -> bool {
        self.moniker == moniker && self.require_readable().is_ok()
    }
    pub fn finish(
        &mut self,
        restore: impl FnOnce() -> Result<()>,
        defer: impl FnOnce() -> Result<()>,
        compare: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        ensure!(self.active, "supported registry owner is not active");
        self.closed = true;
        let result = finish_supported(self.runs == 0 && !self.uncertain, restore, defer, compare);
        self.active = false;
        result
    }
}
pub fn finish_supported(
    safe: bool,
    restore: impl FnOnce() -> Result<()>,
    defer: impl FnOnce() -> Result<()>,
    compare: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if !safe {
        return Err(combine(
            Some(anyhow::anyhow!(
                "supported registry process cleanup remains uncertain"
            )),
            defer().err(),
        )
        .unwrap());
    }
    restore()?;
    compare()
}

#[path = "registry_comparison_checks.rs"]
mod checks;
pub use checks::{
    check_authority_validation, check_causal_validation, check_startup_validation,
    check_supported_validation,
};
#[path = "registry_causal.rs"]
pub mod causal;
#[path = "registry_completion.rs"]
pub mod completion;
#[path = "registry_surface.rs"]
pub mod surface;
#[path = "registry_wire.rs"]
pub mod wire;
