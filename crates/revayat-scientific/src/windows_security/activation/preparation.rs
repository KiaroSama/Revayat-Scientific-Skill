//! Matched pass-code preparation with measured token policy and explicit lease recovery.
use super::{csr::combine, sweep::Trial};
use crate::windows_security::policy::child_acl_equal;
use anyhow::{Result, ensure};
use std::sync::{Arc, Mutex};
#[path = "preparation_checks.rs"]
mod checks;
#[path = "preparation_transition_checks.rs"]
mod transitions;
pub use checks::check_validation;
pub const EMPTY_POLICY: [u8; 8] = [2, 0, 8, 0, 0, 0, 0, 0];
pub const CREATED: &str = "WINDOWS_STARTUP_ACTIVATION context=lpac resource_type=24 resource_id=1 created=True win32_error=0 activated=False child_equivalence_claimed=False cause_claimed=False";
pub const DENIED: &str = "WINDOWS_STARTUP_ACTIVATION context=lpac resource_type=24 resource_id=1 created=False win32_error=5 activated=False child_equivalence_claimed=False cause_claimed=False";
fn b(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    Baseline,
    ChildCreate,
    BaselineAgain,
}
impl Condition {
    pub fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::ChildCreate => "child-create",
            Self::BaselineAgain => "baseline-again",
        }
    }
}
impl TryFrom<u8> for Condition {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Baseline),
            1 => Ok(Self::ChildCreate),
            2 => Ok(Self::BaselineAgain),
            _ => anyhow::bail!("unsupported fixed Python preparation condition"),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Experiment {
    Token,
    Host,
    Image,
    ActivationBundle,
}
impl TryFrom<u8> for Experiment {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Token),
            1 => Ok(Self::Host),
            2 => Ok(Self::Image),
            3 => Ok(Self::ActivationBundle),
            _ => anyhow::bail!("unsupported fixed Python preparation experiment"),
        }
    }
}
#[derive(Clone)]
pub struct PolicyBuffer(Arc<Mutex<Vec<u8>>>);
impl PolicyBuffer {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Arc::new(Mutex::new(bytes)))
    }
    pub fn cleared(&self) -> bool {
        self.0.lock().unwrap().iter().all(|v| *v == 0)
    }
    pub fn clear(&self) {
        for byte in self.0.lock().unwrap().iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}
struct Clear(PolicyBuffer);
impl Drop for Clear {
    fn drop(&mut self) {
        self.0.clear();
    }
}
impl Clear {
    fn take(mut self) -> PolicyBuffer {
        std::mem::replace(&mut self.0, PolicyBuffer::new(Vec::new()))
    }
}
fn equal(expected: &PolicyBuffer, actual: &PolicyBuffer) -> Result<()> {
    let mut a = expected.0.lock().unwrap().clone();
    let mut c = actual.0.lock().unwrap().clone();
    let result = child_acl_equal(&a, &c);
    a.fill(0);
    c.fill(0);
    ensure!(result?, "fixed child default DACL differs");
    Ok(())
}
fn equal_and_clear(expected: &PolicyBuffer, actual: PolicyBuffer) -> Result<()> {
    let guard = Clear(actual);
    equal(expected, &guard.0)
}
pub struct Observation {
    condition: Condition,
    experiment: Experiment,
    prepared: bool,
    attempted: bool,
    created: bool,
    recorded: bool,
    completed: bool,
    exit: u32,
    baseline: Option<PolicyBuffer>,
    activation_seen: bool,
    operation_completed: bool,
    activation_error: u32,
}
impl Observation {
    pub fn condition(&self) -> Condition {
        self.condition
    }
    pub fn experiment(&self) -> Experiment {
        self.experiment
    }
    pub fn prepared(&self) -> bool {
        self.prepared
    }
    pub fn attempted(&self) -> bool {
        self.attempted
    }
    pub fn created(&self) -> bool {
        self.created
    }
    pub fn recorded(&self) -> bool {
        self.recorded
    }
    pub fn completed(&self) -> bool {
        self.completed
    }
    pub fn exit(&self) -> u32 {
        self.exit
    }
    pub fn new(condition: Condition, experiment: Experiment) -> Self {
        Self {
            condition,
            experiment,
            prepared: false,
            attempted: false,
            created: false,
            recorded: false,
            completed: false,
            exit: 0,
            baseline: None,
            activation_seen: false,
            operation_completed: false,
            activation_error: 0,
        }
    }
    pub fn call_expected(&self) -> bool {
        self.condition == Condition::ChildCreate
    }
    pub fn compound(&self) -> bool {
        matches!(
            self.experiment,
            Experiment::Image | Experiment::ActivationBundle
        )
    }
    pub fn label(&self) -> &'static str {
        if self.call_expected() {
            match self.experiment {
                Experiment::Host => "host-create",
                Experiment::Image => "image-bundle",
                Experiment::ActivationBundle => "activation-bundle",
                Experiment::Token => self.condition.name(),
            }
        } else {
            self.condition.name()
        }
    }
    pub fn prefix(&self) -> &'static str {
        match self.experiment {
            Experiment::Token => "WINDOWS_PYTHON_ACTIVATION_PREPARATION",
            Experiment::Host => "WINDOWS_PYTHON_HOST_PREPARATION",
            Experiment::Image => "WINDOWS_PYTHON_IMAGE_PREPARATION",
            Experiment::ActivationBundle => "WINDOWS_PYTHON_ACTIVATION_BUNDLE",
        }
    }
    pub fn require_fresh(&self) -> Result<()> {
        ensure!(
            !self.prepared
                && !self.attempted
                && !self.created
                && !self.recorded
                && !self.activation_seen
                && !self.operation_completed
                && self.baseline.is_none(),
            "fixed Python activation preparation is inconclusive"
        );
        Ok(())
    }
    pub fn activation(&mut self, line: &str) -> Result<()> {
        ensure!(
            !self.compound()
                && self.prepared
                && self.attempted
                && !self.activation_seen
                && line.len() < 256,
            "fixed Python activation preparation is inconclusive"
        );
        let prefix = format!(
            "WINDOWS_STARTUP_ACTIVATION context={} resource_type=24 resource_id=1 created=",
            if self.experiment == Experiment::Host {
                "host"
            } else {
                "lpac"
            }
        );
        let core = line
            .strip_prefix(&prefix)
            .and_then(|s| {
                s.strip_suffix(
                    " activated=False child_equivalence_claimed=False cause_claimed=False",
                )
            })
            .ok_or_else(|| {
                anyhow::anyhow!("fixed Python activation preparation is inconclusive")
            })?;
        let (created, error) = core.split_once(" win32_error=").ok_or_else(|| {
            anyhow::anyhow!("fixed Python activation preparation is inconclusive")
        })?;
        ensure!(
            matches!(created, "True" | "False")
                && (created == "True") == self.created
                && (1..=10).contains(&error.len())
                && error.bytes().all(|v| v.is_ascii_digit()),
            "fixed Python activation preparation is inconclusive"
        );
        let error: u32 = error
            .parse()
            .map_err(|_| anyhow::anyhow!("fixed Python activation preparation is inconclusive"))?;
        ensure!(
            !self.created || error == 0,
            "fixed Python activation preparation is inconclusive"
        );
        self.activation_error = error;
        self.activation_seen = true;
        Ok(())
    }
    pub fn complete_bundle(&mut self) -> Result<()> {
        ensure!(
            self.compound()
                && self.attempted
                && !self.operation_completed
                && !self.activation_seen
                && !self.created,
            "fixed Python activation preparation is inconclusive"
        );
        self.operation_completed = true;
        Ok(())
    }
    pub fn record(&mut self, exit: u32, text: &str, errors: &str) -> Result<()> {
        ensure!(
            self.prepared
                && self.baseline.is_some()
                && !self.recorded
                && self.attempted == self.call_expected()
                && (if self.compound() {
                    self.operation_completed == self.attempted
                        && !self.activation_seen
                        && !self.created
                } else {
                    self.activation_seen == self.attempted
                })
                && text.is_empty()
                && errors.is_empty(),
            "fixed Python activation preparation is inconclusive"
        );
        self.exit = exit;
        self.completed = exit == 0;
        self.recorded = true;
        Ok(())
    }
    pub fn activation_metadata(&self) -> Result<String> {
        if self.compound() {
            ensure!(
                self.recorded && self.attempted && self.operation_completed,
                "fixed Python activation preparation is inconclusive"
            );
            return Ok(format!(
                "{}_CALL condition={} operation_completed=True all_access_succeeded_claimed=False cause_claimed=False target_admitted=False production_grant=False",
                self.prefix(),
                self.label()
            ));
        }
        ensure!(
            self.recorded && self.activation_seen,
            "fixed Python activation preparation is inconclusive"
        );
        Ok(format!(
            "{}{} win32_error=0x{:08X} released_if_valid=True activated=False cause_claimed=False target_admitted=False production_grant=False",
            if self.experiment == Experiment::Host {
                "WINDOWS_PYTHON_HOST_PREPARATION_CALL condition=host-create context=host created="
            } else {
                "WINDOWS_PYTHON_ACTIVATION_CALL condition=child-create created="
            },
            b(self.created),
            self.activation_error
        ))
    }
    pub fn metadata(&self) -> Result<String> {
        ensure!(
            self.recorded,
            "fixed Python activation preparation is inconclusive"
        );
        Ok(format!(
            "{} condition={} {}={} raw_process_exit=0x{:08X} pass_code_completed={} stdout_empty=True stderr_empty=True default_dacl_unchanged=True process_job_handle_cleanup=True key_readable=True cause_claimed=False target_admitted=False production_grant=False",
            self.prefix(),
            self.label(),
            match self.experiment {
                Experiment::Image => "image_bundle_attempted",
                Experiment::ActivationBundle => "activation_bundle_attempted",
                _ => "activation_attempted",
            },
            b(self.attempted),
            self.exit,
            b(self.completed)
        ))
    }
    pub fn clear(&mut self) {
        if let Some(policy) = self.baseline.take() {
            policy.clear();
        }
    }
    pub fn policy_retained(&self) -> bool {
        self.baseline.is_some()
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        self.clear();
    }
}
/// Implemented by the actual qualified-token owner; host enter must requalify that same token.
pub trait PreparationIo {
    fn qualify(&mut self) -> Result<()>;
    fn deadline(&mut self) -> Result<()>;
    fn primary(&mut self) -> Result<PolicyBuffer>;
    fn duplicate(&mut self) -> Result<PolicyBuffer>;
    fn operation(&mut self) -> Result<bool>;
    fn leave(&mut self) -> Result<()>;
    fn require_host(&mut self) -> Result<()>;
    fn enter(&mut self) -> Result<()>;
}
pub fn prepare_token(value: &mut Observation, io: &mut impl PreparationIo) -> Result<()> {
    ensure!(
        value.experiment == Experiment::Token,
        "fixed Python activation preparation is inconclusive"
    );
    prepare_core(value, io, false)
}
pub fn prepare_host(value: &mut Observation, io: &mut impl PreparationIo) -> Result<()> {
    ensure!(
        value.experiment != Experiment::Token,
        "fixed Python activation preparation is inconclusive"
    );
    prepare_core(value, io, true)
}
fn prepare_core(value: &mut Observation, io: &mut impl PreparationIo, host: bool) -> Result<()> {
    value.require_fresh()?;
    io.qualify()?;
    io.deadline()?;
    let guard = Clear(io.primary()?);
    equal_and_clear(&guard.0, io.duplicate()?)?;
    io.qualify()?;
    io.deadline()?;
    if host {
        io.leave()?;
        io.require_host()?;
        io.deadline()?;
    }
    if value.call_expected() {
        value.attempted = true;
        let result = io.operation()?;
        if value.compound() {
            ensure!(
                result,
                "fixed Python activation preparation is inconclusive"
            );
            value.complete_bundle()?;
        } else {
            value.created = result;
        }
    }
    if host {
        io.require_host()?;
        io.deadline()?;
        io.enter()?;
    }
    io.qualify()?;
    io.deadline()?;
    equal_and_clear(&guard.0, io.primary()?)?;
    equal_and_clear(&guard.0, io.duplicate()?)?;
    value.baseline = Some(guard.take());
    value.prepared = true;
    Ok(())
}
pub fn emit_bounded(
    line: &str,
    bytes: &mut usize,
    emit: &mut impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let next = bytes
        .checked_add(line.len())
        .ok_or_else(|| anyhow::anyhow!("fixed preparation report overflow"))?;
    ensure!(next <= 4096, "fixed preparation report budget exceeded");
    *bytes = next;
    emit(line)
}
pub fn execute_comparison<'a>(
    kind: Experiment,
    mut observe: impl FnMut(&mut Observation) -> Result<()>,
    begin: impl FnOnce() -> Result<Trial<'a>>,
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<Option<anyhow::Error>> {
    let mut lease = begin()?;
    let mut values = Vec::new();
    let mut clean = true;
    let mut diagnostic = None;
    let mut bytes = 0;
    let operation = (|| {
        for condition in [
            Condition::Baseline,
            Condition::ChildCreate,
            Condition::BaselineAgain,
        ] {
            values.push(Observation::new(condition, kind));
            let at = values.len() - 1;
            clean = false;
            observe(&mut values[at])?;
            clean = true;
            let value = &values[at];
            ensure!(
                value.recorded && value.baseline.is_some() && value.experiment == kind,
                "fixed Python activation preparation is inconclusive"
            );
            if kind == Experiment::Host && value.attempted && !value.created {
                diagnostic = combine(
                    diagnostic.take(),
                    Some(anyhow::anyhow!(
                        "fixed host activation preparation positive control failed"
                    )),
                );
            }
            if !value.completed {
                diagnostic = combine(
                    diagnostic.take(),
                    Some(anyhow::anyhow!(
                        "fixed Python preparation pass failed condition={} raw_process_exit=0x{:08X}",
                        value.label(),
                        value.exit
                    )),
                );
            }
            if at > 0 {
                equal(
                    values[0].baseline.as_ref().unwrap(),
                    value.baseline.as_ref().unwrap(),
                )?;
            }
            if value.attempted {
                emit_bounded(&value.activation_metadata()?, &mut bytes, &mut emit)?;
            }
            emit_bounded(&value.metadata()?, &mut bytes, &mut emit)?;
        }
        Ok(())
    })();
    let primary = match operation {
        Ok(()) => None,
        Err(error) => combine(diagnostic.take(), Some(error)),
    };
    let recovery = if clean {
        (lease.restore)()
    } else {
        (lease.defer)()
    };
    for value in &mut values {
        value.clear();
    }
    if let Err(error) = recovery {
        return Err(combine(primary.or_else(|| diagnostic.take()), Some(error)).unwrap());
    }
    if let Some(error) = primary {
        return Err(error);
    }
    let line = format!(
        "{}_COMPARISON middle_exit_differs={} final_exit_differs={} baseline_policy_equal=True key_restored=True cache_reset_claimed=False cause_claimed=False target_admitted=False production_grant=False",
        values[0].prefix(),
        b(values[0].exit != values[1].exit),
        b(values[0].exit != values[2].exit)
    );
    if let Err(error) = emit_bounded(&line, &mut bytes, &mut emit) {
        return Err(combine(diagnostic.take(), Some(error)).unwrap());
    }
    Ok(diagnostic)
}
#[derive(Default)]
pub struct RetainedPreparations {
    values: [Option<anyhow::Error>; 4],
}
impl RetainedPreparations {
    pub fn retain(&mut self, kind: Experiment, error: Option<anyhow::Error>) -> Result<()> {
        let at = kind as usize;
        ensure!(
            self.values[at].is_none(),
            "fixed preparation diagnostic repeats"
        );
        self.values[at] = error;
        Ok(())
    }
    pub fn preserve(&mut self, later: Option<anyhow::Error>) -> Option<anyhow::Error> {
        let mut first = None;
        for value in &mut self.values {
            first = combine(first, value.take());
        }
        combine(first, later)
    }
}
pub fn require_bundle_registry_status(status: i32) -> Result<()> {
    ensure!(
        status == 0,
        "fixed activation bundle registry status differs"
    );
    Ok(())
}
pub fn preserve_all(
    startup: &mut crate::windows_security::policy::registry_comparison::StartupComparison,
    preparation: &mut RetainedPreparations,
    csr: &mut super::csr::RetainedFailures,
    callback: &mut crate::windows_security::policy::registry_comparison::causal::CallbackLatch,
    later: Option<anyhow::Error>,
) -> Option<anyhow::Error> {
    startup.preserve_failure(preparation.preserve(csr.preserve(callback.preserve(later))))
}
#[derive(Default)]
pub struct PreparationPlan {
    retained: RetainedPreparations,
    started: [bool; 4],
}
impl PreparationPlan {
    pub fn run<'a>(
        &mut self,
        kind: Experiment,
        observe: impl FnMut(&mut Observation) -> Result<()>,
        begin: impl FnOnce() -> Result<Trial<'a>>,
        emit: impl FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        let at = kind as usize;
        ensure!(
            self.retained.values[at].is_none()
                && (kind == Experiment::Token || !self.started[at])
                && (at < 2 || self.started[at - 1]),
            "fixed preparation experiment order differs"
        );
        self.started[at] = true;
        self.retained
            .retain(kind, execute_comparison(kind, observe, begin, emit)?)
    }
    pub fn retained_mut(&mut self) -> &mut RetainedPreparations {
        &mut self.retained
    }
}
