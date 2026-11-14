//! Traced/undebugged transport and lease recovery, independent of admission or attribution.
use super::{
    Failures,
    dispatch::{QualifiedFailure, finish_trace},
    self_result::{self, SelfRole},
    sweep::Trial,
};
use anyhow::{Result, ensure};
#[path = "csr_checks.rs"]
mod checks;
pub use checks::{check_module_validation, check_validation};
pub fn check_python_validation() -> Result<()> {
    checks::check_python()
}
#[path = "csr_thread_checks.rs"]
pub(crate) mod thread_checks;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    ExplicitId2,
    Module,
    PythonPass,
}
fn b(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}
pub const MODULE_WIRE: &str = "WINDOWS_MODULE_ACTIVATION attach=1 query_succeeded=1 root_evaluated=1 root_is_module=1 win32_error=0x00000000 returned_bytes=0x00000080 assembly_count=0x00000003\n";
pub const HOST_PASS: &str =
    "pass_code_completed=True raw_process_exit=0x00000000 stdout_empty=True stderr_empty=True";
pub fn trace_metadata(
    state: &super::threads::ObservationState,
    natural_exit: bool,
    invalidated: bool,
    role: Role,
) -> Result<String> {
    ensure!(
        state.destroyed,
        "fixed resource observation refused check=dispatch-metadata-destruction"
    );
    let qualified = state.captured
        && state.base_equal
        && state.restored
        && !state.failed
        && natural_exit
        && !invalidated;
    let prefix = match role {
        Role::PythonPass => {
            "WINDOWS_PYTHON_CSR_DISPATCH invocation_module_verified=False failing_request_verified=False paired="
        }
        Role::Module => {
            "WINDOWS_MODULE_CSR_DISPATCH invocation_module_verified=False python_equivalence_claimed=False paired="
        }
        Role::ExplicitId2 => "WINDOWS_CSR_DISPATCH paired=",
    };
    let observed = state
        .raw_eax
        .filter(|_| state.captured)
        .map(|raw| format!(" request=0x1001001E length=0x000001F8 raw_return=0x{raw:08X}"))
        .unwrap_or_default();
    let line = format!(
        "{prefix}{} target_equal={}{observed} live_restored={} natural_exit={} state_destroyed=True observation_qualified={}{}{} server_operation_verified=False cause_claimed=False target_admitted=False production_grant=False undebugged_equivalence_claimed=False",
        b(state.captured),
        b(state.base_equal),
        b(state.restored),
        b(natural_exit),
        b(qualified),
        state.traps,
        state.software
    );
    ensure!(
        line.len() <= 1024 && line.is_ascii(),
        "fixed resource observation refused check=dispatch-metadata-budget"
    );
    Ok(line)
}
fn hex(value: &str) -> Result<u32> {
    ensure!(
        value.len() == 8
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c)),
        "fixed module activation contract failed"
    );
    Ok(u32::from_str_radix(value, 16)?)
}
pub fn module_result(manifest: bool, exit: u32, text: &str, errors: &str) -> Result<String> {
    ensure!(errors.is_empty(), "fixed module activation contract failed");
    if exit != 0 {
        ensure!(
            manifest && exit & 0x80000000 != 0 && text.is_empty(),
            "fixed module activation contract failed"
        );
        return Ok(format!(
            "entry_observed=False association_proved=False exit=0x{exit:08X}"
        ));
    }
    let fields: Vec<_> = text.strip_suffix('\n').unwrap_or("").split(' ').collect();
    ensure!(
        fields.len() == 8 && fields[0] == "WINDOWS_MODULE_ACTIVATION" && fields[1] == "attach=1",
        "fixed module activation contract failed"
    );
    let bit = |at: usize, label: &str| -> Result<bool> {
        match fields[at].strip_prefix(label) {
            Some("0") => Ok(false),
            Some("1") => Ok(true),
            _ => anyhow::bail!("fixed module activation contract failed"),
        }
    };
    let query = bit(2, "query_succeeded=")?;
    let evaluated = bit(3, "root_evaluated=")?;
    let own = bit(4, "root_is_module=")?;
    let field = |at: usize, label: &str| -> Result<u32> {
        hex(fields[at].strip_prefix(label).unwrap_or(""))
    };
    let error = field(5, "win32_error=0x")?;
    let returned = field(6, "returned_bytes=0x")?;
    let assemblies = field(7, "assembly_count=0x")?;
    ensure!(
        returned <= 65536
            && assemblies <= 16
            && (!own || evaluated)
            && (!evaluated || query && assemblies >= 1)
            && (if query {
                error == 0 && returned >= 64
            } else {
                error != 0 && !evaluated && !own && assemblies == 0
            })
            && (!manifest || query && evaluated && own),
        "fixed module activation contract failed"
    );
    Ok(format!(
        "entry_observed=True association_proved={} exit=0x00000000 {}",
        b(own),
        text.trim_end_matches('\n')
    ))
}
pub struct Observation {
    traced: bool,
    role: Role,
    recorded: bool,
    receipt: bool,
    completed: bool,
    exit: u32,
    characters: usize,
}
impl Observation {
    pub fn traced(&self) -> bool {
        self.traced
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn recorded(&self) -> bool {
        self.recorded
    }
    pub fn receipt(&self) -> bool {
        self.receipt
    }
    pub fn completed(&self) -> bool {
        self.completed
    }
    pub fn exit(&self) -> u32 {
        self.exit
    }
    pub fn characters(&self) -> usize {
        self.characters
    }
    pub fn new(traced: bool, role: Role) -> Self {
        Self {
            traced,
            role,
            recorded: false,
            receipt: false,
            completed: false,
            exit: 0,
            characters: 0,
        }
    }
    pub fn from_flags(traced: bool, module: bool, python: bool) -> Result<Self> {
        ensure!(
            !module || !python,
            "fixed CSR dispatch transport is inconclusive"
        );
        Ok(Self::new(
            traced,
            if python {
                Role::PythonPass
            } else if module {
                Role::Module
            } else {
                Role::ExplicitId2
            },
        ))
    }
    pub fn record(&mut self, code: u32, text: &str, errors: &str) -> Result<()> {
        ensure!(
            !self.recorded
                && text.encode_utf16().count() <= if self.role == Role::Module { 256 } else { 128 }
                && errors.is_empty(),
            "fixed CSR dispatch transport is inconclusive"
        );
        let complete = match self.role {
            Role::PythonPass => {
                ensure!(
                    text.is_empty(),
                    "fixed CSR dispatch transport is inconclusive"
                );
                code == 0
            }
            Role::Module => {
                module_result(true, code, text, errors)?;
                code == 0
            }
            Role::ExplicitId2 => {
                let complete = code == 0
                    && self_result::result(
                        code,
                        Some(text),
                        Some(errors),
                        SelfRole::ExplicitId2,
                        |_| Ok(()),
                    )
                    .is_ok_and(|line| line == SelfRole::ExplicitId2.success());
                ensure!(
                    complete || code & 0x80000000 != 0 && text.is_empty(),
                    "fixed CSR dispatch transport is inconclusive"
                );
                complete
            }
        };
        self.recorded = true;
        self.exit = code;
        self.completed = complete;
        if self.role != Role::PythonPass {
            self.characters = text.encode_utf16().count();
        }
        self.receipt = self.role == Role::ExplicitId2 && self_result::observed_pre_call(Some(text));
        Ok(())
    }
    pub fn metadata(&self) -> Result<String> {
        ensure!(
            self.recorded,
            "fixed CSR dispatch transport is inconclusive"
        );
        let line = match self.role {
            Role::PythonPass => format!(
                "WINDOWS_PYTHON_CSR_TRANSPORT traced={} raw_process_exit=0x{:08X} pass_code_completed={} stdout_empty=True stderr_empty=True process_job_handle_cleanup=True key_readable=True invocation_module_verified=False failing_request_verified=False server_operation_verified=False cause_claimed=False target_admitted=False production_grant=False undebugged_equivalence_claimed=False",
                b(self.traced),
                self.exit,
                b(self.completed)
            ),
            Role::Module => format!(
                "WINDOWS_MODULE_CSR_TRANSPORT traced={} raw_process_exit=0x{:08X} entry_observed={} association_proved={} completed_wire={} stdout_chars={} process_job_handle_cleanup=True key_readable=True invocation_module_verified=False python_equivalence_claimed=False target_admitted=False cause_claimed=False production_grant=False",
                b(self.traced),
                self.exit,
                b(self.completed),
                b(self.completed),
                b(self.completed),
                self.characters
            ),
            Role::ExplicitId2 => format!(
                "WINDOWS_CSR_DISPATCH_TRANSPORT traced={} raw_process_exit=0x{:08X} pre_call_receipt_observed={} completed_wire={} stdout_chars={} process_job_handle_cleanup=True key_readable=True target_admitted=False cause_claimed=False production_grant=False",
                b(self.traced),
                self.exit,
                b(self.receipt),
                b(self.completed),
                self.characters
            ),
        };
        ensure!(
            line.len() < 1024 && line.is_ascii(),
            "fixed CSR dispatch metadata budget differs"
        );
        Ok(line)
    }
}
pub(crate) fn combine(
    first: Option<anyhow::Error>,
    later: Option<anyhow::Error>,
) -> Option<anyhow::Error> {
    match (first, later) {
        (Some(a), Some(b)) => Some(Failures { errors: vec![a, b] }.into()),
        (a, None) | (None, a) => a,
    }
}
/// A successful return may contain a retained diagnostic. Only uncertain cleanup is an error.
pub fn execute<'a>(
    role: Role,
    mut observe: impl FnMut(&mut Observation) -> Result<()>,
    begin: impl FnOnce() -> Result<Trial<'a>>,
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<Option<anyhow::Error>> {
    let mut lease = begin()?;
    let mut clean = true;
    let mut diagnostic = None;
    let operation = (|| {
        for traced in [true, false] {
            let mut value = Observation::new(traced, role);
            clean = false;
            let mut qualified = false;
            match observe(&mut value) {
                Ok(()) => clean = true,
                Err(error) => match error.downcast::<QualifiedFailure>() {
                    Ok(failure) => {
                        clean = true;
                        qualified = true;
                        diagnostic = combine(diagnostic.take(), Some(failure.into_original()));
                    }
                    Err(error) => return Err(error),
                },
            }
            if value.recorded {
                if role == Role::PythonPass && !value.completed {
                    diagnostic = combine(
                        diagnostic.take(),
                        Some(anyhow::anyhow!(
                            "fixed Python CSR pass failed raw_process_exit=0x{:08X}",
                            value.exit
                        )),
                    );
                }
                emit(&value.metadata()?)?;
            } else {
                ensure!(qualified, "fixed CSR dispatch comparison is inconclusive");
            }
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
    if let Err(error) = recovery {
        return Err(combine(primary.or_else(|| diagnostic.take()), Some(error)).unwrap());
    }
    if let Some(error) = primary {
        return Err(error);
    }
    Ok(diagnostic)
}
pub fn finish_undebugged(
    primary: anyhow::Error,
    cleanup: Vec<anyhow::Error>,
    started: bool,
    signaled: bool,
    reaped: bool,
) -> anyhow::Error {
    finish_trace(
        Some(primary),
        cleanup,
        started,
        signaled && reaped,
        || Ok(String::new()),
        |_| Ok(()),
    )
    .unwrap_err()
}
#[derive(Default)]
pub struct RetainedFailures {
    values: [Option<anyhow::Error>; 3],
}
impl RetainedFailures {
    pub fn retain(&mut self, role: Role, error: Option<anyhow::Error>) -> Result<()> {
        let at = match role {
            Role::ExplicitId2 => 0,
            Role::Module => 1,
            Role::PythonPass => 2,
        };
        ensure!(
            self.values[at].is_none(),
            "fixed CSR diagnostic already retained"
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
/// Run/lease/metadata/positive/latch ordering is shared by all three genuine fixture roles.
pub fn complete_host(
    role: Role,
    run: impl FnOnce(&mut dyn FnMut(&str) -> Result<()>) -> Result<String>,
    close: impl FnOnce() -> Result<()>,
    mut emit: impl FnMut(&str) -> Result<()>,
    accept: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut metadata = None;
    let operation = run(&mut |line| {
        ensure!(
            metadata.is_none() && (role != Role::PythonPass || line.encode_utf16().count() <= 4096),
            "fixed CSR host metadata repeats or exceeds budget"
        );
        metadata = Some(line.to_owned());
        Ok(())
    })
    .and_then(|value| {
        match role {
            Role::ExplicitId2 => self_result::require_host(&value, SelfRole::ExplicitId2)?,
            Role::PythonPass => ensure!(
                value == HOST_PASS,
                "fixed original Python CSR contract failed"
            ),
            Role::Module => {
                let prefix = "entry_observed=True association_proved=True exit=0x00000000 ";
                let wire = value
                    .strip_prefix(prefix)
                    .ok_or_else(|| anyhow::anyhow!("fixed module CSR host failed"))?;
                ensure!(
                    module_result(true, 0, &format!("{wire}\n"), "")? == value,
                    "fixed module CSR host failed"
                );
            }
        }
        ensure!(metadata.is_some(), "fixed CSR host metadata absent");
        Ok(())
    });
    let closing = close();
    if let Some(error) = combine(operation.err(), closing.err()) {
        return Err(error);
    }
    emit(metadata.as_deref().unwrap())?;
    emit(match role {
        Role::ExplicitId2 => {
            "WINDOWS_CSR_DISPATCH_HOST positive=True cleanup_complete=True cause_claimed=False"
        }
        Role::Module => {
            "WINDOWS_MODULE_CSR_HOST positive=True cleanup_complete=True invocation_module_verified=False cause_claimed=False"
        }
        Role::PythonPass => {
            "WINDOWS_PYTHON_CSR_HOST positive=True cleanup_complete=True invocation_module_verified=False failing_request_verified=False server_operation_verified=False cause_claimed=False target_admitted=False production_grant=False undebugged_equivalence_claimed=False"
        }
    })?;
    accept()
}
