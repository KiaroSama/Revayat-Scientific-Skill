//! Nested registry differential controls. Returned controls must include their owned cleanup.
use super::{DENIED, boolean, combine};
use crate::windows_security::{
    activation::self_result::{self, SelfRole},
    scratch::cleanup::QualifiedModuleCallbackFailure,
};
use anyhow::{Result, ensure};
use std::sync::OnceLock;
fn condition(value: &str) -> Result<()> {
    ensure!(
        ["original", "modified", "restored"].contains(&value),
        "unsupported registry differential condition"
    );
    Ok(())
}
fn hex(value: &str) -> Option<u32> {
    if value.len() != 8
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    {
        return None;
    }
    u32::from_str_radix(value, 16).ok()
}
pub fn child_result(value: &str) -> Result<String> {
    ensure!(value.len() <= 256, "child activation result exceeds bound");
    let value = value
        .strip_prefix("WINDOWS_CHILD_ACTIVATION created=")
        .and_then(|v| v.strip_suffix(" cause_claimed=False child_equivalence_claimed=False\n"))
        .ok_or_else(|| anyhow::anyhow!("child activation result is missing or malformed"))?;
    let (created, error) = value
        .split_once(" win32_error=0x")
        .ok_or_else(|| anyhow::anyhow!("child activation result is malformed"))?;
    let code = hex(error).ok_or_else(|| anyhow::anyhow!("child activation status is malformed"))?;
    ensure!(
        ["True", "False"].contains(&created) && (created == "True") == (code == 0),
        "child activation result/error is inconsistent"
    );
    Ok(format!(
        "WINDOWS_CHILD_ACTIVATION created={created} win32_error=0x{error} cause_claimed=False child_equivalence_claimed=False"
    ))
}
pub fn registry_condition(label: &str, activation: &str, exit: u32) -> Result<String> {
    condition(label)?;
    ensure!(
        child_result(&format!("{activation}\n"))? == activation,
        "registry condition activation is not canonical"
    );
    Ok(format!(
        "WINDOWS_REGISTRY_CONDITION condition={label} {activation} python_exit=0x{exit:08X} target_admitted=False cause_claimed=False"
    ))
}
pub fn default_condition(label: &str, result: &str) -> Result<String> {
    condition(label)?;
    let absent = result
        .strip_prefix("entry_observed=False exit=0x")
        .and_then(hex)
        .is_some_and(|exit| exit & 0x80000000 != 0);
    ensure!(
        result == "entry_observed=True exit=0x00000000" || absent,
        "default activation result is unqualified"
    );
    Ok(format!(
        "WINDOWS_DEFAULT_ACTIVATION condition={label} {result} cause_claimed=False python_equivalence_claimed=False"
    ))
}
pub fn observe_startup(
    label: &str,
    control: impl FnOnce() -> Result<String>,
    ordinary: impl FnOnce() -> Result<u32>,
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<u32> {
    let result = control()?;
    emit(&default_condition(label, &result)?)?;
    ordinary()
}
pub fn observe_self(
    label: &str,
    control: impl FnOnce() -> Result<String>,
    later: impl FnOnce() -> Result<u32>,
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<u32> {
    condition(label)?;
    let result = control()?;
    if label == "modified" {
        ensure!(
            result == SelfRole::Original.success(),
            "modified self activation failed"
        );
        emit(&self_result::condition(
            label,
            Some(&result),
            SelfRole::Original,
        )?)?;
    } else {
        ensure!(
            result == "completed_wire=False exit=0xC0000022",
            "baseline self activation did not preserve denial"
        );
        emit(&format!(
            "WINDOWS_SELF_ACTIVATION_NEGATIVE condition={label} {result} process_job_handle_cleanup=True"
        ))?;
    }
    later()
}
pub fn module_result(manifest: bool, exit: u32, text: &str, errors: &str) -> Result<String> {
    ensure!(errors.is_empty(), "module activation transport failed");
    if exit != 0 {
        ensure!(
            manifest && exit & 0x80000000 != 0 && text.is_empty(),
            "module activation nonentry is unqualified"
        );
        return Ok(format!(
            "entry_observed=False association_proved=False exit=0x{exit:08X}"
        ));
    }
    static RECORD: OnceLock<regex::Regex> = OnceLock::new();
    let pattern=RECORD.get_or_init(||regex::Regex::new(r"\AWINDOWS_MODULE_ACTIVATION attach=1 query_succeeded=([01]) root_evaluated=([01]) root_is_module=([01]) win32_error=0x([0-9A-F]{8}) returned_bytes=0x([0-9A-F]{8}) assembly_count=0x([0-9A-F]{8})\n\z").expect("fixed module activation grammar"));
    let fields = pattern
        .captures(text)
        .ok_or_else(|| anyhow::anyhow!("module activation output is malformed"))?;
    let (query, evaluated, own) = (&fields[1] == "1", &fields[2] == "1", &fields[3] == "1");
    let (error, returned, assemblies) = (
        hex(&fields[4]).unwrap(),
        hex(&fields[5]).unwrap(),
        hex(&fields[6]).unwrap(),
    );
    ensure!(
        returned <= 65536
            && assemblies <= 16
            && (!own || evaluated)
            && (!evaluated || query && assemblies >= 1),
        "module activation association fields differ"
    );
    ensure!(
        if query {
            error == 0 && returned >= 64
        } else {
            error != 0 && !evaluated && !own && assemblies == 0
        },
        "module activation query/status differs"
    );
    ensure!(
        !manifest || query && evaluated && own,
        "manifest module association is unqualified"
    );
    Ok(format!(
        "entry_observed=True association_proved={} exit=0x00000000 {}",
        boolean(own),
        text.trim_end_matches('\n')
    ))
}
pub fn module_condition(label: &str, manifest: bool, result: &str) -> Result<String> {
    condition(label)?;
    ensure!(result.len() <= 512, "module condition exceeds bound");
    let canonical = if let Some(tail) = result
        .strip_prefix("entry_observed=True association_proved=True exit=0x00000000 ")
        .or_else(|| {
            result.strip_prefix("entry_observed=True association_proved=False exit=0x00000000 ")
        }) {
        module_result(manifest, 0, &format!("{tail}\n"), "")?
    } else {
        let exit = result
            .strip_prefix("entry_observed=False association_proved=False exit=0x")
            .and_then(hex)
            .ok_or_else(|| anyhow::anyhow!("module condition is malformed"))?;
        module_result(manifest, exit, "", "")?
    };
    ensure!(canonical == result, "module condition is not canonical");
    Ok(format!(
        "WINDOWS_MODULE_CONDITION condition={label} pair={} {result} active_at_entry_claimed=False python_equivalence_claimed=False cause_claimed=False",
        if manifest {
            "module-id2"
        } else {
            "module-plain"
        }
    ))
}
pub fn require_unentered(result: &str) -> Result<u32> {
    module_condition("modified", true, result)?;
    let exit = result
        .strip_prefix("entry_observed=False association_proved=False exit=0x")
        .and_then(hex)
        .ok_or_else(|| anyhow::anyhow!("module callback entry was already observed"))?;
    ensure!(
        exit & 0x80000000 != 0,
        "module callback expected a failing process exit"
    );
    Ok(exit)
}
#[derive(Default)]
pub struct CallbackLatch {
    failure: Option<anyhow::Error>,
}
impl CallbackLatch {
    pub fn retain(&mut self, error: anyhow::Error) -> Result<()> {
        ensure!(
            self.failure.is_none() && error.is::<QualifiedModuleCallbackFailure<anyhow::Error>>(),
            "registry callback diagnostic is foreign or already retained"
        );
        self.failure = Some(error);
        Ok(())
    }
    pub fn pending(&self) -> bool {
        self.failure.is_some()
    }
    pub fn preserve(&mut self, later: Option<anyhow::Error>) -> Option<anyhow::Error> {
        combine(self.failure.take(), later)
    }
    pub fn require_negative(&mut self, exit: u32) -> Result<()> {
        let later = if exit == DENIED as u32 {
            None
        } else {
            Some(anyhow::anyhow!(
                "fixed negative baseline did not retain its expected denial"
            ))
        };
        match self.preserve(later) {
            None => Ok(()),
            Some(error) => Err(error),
        }
    }
}
pub fn observe_modules(
    label: &str,
    mut control: impl FnMut(bool) -> Result<String>,
    ordinary: impl FnOnce() -> Result<u32>,
    mut emit: impl FnMut(&str) -> Result<()>,
    trace: Option<&mut dyn FnMut(u32) -> Result<String>>,
    latch: Option<&mut CallbackLatch>,
) -> Result<u32> {
    condition(label)?;
    let mut id2 = None;
    for manifest in [false, true] {
        let result = control(manifest)?;
        if label == "modified" {
            ensure!(
                result.starts_with(if manifest {
                    "entry_observed=True association_proved=True exit=0x00000000 "
                } else {
                    "entry_observed=True association_proved="
                }),
                "modified module control did not enter its fixed role"
            );
        }
        emit(&module_condition(label, manifest, &result)?)?;
        if manifest {
            id2 = Some(result);
        }
    }
    if let Some(trace) = trace
        && label == "original"
    {
        let latch = latch.ok_or_else(|| {
            anyhow::anyhow!("callback trace requires its retained diagnostic owner")
        })?;
        let expected = match require_unentered(id2.as_deref().unwrap()) {
            Ok(exit) => exit,
            Err(original) => {
                // Both completed control callbacks returned only after owned cleanup;
                // no callback method ran, and no native success is claimed by this diagnostic.
                latch.retain(QualifiedModuleCallbackFailure { original }.into())?;
                emit(
                    "WINDOWS_MODULE_CALLBACK diagnostic_failed=True cleanup_qualified=True method_applicable=False",
                )?;
                return ordinary();
            }
        };
        match trace(expected) {
            Ok(line) => emit(&line)?,
            Err(error) => {
                if error.is::<QualifiedModuleCallbackFailure<anyhow::Error>>() {
                    latch.retain(error)?;
                    emit(
                        "WINDOWS_MODULE_CALLBACK diagnostic_failed=True cleanup_qualified=True observation_only=True",
                    )?;
                } else {
                    return Err(error);
                }
            }
        }
    }
    ordinary()
}
