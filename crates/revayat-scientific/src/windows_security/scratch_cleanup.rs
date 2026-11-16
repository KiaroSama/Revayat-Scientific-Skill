//! Fixed contained-launch guards, bounded preflight evidence, and owned cleanup qualification.
use super::{SharedError, failure};
use anyhow::{Result, ensure};
use std::{error::Error, fmt, sync::Arc};

#[derive(Clone, Copy, Debug)]
pub enum Dispatch {
    Python,
    Module,
    SelfActivation { traced: bool },
}
#[derive(Clone, Copy, Debug, Default)]
pub struct LaunchRole {
    pub module: i32,
    pub self_activation: bool,
    pub self_resource: bool,
    pub self_role: i32,
}
pub fn validate_dispatch(role: LaunchRole, dispatch: Dispatch) -> Result<()> {
    let supported = match dispatch {
        Dispatch::Python => {
            role.module == 0 && !role.self_activation && !role.self_resource && role.self_role == 0
        }
        Dispatch::Module => {
            role.module == 2 && !role.self_activation && !role.self_resource && role.self_role == 0
        }
        Dispatch::SelfActivation { traced } => {
            role.module == 0
                && role.self_activation
                && role.self_role == 2
                && role.self_resource == traced
        }
    };
    ensure!(supported, "unsupported fixed CSR dispatch role");
    Ok(())
}
pub fn manual_activation_role(role: i32) -> Result<()> {
    ensure!(
        (0..=2).contains(&role),
        "undefined fixed manual activation role"
    );
    Ok(())
}
pub fn module_role(role: i32, registry: Option<i32>, exit: Option<u32>) -> Result<bool> {
    let callback = role == 3;
    ensure!(
        (0..=3).contains(&role)
            && callback == exit.is_some()
            && (!callback || registry == Some(0xc0000022u32 as i32) && exit == Some(0xc0000022)),
        "unsupported fixed module activation role"
    );
    Ok(callback)
}
pub fn registry_condition(actual: i32, expected: i32) -> Result<()> {
    ensure!(
        matches!(expected as u32, 0 | 0xc0000022)
            && if expected == 0 {
                actual >= 0
            } else {
                actual == expected
            },
        "fixed registry differential condition was not observed"
    );
    Ok(())
}
pub fn creation_flags(debug: bool) -> u32 {
    0x8040c | if debug { 2 } else { 0 }
}
fn hexadecimal(value: &str) -> bool {
    value.len() == 8
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}
pub fn preflight_evidence(capture: &str) -> String {
    let unknown = "WINDOWS_PREFLIGHT_FAILURE evidence=unknown";
    if capture.len() > 128 {
        return unknown.into();
    }
    let Some(line) = capture.strip_suffix('\n') else {
        return unknown.into();
    };
    let line = line.strip_suffix('\r').unwrap_or(line);
    let words = line.split(' ').collect::<Vec<_>>();
    let valid = (|| {
        if !matches!(words.len(), 5 | 8) || words[0] != "WINDOWS_PREFLIGHT_FAILURE" {
            return false;
        }
        let Some(number) = words[1].strip_prefix("line=") else {
            return false;
        };
        if number.is_empty()
            || number.len() > 4
            || !number.bytes().all(|b| b.is_ascii_digit())
            || number.len() > 1 && number.starts_with('0')
        {
            return false;
        }
        if ![
            "kind=assertion",
            "kind=os",
            "kind=timeout",
            "kind=import",
            "kind=other",
        ]
        .contains(&words[2])
        {
            return false;
        }
        for (word, prefix) in [(words[3], "errno="), (words[4], "winerror=")] {
            let Some(value) = word.strip_prefix(prefix) else {
                return false;
            };
            if value != "none" && !hexadecimal(value) {
                return false;
            }
        }
        if words.len() == 8 {
            if !["cwd=same", "cwd=other", "cwd=unknown"].contains(&words[5]) {
                return false;
            }
            for (word, prefix) in [(words[6], "open="), (words[7], "close=")] {
                let Some(value) = word.strip_prefix(prefix) else {
                    return false;
                };
                if !["ok", "none", "unknown"].contains(&value) && !hexadecimal(value) {
                    return false;
                }
            }
        }
        true
    })();
    if valid { line.into() } else { unknown.into() }
}
#[derive(Debug)]
pub struct PreflightExit {
    pub code: u32,
    pub evidence: String,
}
impl fmt::Display for PreflightExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fixed ordinary preflight returned a nonzero exit")
    }
}
impl Error for PreflightExit {}
pub fn require_exit(
    code: u32,
    phase: &str,
    observe: bool,
    errors: &str,
    output: &str,
) -> Result<()> {
    if code == 0 {
        return Ok(());
    }
    if phase == "preflight" {
        if observe {
            return Err(PreflightExit {
                code,
                evidence: preflight_evidence(errors),
            }
            .into());
        }
        anyhow::bail!(
            "Windows preflight failed exit=0x{code:08X} {}",
            preflight_evidence(errors)
        );
    }
    ensure!(!observe, "exit observation is not ordinary preflight");
    anyhow::bail!("Windows {phase} failed exit={code} {errors} {output}")
}
#[derive(Debug)]
pub struct OwnedCleanupFailure<E = SharedError> {
    pub errors: Vec<E>,
}
impl<E> fmt::Display for OwnedCleanupFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("owned Windows operation/cleanup failed")
    }
}
impl<E: fmt::Debug> Error for OwnedCleanupFailure<E> {}
pub struct QualifiedModuleCallbackFailure<E = SharedError> {
    pub original: E,
}
impl<E> fmt::Display for QualifiedModuleCallbackFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fixed module callback failed after qualified cleanup")
    }
}
impl<E> fmt::Debug for QualifiedModuleCallbackFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl<E> Error for QualifiedModuleCallbackFailure<E> {}
pub fn cleanup_failure(primary: Option<SharedError>, cleanup: Vec<SharedError>) -> SharedError {
    let mut errors = Vec::new();
    if let Some(error) = primary {
        errors.push(error);
    }
    errors.extend(cleanup);
    Arc::new(OwnedCleanupFailure { errors })
}
pub fn completion_failure(
    primary: Option<SharedError>,
    cleanup: Vec<SharedError>,
    callback: bool,
    destroyed: bool,
) -> Option<SharedError> {
    if !cleanup.is_empty() {
        return Some(cleanup_failure(primary, cleanup));
    }
    if callback && destroyed {
        primary.map(|original| Arc::new(QualifiedModuleCallbackFailure { original }) as SharedError)
    } else {
        None
    }
}

pub fn check_cleanup_validation() -> Result<()> {
    for (role, dispatch) in [
        (
            LaunchRole {
                module: 1,
                ..LaunchRole::default()
            },
            Dispatch::Module,
        ),
        (
            LaunchRole {
                module: 2,
                self_activation: true,
                ..LaunchRole::default()
            },
            Dispatch::Module,
        ),
        (
            LaunchRole {
                module: 2,
                self_resource: true,
                ..LaunchRole::default()
            },
            Dispatch::Module,
        ),
        (
            LaunchRole {
                module: 2,
                ..LaunchRole::default()
            },
            Dispatch::SelfActivation { traced: false },
        ),
    ] {
        ensure!(
            validate_dispatch(role, dispatch).is_err(),
            "module CSR role reached unrelated launch effects"
        );
    }
    for role in [-1, 3, i32::MAX] {
        ensure!(
            manual_activation_role(role).is_err(),
            "undefined activation role reached contained launch effects"
        );
    }
    let evidence = "WINDOWS_PREFLIGHT_FAILURE line=123 kind=assertion errno=none winerror=none";
    for ending in ["\n", "\r\n"] {
        ensure!(
            preflight_evidence(&format!("{evidence}{ending}")) == evidence,
            "fixed ordinary failure evidence changed"
        );
    }
    let unknown = "WINDOWS_PREFLIGHT_FAILURE evidence=unknown";
    for invalid in [
        "".into(),
        "private-capture".into(),
        evidence.into(),
        format!("{evidence}\n{evidence}\n"),
        format!("{}\n", evidence.replace("line=123", "line=10000")),
        format!("{}\n", evidence.replace("kind=assertion", "kind=private")),
        format!("{}\n", evidence.replace("errno=none", "errno=100000000")),
        "x".repeat(129),
    ] {
        ensure!(
            preflight_evidence(&invalid) == unknown,
            "unqualified ordinary failure evidence escaped"
        );
    }
    for suffix in [
        " cwd=same open=ok close=ok",
        " cwd=other open=00000005 close=none",
        " cwd=unknown open=unknown close=unknown",
    ] {
        ensure!(
            preflight_evidence(&format!("{evidence}{suffix}\n")) == format!("{evidence}{suffix}"),
            "fixed scratch failure evidence changed"
        );
    }
    for suffix in [
        " cwd=private open=ok close=ok",
        " cwd=same open=100000000 close=none",
        " cwd=same open=ok close=private",
        " cwd=same",
        " cwd=same open=ok close=ok extra=True",
    ] {
        ensure!(
            preflight_evidence(&format!("{evidence}{suffix}\n")) == unknown,
            "unqualified scratch failure evidence escaped"
        );
    }
    require_exit(0, "preflight", false, "", "")?;
    require_exit(0, "preflight", true, "", "")?;
    for code in [1, 0xc0000022, u32::MAX] {
        let ordinary = require_exit(code, "preflight", false, "", "").unwrap_err();
        let typed = require_exit(code, "preflight", true, "", "").unwrap_err();
        ensure!(
            ordinary.downcast_ref::<PreflightExit>().is_none()
                && typed
                    .downcast_ref::<PreflightExit>()
                    .is_some_and(|v| v.code == code),
            "ordinary exit observation weakened failure semantics"
        );
        ensure!(
            require_exit(code, "preflight", false, "private-errors", "private-output")
                .unwrap_err()
                .to_string()
                == format!("Windows preflight failed exit=0x{code:08X} {unknown}"),
            "ordinary failure leaked capture"
        );
    }
    for status in [0, 1, 0x40000003] {
        registry_condition(status, 0)?;
    }
    registry_condition(0xc0000022u32 as i32, 0xc0000022u32 as i32)?;
    for (actual, expected) in [(-1, 0), (0, 0xc0000022u32 as i32), (0, 1)] {
        ensure!(
            registry_condition(actual, expected).is_err(),
            "registry condition was not qualified"
        );
    }
    ensure!(
        creation_flags(false) == 0x8040c && creation_flags(true) == 0x8040e,
        "contained launch flags differ"
    );
    ensure!(
        module_role(3, Some(0xc0000022u32 as i32), Some(0xc0000022))?
            && !module_role(0, None, None)?
            && !module_role(1, Some(0), None)?
            && !module_role(2, Some(0), None)?,
        "fixed module role separation failed"
    );
    for role in [-1, 0, 1, 2, 4] {
        ensure!(
            module_role(role, Some(0), Some(0xc0150002)).is_err(),
            "callback exit accepted by unrelated role"
        );
    }
    for code in [None, Some(0), Some(121), Some(0x7fffffff), Some(0xc0150002)] {
        ensure!(
            module_role(3, Some(0xc0000022u32 as i32), code).is_err(),
            "callback role accepted unqualified exit"
        );
    }
    for registry in [None, Some(0), Some(1)] {
        ensure!(
            module_role(3, registry, Some(0xc0000022)).is_err(),
            "callback role escaped registry condition"
        );
    }
    let primary = failure("fixed primary fixture");
    for callback in [false, true] {
        for destroyed in [false, true] {
            let result = completion_failure(Some(primary.clone()), vec![], callback, destroyed);
            ensure!(
                result.is_some() == (callback && destroyed),
                "diagnostic failure qualification differs"
            );
            if let Some(result) = result {
                let qualified = result
                    .downcast_ref::<QualifiedModuleCallbackFailure>()
                    .unwrap();
                ensure!(
                    Arc::ptr_eq(&qualified.original, &primary),
                    "qualified failure lost original identity"
                );
            }
            ensure!(
                completion_failure(None, vec![], callback, destroyed).is_none(),
                "successful cleanup invented failure"
            );
            let failure = failure("fixed cleanup");
            let group = completion_failure(
                Some(primary.clone()),
                vec![failure.clone()],
                callback,
                destroyed,
            )
            .unwrap();
            let group = group.downcast_ref::<OwnedCleanupFailure>().unwrap();
            ensure!(
                group.errors.len() == 2
                    && Arc::ptr_eq(&group.errors[0], &primary)
                    && Arc::ptr_eq(&group.errors[1], &failure),
                "uncertain cleanup became qualified diagnostic result"
            );
        }
    }
    let mut cleanup = Vec::new();
    let attempts = std::cell::Cell::new(0);
    for fail in [true, true, false] {
        super::attempt(&mut cleanup, || {
            attempts.set(attempts.get() + 1);
            if fail {
                Err(failure("fixed cleanup"))
            } else {
                Ok(())
            }
        });
    }
    let combined = cleanup_failure(Some(primary.clone()), cleanup.clone());
    let combined = combined.downcast_ref::<OwnedCleanupFailure>().unwrap();
    ensure!(
        attempts.get() == 3
            && combined.errors.len() == 3
            && Arc::ptr_eq(&combined.errors[0], &primary)
            && Arc::ptr_eq(&combined.errors[1], &cleanup[0])
            && Arc::ptr_eq(&combined.errors[2], &cleanup[1])
            && cleanup_failure(None, cleanup)
                .downcast_ref::<OwnedCleanupFailure>()
                .unwrap()
                .errors
                .len()
                == 2,
        "owned cleanup lost primary, order, or close attempt"
    );
    Ok(())
}
