use super::*;
use std::{cell::RefCell, rc::Rc, sync::Arc};
#[derive(Clone, Debug)]
struct Marker(Arc<str>);
impl std::fmt::Display for Marker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_ref())
    }
}
impl std::error::Error for Marker {}
fn error(value: &Arc<str>) -> anyhow::Error {
    Marker(value.clone()).into()
}
fn group(error: &anyhow::Error) -> Result<&[anyhow::Error]> {
    Ok(&error
        .downcast_ref::<Failures>()
        .ok_or_else(|| anyhow::anyhow!("expected ordered failure group"))?
        .errors)
}
fn is(error: &anyhow::Error, value: &Arc<str>) -> bool {
    error
        .downcast_ref::<Marker>()
        .is_some_and(|m| Arc::ptr_eq(&m.0, value))
}
fn trial(order: Rc<RefCell<Vec<&'static str>>>, fail: Option<Arc<str>>) -> Trial<'static> {
    let second = order.clone();
    Trial {
        restore: Box::new(move || {
            order.borrow_mut().push("restore");
            if let Some(f) = &fail {
                return Err(error(f));
            }
            Ok(())
        }),
        defer: Box::new(move || {
            second.borrow_mut().push("defer");
            Ok(())
        }),
    }
}
fn wire() -> String {
    format!(
        "{}{}\n",
        self_result::PRE_CALL_RECEIPT,
        SelfRole::ExplicitId2.success()
    )
}
pub fn check_validation() -> Result<()> {
    crate::windows_security::image::check_csr_dispatch_validation()?;
    thread_checks::check()?;
    transport()?;
    host(Role::ExplicitId2, 6)?;
    lifecycle()?;
    Ok(())
}
fn transport() -> Result<()> {
    let good = wire();
    let mut value = Observation::new(false, Role::ExplicitId2);
    value.record(0, &good, "")?;
    ensure!(
        value.receipt && value.completed && value.metadata()?.contains("completed_wire=True"),
        "explicit CSR completed receipt differs"
    );
    let mut value = Observation::new(true, Role::ExplicitId2);
    value.record(0xc0150002, "", "")?;
    ensure!(
        !value.receipt
            && !value.completed
            && value.metadata()?.contains("raw_process_exit=0xC0150002"),
        "explicit CSR failed transport differs"
    );
    for (code, text, errors) in [
        (0, String::new(), ""),
        (1, String::new(), ""),
        (0, self_result::PRE_CALL_RECEIPT.into(), ""),
        (0xc0000022, good.clone(), ""),
        (0, good.replace("True win32_error", "False win32_error"), ""),
        (0, "private-sentinel".into(), ""),
        (0, good.clone(), "private-sentinel"),
        (0, "x".repeat(129), ""),
    ] {
        let result = Observation::new(false, Role::ExplicitId2)
            .record(code, &text, errors)
            .unwrap_err();
        ensure!(
            !result.to_string().contains("private-sentinel"),
            "CSR private input escaped refusal"
        );
    }
    ensure!(
        value.record(0xc0150002, "", "").is_err()
            && !value.metadata()?.contains("private-sentinel"),
        "CSR repeated record accepted"
    );
    Ok(())
}
fn lifecycle() -> Result<()> {
    let operation = Arc::<str>::from("fixed diagnostic");
    let cleanup = Arc::<str>::from("fixed recovery");
    for mode in 0..8 {
        let order = Rc::new(RefCell::new(Vec::new()));
        let seen = order.clone();
        let emitted = order.clone();
        let begin = order.clone();
        let result = execute(
            Role::ExplicitId2,
            |value| {
                seen.borrow_mut().push(if value.traced {
                    "trace-clean"
                } else {
                    "undebugged-clean"
                });
                if mode == 3 && value.traced || mode == 4 && !value.traced {
                    return Err(error(&operation));
                }
                value.record(0xc0150002, "", "")?;
                if mode == 1 && value.traced || mode == 2 || mode == 7 && value.traced {
                    return Err(finish_undebugged(
                        error(&operation),
                        vec![],
                        true,
                        true,
                        true,
                    ));
                }
                Ok(())
            },
            || {
                begin.borrow_mut().push("begin");
                Ok(trial(
                    begin,
                    if mode >= 6 {
                        Some(cleanup.clone())
                    } else {
                        None
                    },
                ))
            },
            |_| {
                emitted.borrow_mut().push("emit");
                ensure!(mode != 5, "fixed report");
                Ok(())
            },
        );
        let order = order.borrow();
        if mode <= 2 {
            let diagnostic = result?;
            ensure!(
                order.as_slice()
                    == [
                        "begin",
                        "trace-clean",
                        "emit",
                        "undebugged-clean",
                        "emit",
                        "restore"
                    ]
                    && diagnostic.is_some() == (mode != 0),
                "CSR clean lifecycle differs"
            );
        } else {
            let caught = result.unwrap_err();
            ensure!(
                order.contains(&"defer") == matches!(mode, 3 | 4)
                    && order.contains(&"restore") == (mode >= 5),
                "CSR recovery selection differs"
            );
            if mode == 7 {
                let errors = group(&caught)?;
                ensure!(
                    errors.len() == 2 && is(&errors[0], &operation) && is(&errors[1], &cleanup),
                    "CSR primary/recovery identity differs"
                );
            }
        }
    }
    let mut retained = RetainedFailures::default();
    retained.retain(Role::ExplicitId2, Some(error(&operation)))?;
    let combined = retained.preserve(Some(error(&cleanup))).unwrap();
    let errors = group(&combined)?;
    ensure!(
        is(&errors[0], &operation) && is(&errors[1], &cleanup) && retained.preserve(None).is_none(),
        "CSR retained failure was not consumed"
    );
    for cleanup_fails in [false, true] {
        let order = Rc::new(RefCell::new(Vec::new()));
        let seen = order.clone();
        let emitted = order.clone();
        let begin = order.clone();
        let result = execute(
            Role::ExplicitId2,
            |value| {
                if value.traced {
                    value.record(0xc0150002, "", "")?;
                    seen.borrow_mut().push("trace-clean");
                    return Ok(());
                }
                let refusal = value
                    .record(0, self_result::PRE_CALL_RECEIPT, "")
                    .unwrap_err();
                ensure!(!value.recorded, "partial CSR wire recorded");
                seen.borrow_mut().push("undebugged-clean");
                Err(finish_undebugged(
                    refusal,
                    if cleanup_fails {
                        vec![error(&cleanup)]
                    } else {
                        vec![]
                    },
                    true,
                    true,
                    true,
                ))
            },
            || Ok(trial(begin, None)),
            |_| {
                emitted.borrow_mut().push("emit");
                Ok(())
            },
        );
        if cleanup_fails {
            ensure!(
                result.is_err()
                    && order.borrow().as_slice()
                        == ["trace-clean", "emit", "undebugged-clean", "defer"],
                "unclean CSR allowed original chain"
            );
        } else {
            ensure!(
                result?.is_some()
                    && order.borrow().as_slice()
                        == ["trace-clean", "emit", "undebugged-clean", "restore"],
                "qualified CSR suppressed later chain"
            );
        }
    }
    for started in [false, true] {
        for signaled in [false, true] {
            for reaped in [false, true] {
                let error = finish_undebugged(error(&operation), vec![], started, signaled, reaped);
                ensure!(
                    error.is::<QualifiedFailure>() == (started && signaled && reaped),
                    "CSR lifetime qualification differs"
                );
            }
        }
    }
    Ok(())
}
pub(super) fn host(role: Role, modes: usize) -> Result<()> {
    for mode in 0..modes {
        let order = RefCell::new(Vec::new());
        let operation = Arc::<str>::from("fixed host");
        let cleanup = Arc::<str>::from("fixed close");
        let result = complete_host(
            role,
            |retain| {
                order.borrow_mut().push("process-clean");
                if mode != 1 {
                    retain("fixed")?;
                }
                if mode == 2 || mode == 7 {
                    return Err(error(&operation));
                }
                Ok(if mode == 6 {
                    if role == Role::Module {
                        module_result(true, 0xc0150002, "", "")?
                    } else {
                        "pass_code_completed=False".into()
                    }
                } else {
                    match role {
                        Role::ExplicitId2 => SelfRole::ExplicitId2.success(),
                        Role::Module => module_result(true, 0, MODULE_WIRE, "")?,
                        Role::PythonPass => HOST_PASS.into(),
                    }
                })
            },
            || {
                order.borrow_mut().push("lease-close");
                if mode == 3 || mode == 7 {
                    return Err(error(&cleanup));
                }
                Ok(())
            },
            |line| {
                order.borrow_mut().push(if line == "fixed" {
                    "metadata"
                } else {
                    "positive"
                });
                ensure!(!(mode == 4 || mode == 5 && line != "fixed"), "fixed report");
                Ok(())
            },
            || {
                order.borrow_mut().push("latch");
                Ok(())
            },
        );
        ensure!(
            result.is_err() == (mode != 0)
                && order.borrow().contains(&"lease-close")
                && order.borrow().contains(&"latch") == (mode == 0),
            "CSR host completion product differs"
        );
        if mode == 0 {
            ensure!(
                order.borrow().as_slice()
                    == [
                        "process-clean",
                        "lease-close",
                        "metadata",
                        "positive",
                        "latch"
                    ],
                "CSR host report order differs"
            );
        }
        if mode == 7 {
            let caught = result.unwrap_err();
            let errors = group(&caught)?;
            ensure!(
                is(&errors[0], &operation) && is(&errors[1], &cleanup),
                "CSR host primary/close identity differs"
            );
        }
    }
    Ok(())
}
pub fn check_module_validation() -> Result<()> {
    for traced in [false, true] {
        let mut value = Observation::new(traced, Role::Module);
        value.record(0, MODULE_WIRE, "")?;
        let metadata = value.metadata()?;
        ensure!(
            value.completed
                && !value.receipt
                && value.characters == MODULE_WIRE.len()
                && metadata
                    .contains("entry_observed=True association_proved=True completed_wire=True")
                && metadata.contains("invocation_module_verified=False")
                && !metadata.contains("pre_call"),
            "module CSR transport differs"
        );
        let mut failed = Observation::new(traced, Role::Module);
        failed.record(0xc0150002, "", "")?;
        ensure!(
            !failed.completed
                && failed
                    .metadata()?
                    .contains("entry_observed=False association_proved=False"),
            "module nonentry transport differs"
        );
        for (code, text, errors) in [
            (0, String::new(), ""),
            (1, String::new(), ""),
            (121, String::new(), ""),
            (0, MODULE_WIRE.trim_end_matches('\n').into(), ""),
            (0, MODULE_WIRE.repeat(2), ""),
            (
                0,
                MODULE_WIRE.replace("root_is_module=1", "root_is_module=0"),
                "",
            ),
            (0, MODULE_WIRE.into(), "private-sentinel"),
            (0xc0150002, MODULE_WIRE.into(), ""),
            (0, "x".repeat(257), ""),
            (0, self_result::PRE_CALL_RECEIPT.into(), ""),
        ] {
            let error = Observation::new(traced, Role::Module)
                .record(code, &text, errors)
                .unwrap_err();
            ensure!(
                !error.to_string().contains("private-sentinel"),
                "module private input escaped"
            );
        }
        ensure!(
            Observation::new(traced, Role::ExplicitId2)
                .record(0, MODULE_WIRE, "")
                .is_err(),
            "module wire crossed explicit role"
        );
    }
    host(Role::Module, 7)?;
    retention()?;
    super::super::launch_roles::check_module_roles()?;
    let first = Arc::<str>::from("fixed explicit failure");
    let second = Arc::<str>::from("fixed module failure");
    for uncertain in [false, true] {
        let order = Rc::new(RefCell::new(Vec::new()));
        let seen = order.clone();
        let emitted = order.clone();
        let begin = order.clone();
        let result = execute(
            Role::Module,
            |value| {
                ensure!(value.role == Role::Module, "module CSR role differs");
                seen.borrow_mut()
                    .push(if value.traced { "trace" } else { "undebugged" });
                if value.traced {
                    return Err(finish_undebugged(
                        error(&first),
                        if uncertain {
                            vec![error(&second)]
                        } else {
                            vec![]
                        },
                        true,
                        true,
                        true,
                    ));
                }
                value.record(0, MODULE_WIRE, "")
            },
            || Ok(trial(begin, None)),
            |_| {
                emitted.borrow_mut().push("emit");
                Ok(())
            },
        );
        if uncertain {
            ensure!(
                result.is_err() && order.borrow().as_slice() == ["trace", "defer"],
                "uncertain module CSR continued"
            );
        } else {
            ensure!(
                result?.is_some_and(|e| is(&e, &first))
                    && order.borrow().as_slice() == ["trace", "undebugged", "emit", "restore"],
                "qualified module CSR lost original"
            );
        }
    }
    Ok(())
}
pub(super) fn retention() -> Result<()> {
    let mut owner = RetainedFailures::default();
    let mut identities = Vec::new();
    for (role, label) in [
        (Role::ExplicitId2, "fixed explicit"),
        (Role::Module, "fixed module"),
        (Role::PythonPass, "fixed Python"),
    ] {
        let id = Arc::<str>::from(label);
        owner.retain(role, Some(error(&id)))?;
        identities.push(id);
    }
    let later = Arc::<str>::from("fixed later");
    let all = owner.preserve(Some(error(&later))).unwrap();
    let outer = group(&all)?;
    let prior = group(&outer[0])?;
    let first = group(&prior[0])?;
    ensure!(
        is(&first[0], &identities[0])
            && is(&first[1], &identities[1])
            && is(&prior[1], &identities[2])
            && is(&outer[1], &later)
            && owner.preserve(None).is_none(),
        "CSR role retention nesting/consumption differs"
    );
    Ok(())
}
pub(super) fn check_python() -> Result<()> {
    for traced in [false, true] {
        for code in [0, 1, 121, 0x7fffffff, 0xc0000022, 0xc0150002, u32::MAX] {
            let mut value = Observation::new(traced, Role::PythonPass);
            value.record(code, "", "")?;
            let line = value.metadata()?;
            ensure!(value.recorded&&value.exit==code&&value.completed==(code==0)&&!value.receipt&&value.characters==0&&line.starts_with(&format!("WINDOWS_PYTHON_CSR_TRANSPORT traced={} raw_process_exit=0x{code:08X}",b(traced)))&&line.contains(&format!("pass_code_completed={}",b(code==0)))&&line.ends_with("cause_claimed=False target_admitted=False production_grant=False undebugged_equivalence_claimed=False")&&!line.contains("private-sentinel")&&!line.contains("C:\\private"),"Python pass transport differs");
            ensure!(
                value.record(code, "", "").is_err()
                    && Observation::new(traced, Role::PythonPass)
                        .record(code, "private-sentinel", "")
                        .is_err()
                    && Observation::new(traced, Role::PythonPass)
                        .record(code, "", "private-sentinel")
                        .is_err(),
                "Python pass repeated/nonempty transport accepted"
            );
        }
    }
    ensure!(
        Observation::from_flags(true, true, true).is_err(),
        "Python/module CSR role aliases"
    );
    host(Role::PythonPass, 8)?;
    for mode in 0..7 {
        let order = Rc::new(RefCell::new(Vec::new()));
        let seen = order.clone();
        let emitted = order.clone();
        let begin = order.clone();
        let operation = Arc::<str>::from("fixed trace");
        let cleanup = Arc::<str>::from("fixed cleanup");
        let result = execute(
            Role::PythonPass,
            |value| {
                seen.borrow_mut()
                    .push(if value.traced { "trace" } else { "undebugged" });
                if value.traced && matches!(mode, 2 | 3) {
                    return Err(finish_undebugged(
                        error(&operation),
                        if mode == 3 {
                            vec![error(&cleanup)]
                        } else {
                            vec![]
                        },
                        true,
                        true,
                        true,
                    ));
                }
                value.record(
                    if mode == 0 || mode == 4 && !value.traced || mode == 5 && value.traced {
                        0
                    } else {
                        0xc0150002
                    },
                    "",
                    "",
                )
            },
            || Ok(trial(begin, None)),
            |_| {
                emitted.borrow_mut().push("emit");
                if mode == 6 {
                    return Err(error(&cleanup));
                }
                Ok(())
            },
        );
        if mode == 3 {
            ensure!(
                result.is_err() && order.borrow().as_slice() == ["trace", "defer"],
                "unclean Python CSR continued"
            );
        } else if mode == 6 {
            let caught = result.unwrap_err();
            let errors = group(&caught)?;
            ensure!(
                errors[0].to_string() == "fixed Python CSR pass failed raw_process_exit=0xC0150002"
                    && is(&errors[1], &cleanup)
                    && order.borrow().as_slice() == ["trace", "emit", "restore"],
                "Python CSR/report failure order differs"
            );
        } else {
            let diagnostic = result?;
            ensure!(
                diagnostic.is_some() == (mode != 0)
                    && order.borrow().as_slice()
                        == if mode == 2 {
                            &["trace", "undebugged", "emit", "restore"][..]
                        } else {
                            &["trace", "emit", "undebugged", "emit", "restore"][..]
                        },
                "Python CSR clean comparison differs"
            );
            if matches!(mode, 4 | 5) {
                ensure!(
                    diagnostic.unwrap().to_string()
                        == "fixed Python CSR pass failed raw_process_exit=0xC0150002",
                    "Python pass diagnostic differs"
                );
            }
        }
    }
    retention()
}
