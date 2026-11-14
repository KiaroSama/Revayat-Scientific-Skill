use super::transitions::{Fault, FixtureIo, prepared};
use super::*;
use std::{cell::RefCell, rc::Rc};
pub fn check_validation() -> Result<()> {
    transport()?;
    transitions::check()?;
    comparison()?;
    retention()?;
    all_retention()?;
    super::super::launch_roles::check_preparation_roles()?;
    Ok(())
}
fn transport() -> Result<()> {
    for host in [false, true] {
        for condition in [
            Condition::Baseline,
            Condition::ChildCreate,
            Condition::BaselineAgain,
        ] {
            for exit in [0, 1, 121, 0xc0000022, 0xc0150002, u32::MAX] {
                let mut value = prepared(
                    condition,
                    if host {
                        Experiment::Host
                    } else {
                        Experiment::Token
                    },
                    true,
                )?;
                value.record(exit, "", "")?;
                let metadata = value.metadata()?;
                ensure!(
                    value.recorded
                        && value.exit == exit
                        && value.completed == (exit == 0)
                        && metadata.contains(&format!("raw_process_exit=0x{exit:08X}"))
                        && metadata.contains(&format!("pass_code_completed={}", b(exit == 0)))
                        && metadata.contains(&format!(
                            "activation_attempted={}",
                            b(condition == Condition::ChildCreate)
                        ))
                        && metadata.ends_with(
                            "cause_claimed=False target_admitted=False production_grant=False"
                        )
                        && metadata.len() < 512
                        && !metadata.contains("S-1-")
                        && !metadata.contains('\\')
                        && !metadata.contains("private-sentinel"),
                    "preparation transport metadata differs"
                );
                ensure!(
                    value.record(exit, "", "").is_err(),
                    "preparation record repeated"
                );
                value.clear();
                ensure!(
                    !value.policy_retained(),
                    "preparation baseline retained after clear"
                );
            }
        }
    }
    let mut denied = prepared(Condition::ChildCreate, Experiment::Token, false)?;
    denied.record(0xc0150002, "", "")?;
    denied.clear();
    ensure!(
        Condition::try_from(3).is_err()
            && Experiment::try_from(4).is_err()
            && Observation::new(Condition::Baseline, Experiment::Token)
                .record(0, "", "")
                .is_err(),
        "invalid/fresh preparation accepted"
    );
    for error in [false, true] {
        let mut value = prepared(Condition::Baseline, Experiment::Token, true)?;
        let error = value
            .record(
                0,
                if error { "" } else { "private-sentinel" },
                if error { "private-sentinel" } else { "" },
            )
            .unwrap_err();
        ensure!(
            !error.to_string().contains("private-sentinel"),
            "private pass stream escaped refusal"
        );
        value.clear();
    }
    let mut missing = Observation::new(Condition::ChildCreate, Experiment::Token);
    prepare_token(&mut missing, &mut FixtureIo::new(Experiment::Token))?;
    ensure!(
        missing.record(0, "", "").is_err(),
        "preparation missing activation accepted"
    );
    for line in [
        DENIED.to_owned(),
        format!("{CREATED}\n"),
        "private-sentinel".into(),
        CREATED.replace("win32_error=0", "win32_error=1"),
    ] {
        ensure!(
            missing.activation(&line).is_err(),
            "invalid preparation activation grammar accepted"
        );
    }
    missing.activation(CREATED)?;
    ensure!(
        missing.activation(CREATED).is_err(),
        "preparation activation repeated"
    );
    missing.record(0, "", "")?;
    missing.clear();
    let mut baseline = prepared(Condition::Baseline, Experiment::Token, true)?;
    ensure!(
        baseline.activation(CREATED).is_err(),
        "baseline activation accepted"
    );
    baseline.clear();
    Ok(())
}
fn comparison() -> Result<()> {
    for kind in [
        Experiment::Token,
        Experiment::Host,
        Experiment::Image,
        Experiment::ActivationBundle,
    ] {
        for mode in 0..8 {
            let order = Rc::new(RefCell::new(Vec::<String>::new()));
            let policies = RefCell::new(Vec::new());
            let mut visits = 0;
            let mut reports = 0;
            let operation = Arc::new(());
            let reporting = Arc::new(());
            let cleanup = Arc::new(());
            let restored = order.clone();
            let deferred = order.clone();
            let result = execute_comparison(
                kind,
                |value| {
                    visits += 1;
                    order.borrow_mut().push(value.condition.name().into());
                    if mode == 4 && visits == 2 {
                        return Err(Fault(operation.clone()).into());
                    }
                    let mut io = FixtureIo::new(kind);
                    if kind == Experiment::Token {
                        prepare_token(value, &mut io)?;
                    } else {
                        prepare_host(value, &mut io)?;
                    }
                    if value.call_expected() && !value.compound() {
                        value.activation(&if kind == Experiment::Host {
                            CREATED.replace("context=lpac", "context=host")
                        } else {
                            CREATED.into()
                        })?;
                    }
                    value.record(
                        if mode == 0 || mode == 2 && visits == 2 || mode == 3 && visits != 1 {
                            0
                        } else {
                            0xc0150002
                        },
                        "",
                        "",
                    )?;
                    if mode == 7 && visits == 2 {
                        value.baseline.as_ref().unwrap().0.lock().unwrap()[0] = 4;
                    }
                    policies
                        .borrow_mut()
                        .push(value.baseline.as_ref().unwrap().clone());
                    Ok(())
                },
                || {
                    order.borrow_mut().push("begin".into());
                    Ok(Trial {
                        restore: Box::new(|| {
                            restored.borrow_mut().push("restore".into());
                            if mode == 6 {
                                return Err(Fault(cleanup.clone()).into());
                            }
                            Ok(())
                        }),
                        defer: Box::new(|| {
                            deferred.borrow_mut().push("defer".into());
                            Ok(())
                        }),
                    })
                },
                |_| {
                    reports += 1;
                    order.borrow_mut().push("emit".into());
                    if mode == 5 {
                        return Err(Fault(reporting.clone()).into());
                    }
                    Ok(())
                },
            );
            ensure!(
                policies.borrow().iter().all(PolicyBuffer::cleared),
                "comparison retained raw policy after recovery"
            );
            if mode <= 3 {
                let diagnostic = result?;
                ensure!(
                    visits == 3
                        && reports == 5
                        && order.borrow().contains(&"restore".into())
                        && diagnostic.is_none() == (mode == 0),
                    "preparation clean comparison differs"
                );
            } else {
                let error = result.unwrap_err();
                ensure!(
                    error.is::<super::super::Failures>()
                        && order.borrow().contains(&if mode == 4 {
                            "defer".into()
                        } else {
                            "restore".into()
                        })
                        && !order.borrow().contains(&if mode == 4 {
                            "restore".into()
                        } else {
                            "defer".into()
                        }),
                    "preparation recovery qualification differs"
                );
                if mode == 4 {
                    ensure!(
                        visits == 2 && order.borrow().last().map(String::as_str) == Some("defer"),
                        "uncertain preparation continued"
                    );
                }
                if mode == 5 || mode == 6 {
                    let errors = &error
                        .downcast_ref::<super::super::Failures>()
                        .unwrap()
                        .errors;
                    ensure!(
                        errors.len() == 2
                            && errors[1]
                                .downcast_ref::<Fault>()
                                .is_some_and(|f| Arc::ptr_eq(
                                    &f.0,
                                    if mode == 5 { &reporting } else { &cleanup }
                                )),
                        "preparation operation/cleanup identity order differs"
                    );
                    if mode == 5 {
                        ensure!(visits == 1, "preparation reporter error continued");
                    }
                }
            }
        }
    }
    for success in [false, true] {
        let mut visits = 0;
        let lines = Rc::new(RefCell::new(Vec::new()));
        let restored = lines.clone();
        let diagnostic = execute_comparison(
            Experiment::Host,
            |value| {
                visits += 1;
                *value = prepared(value.condition, Experiment::Host, success)?;
                value.record(0, "", "")
            },
            || {
                Ok(Trial {
                    restore: Box::new(|| {
                        restored.borrow_mut().push("restore".to_owned());
                        Ok(())
                    }),
                    defer: Box::new(|| anyhow::bail!("unexpected defer")),
                })
            },
            |line| {
                lines.borrow_mut().push(line.to_owned());
                Ok(())
            },
        )?;
        ensure!(
            visits == 3
                && diagnostic.is_none() == success
                && lines.borrow().len() == 6
                && lines.borrow()[4] == "restore"
                && lines.borrow()[5].starts_with("WINDOWS_PYTHON_HOST_PREPARATION_COMPARISON"),
            "host preparation positive/control/report order differs"
        );
        if !success {
            ensure!(
                diagnostic.unwrap().to_string()
                    == "fixed host activation preparation positive control failed",
                "host preparation diagnostic differs"
            );
        }
    }
    let mut bytes = 0;
    let mut emitted = 0;
    emit_bounded(&"a".repeat(4096), &mut bytes, &mut |_| {
        emitted += 1;
        Ok(())
    })?;
    ensure!(
        bytes == 4096
            && emitted == 1
            && emit_bounded("x", &mut bytes, &mut |_| {
                emitted += 1;
                Ok(())
            })
            .is_err()
            && emitted == 1,
        "preparation exact report budget differs"
    );
    Ok(())
}
fn retention() -> Result<()> {
    let mut retained = RetainedPreparations::default();
    let identities: Vec<_> = (0..5).map(|_| Arc::new(())).collect();
    for (kind, id) in [
        Experiment::Token,
        Experiment::Host,
        Experiment::Image,
        Experiment::ActivationBundle,
    ]
    .into_iter()
    .zip(&identities)
    {
        retained.retain(kind, Some(Fault(id.clone()).into()))?;
    }
    let all = retained
        .preserve(Some(Fault(identities[4].clone()).into()))
        .unwrap();
    let mut cursor = &all;
    for index in (1..5).rev() {
        let errors = &cursor
            .downcast_ref::<super::super::Failures>()
            .ok_or_else(|| anyhow::anyhow!("preparation retention nesting differs"))?
            .errors;
        ensure!(
            errors.len() == 2
                && errors[1]
                    .downcast_ref::<Fault>()
                    .is_some_and(|f| Arc::ptr_eq(&f.0, &identities[index])),
            "preparation retained role identity differs"
        );
        cursor = &errors[0];
    }
    ensure!(
        cursor
            .downcast_ref::<Fault>()
            .is_some_and(|f| Arc::ptr_eq(&f.0, &identities[0]))
            && retained.preserve(None).is_none(),
        "preparation failure was not consumed"
    );
    let returned = retained.preserve(Some(all)).unwrap();
    ensure!(
        returned.is::<super::super::Failures>(),
        "preparation preserve replaced existing failure"
    );
    Ok(())
}
fn all_retention() -> Result<()> {
    use crate::windows_security::policy::registry_comparison::{
        StartupComparison, causal::CallbackLatch, completion as registry_completion,
    };
    for admission in [false, true] {
        let mut startup = StartupComparison::default();
        let mut preparation = RetainedPreparations::default();
        let mut csr = super::super::csr::RetainedFailures::default();
        let mut callback = CallbackLatch::default();
        let ids: Vec<_> = (0..4).map(|_| Arc::new(())).collect();
        preparation.retain(Experiment::Token, Some(Fault(ids[0].clone()).into()))?;
        csr.retain(
            super::super::csr::Role::ExplicitId2,
            Some(Fault(ids[1].clone()).into()),
        )?;
        let qualified =
            registry_completion::check_callback_completion(Fault(ids[2].clone()).into())?;
        callback.retain(qualified)?;
        let caught = preserve_all(
            &mut startup,
            &mut preparation,
            &mut csr,
            &mut callback,
            if admission {
                None
            } else {
                Some(Fault(ids[3].clone()).into())
            },
        )
        .unwrap();
        let outer = &caught
            .downcast_ref::<super::super::Failures>()
            .unwrap()
            .errors;
        let middle = &outer[1]
            .downcast_ref::<super::super::Failures>()
            .unwrap()
            .errors;
        ensure!(
            outer[0]
                .downcast_ref::<Fault>()
                .is_some_and(|f| Arc::ptr_eq(&f.0, &ids[0]))
                && middle[0]
                    .downcast_ref::<Fault>()
                    .is_some_and(|f| Arc::ptr_eq(&f.0, &ids[1])),
            "cross-stage preparation/CSR failure identity differs"
        );
        let carrier = if admission {
            &middle[1]
        } else {
            let inner = &middle[1]
                .downcast_ref::<super::super::Failures>()
                .unwrap()
                .errors;
            ensure!(
                inner[1]
                    .downcast_ref::<Fault>()
                    .is_some_and(|f| Arc::ptr_eq(&f.0, &ids[3])),
                "subsequent failure identity differs"
            );
            &inner[0]
        };
        let original=&carrier.downcast_ref::<crate::windows_security::scratch::cleanup::QualifiedModuleCallbackFailure<anyhow::Error>>().unwrap().original;
        ensure!(
            original
                .downcast_ref::<Fault>()
                .is_some_and(|f| Arc::ptr_eq(&f.0, &ids[2]))
                && preserve_all(
                    &mut startup,
                    &mut preparation,
                    &mut csr,
                    &mut callback,
                    None
                )
                .is_none(),
            "callback identity/retention consumption differs"
        );
        ensure!(
            preserve_all(
                &mut startup,
                &mut preparation,
                &mut csr,
                &mut callback,
                Some(caught)
            )
            .is_some(),
            "idempotent failure preservation discarded cause"
        );
    }
    Ok(())
}
