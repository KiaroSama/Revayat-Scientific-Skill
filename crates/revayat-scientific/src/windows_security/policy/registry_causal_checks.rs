//! Original causal comparison and nested controlled-observation assertions.
use super::super::causal as controls;
use super::*;
#[path = "registry_callback_checks.rs"]
mod callback_checks;
#[path = "registry_causal_controls_checks.rs"]
mod controls_checks;
pub fn check_validation() -> Result<()> {
    controls_checks::startup()?;
    controls_checks::self_ordering()?;
    controls_checks::module_ordering()?;
    callback_checks::check_validation()?;
    for label in ["original", "modified", "restored"] {
        let line = controls::registry_condition(label, ACTIVATION_DENIED, DENIED as u32)?;
        ensure!(
            line == format!(
                "WINDOWS_REGISTRY_CONDITION condition={label} {ACTIVATION_DENIED} python_exit=0xC0000022 target_admitted=False cause_claimed=False"
            )
        );
    }
    ensure!(controls::registry_condition("other", ACTIVATION_DENIED, 0).is_err());
    for changes in [false, true] {
        let visits = Cell::new(0);
        let order = RefCell::new(Vec::new());
        let report = RefCell::new(String::new());
        let exit = execute_causal(
            |expected| {
                visits.set(visits.get() + 1);
                let visit = visits.get();
                ensure!(expected == if visit == 2 { 0 } else { DENIED });
                order.borrow_mut().push(format!("observe{visit}"));
                Ok(CausalObservation {
                    activation: if visit == 2 && changes {
                        "WINDOWS_CHILD_ACTIVATION created=True win32_error=0x00000000 cause_claimed=False child_equivalence_claimed=False".into()
                    } else {
                        ACTIVATION_DENIED.into()
                    },
                    exit: if visit == 2 && changes {
                        0
                    } else {
                        DENIED as u32
                    },
                })
            },
            || {
                order.borrow_mut().push("begin".into());
                Ok(Trial {
                    restore: Box::new(|| {
                        order.borrow_mut().push("restore".into());
                        Ok(())
                    }),
                    defer: Box::new(|| {
                        order.borrow_mut().push("defer".into());
                        Ok(())
                    }),
                })
            },
            |line| {
                order.borrow_mut().push("emit".into());
                *report.borrow_mut() = line.into();
                Ok(())
            },
        )?;
        ensure!(exit==DENIED as u32&&*order.borrow()==["observe1","begin","observe2","restore","observe3","emit"]&&report.borrow().contains(&format!("activation_changed={} python_exit_changed={}",boolean(changes),boolean(changes)))&&report.borrow().ends_with("restored_baseline=True target_admitted=False cause_claimed=False production_grant=False"),"registry causal comparison altered order or claims");
    }
    for cleanup_fails in [false, true] {
        let visits = Cell::new(0);
        let restored = Cell::new(0);
        let deferred = Cell::new(0);
        let emissions = Cell::new(0);
        let queries = Cell::new(0);
        let (operation, address) = fault("causal operation");
        let operation = RefCell::new(Some(operation));
        let (cleanup, cleanup_address) = fault("causal cleanup");
        let cleanup = RefCell::new(Some(cleanup));
        let error = after_restoration(
            || {
                execute_causal(
                    |_| {
                        visits.set(visits.get() + 1);
                        if visits.get() == 2 {
                            return Err(operation.borrow_mut().take().unwrap());
                        }
                        Ok(CausalObservation {
                            activation: ACTIVATION_DENIED.into(),
                            exit: DENIED as u32,
                        })
                    },
                    || {
                        Ok(Trial {
                            restore: Box::new(|| {
                                restored.set(restored.get() + 1);
                                Ok(())
                            }),
                            defer: Box::new(|| {
                                deferred.set(deferred.get() + 1);
                                if cleanup_fails {
                                    Err(cleanup.borrow_mut().take().unwrap())
                                } else {
                                    Ok(())
                                }
                            }),
                        })
                    },
                    |_| {
                        emissions.set(1);
                        Ok(())
                    },
                )
            },
            || {
                queries.set(1);
                Ok(())
            },
        )
        .unwrap_err();
        ensure!(
            visits.get() == 2
                && restored.get() == 0
                && deferred.get() == 1
                && emissions.get() == 0
                && queries.get() == 0,
            "unqualified causal failure advanced past deferred recovery"
        );
        if cleanup_fails {
            let group = error.downcast_ref::<Failures>().unwrap();
            ensure!(
                group.errors.len() == 2
                    && same(&group.errors[0], address)
                    && same(&group.errors[1], cleanup_address),
                "causal error aggregation changed identity/order"
            );
        } else {
            ensure!(same(&error, address), "causal operation error was replaced");
        }
    }
    for wrong_activation in [false, true] {
        let begins = Cell::new(0);
        ensure!(
            execute_causal(
                |_| Ok(CausalObservation {
                    activation: if wrong_activation {
                        "other".into()
                    } else {
                        ACTIVATION_DENIED.into()
                    },
                    exit: if wrong_activation { DENIED as u32 } else { 0 }
                }),
                || {
                    begins.set(1);
                    Ok(Trial {
                        restore: Box::new(|| Ok(())),
                        defer: Box::new(|| Ok(())),
                    })
                },
                |_| Ok(())
            )
            .is_err()
                && begins.get() == 0,
            "unqualified causal baseline installed policy"
        );
    }
    let order = RefCell::new(Vec::new());
    let visits = Cell::new(0);
    let (primary, address) = fault("fixed evidence");
    let error = after_restoration(
        || {
            execute_causal(
                |_| {
                    visits.set(visits.get() + 1);
                    order.borrow_mut().push(format!("child{}", visits.get()));
                    Ok(CausalObservation {
                        activation: ACTIVATION_DENIED.into(),
                        exit: DENIED as u32,
                    })
                },
                || {
                    Ok(Trial {
                        restore: Box::new(|| {
                            order.borrow_mut().push("restore".into());
                            Ok(())
                        }),
                        defer: Box::new(|| {
                            order.borrow_mut().push("defer".into());
                            Ok(())
                        }),
                    })
                },
                |_| {
                    order.borrow_mut().push("comparison".into());
                    Ok(())
                },
            )
        },
        || {
            order.borrow_mut().push("query".into());
            Err(primary)
        },
    )
    .unwrap_err();
    ensure!(
        same(&error, address)
            && order.borrow().join(",") == "child1,child2,restore,child3,comparison,query",
        "evidence ran before restoration or changed its failure"
    );
    Ok(())
}
