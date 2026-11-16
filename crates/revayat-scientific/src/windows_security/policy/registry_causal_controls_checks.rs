//! Frozen CheckStartupOrdering/CheckSelfOrdering/CheckModuleOrdering products.
use super::*;
fn address(error: &anyhow::Error) -> *const (dyn std::error::Error + Send + Sync) {
    error.as_ref() as *const _
}
fn same_any(error: &anyhow::Error, pointer: *const (dyn std::error::Error + Send + Sync)) -> bool {
    std::ptr::addr_eq(address(error), pointer)
}
pub fn startup() -> Result<()> {
    const RESULT: &str = "entry_observed=False exit=0xC0000022";
    let order = RefCell::new(Vec::<String>::new());
    let visits = Cell::new(0);
    let exit = after_restoration(
        || {
            execute_causal(
                |expected| {
                    let label = ["original", "modified", "restored"][visits.get()];
                    visits.set(visits.get() + 1);
                    ensure!(expected == if visits.get() == 2 { 0 } else { DENIED });
                    let code = controls::observe_startup(
                        label,
                        || {
                            order.borrow_mut().push(format!("{label}:control-clean"));
                            Ok(RESULT.into())
                        },
                        || {
                            order.borrow_mut().push(format!("{label}:ordinary"));
                            Ok(DENIED as u32)
                        },
                        |line| {
                            ensure!(line == controls::default_condition(label, RESULT)?);
                            order.borrow_mut().push(format!("{label}:emit"));
                            Ok(())
                        },
                    )?;
                    Ok(CausalObservation {
                        activation: ACTIVATION_DENIED.into(),
                        exit: code,
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
                |_| {
                    order.borrow_mut().push("comparison".into());
                    Ok(())
                },
            )
        },
        || {
            order.borrow_mut().push("query".into());
            Ok(())
        },
    )?;
    ensure!(
        exit == DENIED as u32
            && order.borrow().join(",")
                == "original:control-clean,original:emit,original:ordinary,begin,modified:control-clean,modified:emit,modified:ordinary,restore,restored:control-clean,restored:emit,restored:ordinary,comparison,query",
        "registry startup control did not finish before ordinary observation/restoration"
    );
    for cleanup_aggregate in [false, true] {
        let primary = if cleanup_aggregate {
            completion::check_capture_validation()?
        } else {
            fault("fixed control").0
        };
        let pointer = address(&primary);
        let primary = RefCell::new(Some(primary));
        let (observed, ordinary, emitted, restores, deferred, queries) = (
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
        );
        let error = after_restoration(
            || {
                execute_causal(
                    |_| {
                        observed.set(observed.get() + 1);
                        let label = if observed.get() == 1 {
                            "original"
                        } else {
                            "modified"
                        };
                        let code = controls::observe_startup(
                            label,
                            || {
                                if observed.get() == 2 {
                                    return Err(primary.borrow_mut().take().unwrap());
                                }
                                Ok(RESULT.into())
                            },
                            || {
                                ordinary.set(ordinary.get() + 1);
                                Ok(DENIED as u32)
                            },
                            |_| {
                                emitted.set(emitted.get() + 1);
                                Ok(())
                            },
                        )?;
                        Ok(CausalObservation {
                            activation: ACTIVATION_DENIED.into(),
                            exit: code,
                        })
                    },
                    || {
                        Ok(Trial {
                            restore: Box::new(|| {
                                restores.set(restores.get() + 1);
                                Ok(())
                            }),
                            defer: Box::new(|| {
                                deferred.set(deferred.get() + 1);
                                Ok(())
                            }),
                        })
                    },
                    |_| {
                        emitted.set(emitted.get() + 1);
                        Ok(())
                    },
                )
            },
            || {
                queries.set(queries.get() + 1);
                Ok(())
            },
        )
        .unwrap_err();
        ensure!(
            same_any(&error, pointer)
                && observed.get() == 2
                && ordinary.get() == 1
                && emitted.get() == 1
                && restores.get() == 0
                && deferred.get() == 1
                && queries.get() == 0,
            "registry startup failure advanced past cleanup or changed original"
        );
    }
    let later = Cell::new(0);
    ensure!(
        controls::observe_startup(
            "original",
            || Ok("private-sentinel".into()),
            || {
                later.set(1);
                Ok(0)
            },
            |_| Ok(())
        )
        .is_err()
            && later.get() == 0,
        "malformed startup control reached ordinary operation"
    );
    Ok(())
}
pub fn self_ordering() -> Result<()> {
    const SUCCESS: &str =
        "WINDOWS_SELF_ACTIVATION entry_reached=True created=True win32_error=0x00000000";
    let order = RefCell::new(Vec::<String>::new());
    let visits = Cell::new(0);
    let exit = after_restoration(
        || {
            execute_causal(
                |_| {
                    let label = ["original", "modified", "restored"][visits.get()];
                    visits.set(visits.get() + 1);
                    let code = controls::observe_startup(
                        label,
                        || {
                            order.borrow_mut().push(format!("{label}:default"));
                            Ok("entry_observed=True exit=0x00000000".into())
                        },
                        || {
                            controls::observe_self(
                                label,
                                || {
                                    order.borrow_mut().push(format!("{label}:self-clean"));
                                    Ok(if label == "modified" {
                                        SUCCESS.into()
                                    } else {
                                        "completed_wire=False exit=0xC0000022".into()
                                    })
                                },
                                || {
                                    order.borrow_mut().push(format!("{label}:modules-ordinary"));
                                    Ok(DENIED as u32)
                                },
                                |_| {
                                    order.borrow_mut().push(format!("{label}:self-emit"));
                                    Ok(())
                                },
                            )
                        },
                        |_| {
                            order.borrow_mut().push(format!("{label}:default-emit"));
                            Ok(())
                        },
                    )?;
                    Ok(CausalObservation {
                        activation: ACTIVATION_DENIED.into(),
                        exit: code,
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
                |_| {
                    order.borrow_mut().push("comparison".into());
                    Ok(())
                },
            )
        },
        || {
            order.borrow_mut().push("query".into());
            Ok(())
        },
    )?;
    ensure!(
        exit == DENIED as u32
            && order.borrow().join(",")
                == "original:default,original:default-emit,original:self-clean,original:self-emit,original:modules-ordinary,begin,modified:default,modified:default-emit,modified:self-clean,modified:self-emit,modified:modules-ordinary,restore,restored:default,restored:default-emit,restored:self-clean,restored:self-emit,restored:modules-ordinary,comparison,query",
        "self control cleanup/reporting did not precede later registry observations"
    );
    for mode in 0..3 {
        let primary = if mode == 0 {
            fault("fixed self operation").0
        } else {
            completion::check_capture_validation()?
        };
        let pointer = address(&primary);
        let primary = RefCell::new(Some(primary));
        let (observed, later, restores, deferred, queries) = (
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
        );
        let error = after_restoration(
            || {
                execute_causal(
                    |_| {
                        observed.set(observed.get() + 1);
                        let label = if observed.get() == 1 {
                            "original"
                        } else {
                            "modified"
                        };
                        let code = controls::observe_self(
                            label,
                            || {
                                if observed.get() == 2 && mode != 2 {
                                    return Err(primary.borrow_mut().take().unwrap());
                                }
                                Ok(if observed.get() == 2 {
                                    "private-sentinel"
                                } else {
                                    "completed_wire=False exit=0xC0000022"
                                }
                                .into())
                            },
                            || {
                                later.set(later.get() + 1);
                                Ok(DENIED as u32)
                            },
                            |_| Ok(()),
                        )?;
                        Ok(CausalObservation {
                            activation: ACTIVATION_DENIED.into(),
                            exit: code,
                        })
                    },
                    || {
                        Ok(Trial {
                            restore: Box::new(|| {
                                restores.set(restores.get() + 1);
                                Ok(())
                            }),
                            defer: Box::new(|| {
                                deferred.set(deferred.get() + 1);
                                Ok(())
                            }),
                        })
                    },
                    |_| Ok(()),
                )
            },
            || {
                queries.set(queries.get() + 1);
                Ok(())
            },
        )
        .unwrap_err();
        ensure!(
            observed.get() == 2
                && later.get() == 1
                && restores.get() == 0
                && deferred.get() == 1
                && queries.get() == 0
                && (mode == 2 || same_any(&error, pointer))
                && !error.to_string().contains("private-sentinel"),
            "self operation/cleanup failure changed identity or advanced past deferred recovery"
        );
    }
    Ok(())
}
pub const MODULE_SUCCESS: &str = "entry_observed=True association_proved=True exit=0x00000000 WINDOWS_MODULE_ACTIVATION attach=1 query_succeeded=1 root_evaluated=1 root_is_module=1 win32_error=0x00000000 returned_bytes=0x00000080 assembly_count=0x00000003";
pub fn module_ordering() -> Result<()> {
    let order = RefCell::new(Vec::<String>::new());
    let visits = Cell::new(0);
    let exit = after_restoration(
        || {
            execute_causal(
                |_| {
                    let label = ["original", "modified", "restored"][visits.get()];
                    visits.set(visits.get() + 1);
                    let code = controls::observe_modules(
                        label,
                        |manifest| {
                            order.borrow_mut().push(format!(
                                "{label}:{}",
                                if manifest { "id2" } else { "plain" }
                            ));
                            Ok(MODULE_SUCCESS.into())
                        },
                        || {
                            order.borrow_mut().push(format!("{label}:ordinary"));
                            Ok(DENIED as u32)
                        },
                        |_| {
                            order.borrow_mut().push("emit".into());
                            Ok(())
                        },
                        None,
                        None,
                    )?;
                    Ok(CausalObservation {
                        activation: ACTIVATION_DENIED.into(),
                        exit: code,
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
                |_| {
                    order.borrow_mut().push("comparison".into());
                    Ok(())
                },
            )
        },
        || {
            order.borrow_mut().push("query".into());
            Ok(())
        },
    )?;
    ensure!(
        exit == DENIED as u32
            && order.borrow().join(",")
                == "original:plain,emit,original:id2,emit,original:ordinary,begin,modified:plain,emit,modified:id2,emit,modified:ordinary,restore,restored:plain,emit,restored:id2,emit,restored:ordinary,comparison,query",
        "module controls did not precede ordinary/restored registry observations"
    );
    for fail_at in [1, 2] {
        let primary = completion::check_capture_validation()?;
        let pointer = address(&primary);
        let primary = RefCell::new(Some(primary));
        let (calls, ordinary, restores, deferred, queries, observed) = (
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
        );
        let error = after_restoration(
            || {
                execute_causal(
                    |_| {
                        observed.set(observed.get() + 1);
                        let modified = observed.get() == 2;
                        let code = controls::observe_modules(
                            if modified { "modified" } else { "original" },
                            |_| {
                                if modified {
                                    calls.set(calls.get() + 1);
                                    if calls.get() == fail_at {
                                        return Err(primary.borrow_mut().take().unwrap());
                                    }
                                }
                                Ok(MODULE_SUCCESS.into())
                            },
                            || {
                                ordinary.set(ordinary.get() + 1);
                                Ok(DENIED as u32)
                            },
                            |_| Ok(()),
                            None,
                            None,
                        )?;
                        Ok(CausalObservation {
                            activation: ACTIVATION_DENIED.into(),
                            exit: code,
                        })
                    },
                    || {
                        Ok(Trial {
                            restore: Box::new(|| {
                                restores.set(restores.get() + 1);
                                Ok(())
                            }),
                            defer: Box::new(|| {
                                deferred.set(deferred.get() + 1);
                                Ok(())
                            }),
                        })
                    },
                    |_| Ok(()),
                )
            },
            || {
                queries.set(queries.get() + 1);
                Ok(())
            },
        )
        .unwrap_err();
        ensure!(
            same_any(&error, pointer)
                && calls.get() == fail_at
                && ordinary.get() == 1
                && restores.get() == 0
                && deferred.get() == 1
                && queries.get() == 0,
            "module cleanup failure advanced or changed original"
        );
    }
    let later = Cell::new(0);
    ensure!(
        controls::observe_modules(
            "original",
            |_| Ok("private-sentinel".into()),
            || {
                later.set(1);
                Ok(0)
            },
            |_| Ok(()),
            None,
            None
        )
        .is_err()
            && later.get() == 0,
        "malformed module control advanced to ordinary operation"
    );
    Ok(())
}
