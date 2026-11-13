//! Original registry comparison assertion products, executed through their shared operations.
use super::*;
use std::cell::{Cell, RefCell};
fn observed(value: &mut StartupObservation, policy: &[u8], exit: u32) -> Result<()> {
    value.prepare(policy, policy)?;
    value.require_policy(policy, policy)?;
    value.read_control(value.condition.expected())?;
    value.stage(exit, Some(""), Some(""))?;
    value.complete()
}
pub(super) fn qualified(error: anyhow::Error) -> anyhow::Error {
    crate::windows_security::activation::dispatch::finish_trace(
        Some(error),
        vec![],
        true,
        true,
        || Ok("fixed".into()),
        |_| Ok(()),
    )
    .unwrap_err()
}
fn flattened<'a>(error: &'a anyhow::Error, values: &mut Vec<&'a anyhow::Error>) {
    if let Some(group) = error.downcast_ref::<Failures>() {
        for error in &group.errors {
            flattened(error, values);
        }
    } else {
        values.push(error);
    }
}
fn fault(label: &'static str) -> (anyhow::Error, *const std::io::Error) {
    let value = anyhow::Error::new(std::io::Error::other(label));
    let address = value.downcast_ref::<std::io::Error>().unwrap() as *const _;
    (value, address)
}
fn same(error: &anyhow::Error, address: *const std::io::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| std::ptr::eq(error, address))
}

pub fn check_startup_validation() -> Result<()> {
    let policy = [2, 0, 8, 0, 0, 0, 0, 0];
    let different = [4, 0, 8, 0, 0, 0, 0, 0];
    for mode in 0..4 {
        let order = RefCell::new(Vec::new());
        let reports = Cell::new(0);
        let diagnostic = execute_startup(
            |value| {
                order.borrow_mut().push(value.condition.label());
                let code = if value.condition == Condition::Readable {
                    if mode == 2 { DENIED as u32 } else { 0 }
                } else if mode == 1 {
                    0
                } else if value.condition == Condition::Restored && mode == 3 {
                    0xc0150002
                } else {
                    DENIED as u32
                };
                observed(value, &policy, code)
            },
            || {
                order.borrow_mut().push("begin");
                Ok(Trial {
                    restore: Box::new(|| {
                        order.borrow_mut().push("restore");
                        Ok(())
                    }),
                    defer: Box::new(|| {
                        order.borrow_mut().push("defer");
                        Ok(())
                    }),
                })
            },
            |line| {
                ensure!(line.len() <= 4096 && !line.contains("private-") && !line.contains("S-1-"));
                reports.set(reports.get() + 1);
                Ok(())
            },
        )?;
        ensure!(
            diagnostic.is_none() == (mode == 0)
                && reports.get() == 4
                && *order.borrow() == ["original", "begin", "readable", "restore", "restored"],
            "registry startup result or order differs"
        );
    }
    for mode in 0..6 {
        let mut value = StartupObservation::new(Condition::Original);
        let result: Result<()> = (|| {
            if mode == 0 {
                value.stage(0, Some(""), Some(""))?;
            }
            value.prepare(&policy, &policy)?;
            if mode == 1 {
                value.prepare(&policy, &policy)?;
            }
            if mode == 2 {
                value.read_control(0)?;
            }
            value.read_control(DENIED)?;
            if mode == 3 {
                value.stage(0, Some("unexpected"), Some(""))?;
            }
            if mode == 4 {
                value.complete()?;
            }
            value.stage(DENIED as u32, Some(""), Some(""))?;
            value.complete()?;
            if mode == 5 {
                value.complete()?;
            }
            Ok(())
        })();
        ensure!(
            result.is_err(),
            "registry observation accepted invalid ordering mode={mode}"
        );
    }
    for mode in 0..4 {
        let mut value = StartupObservation::new(Condition::Original);
        let result = (|| {
            value.prepare(&policy, if mode == 0 { &different } else { &policy })?;
            if mode == 1 {
                value.require_policy(&different, &policy)?;
            }
            if mode == 2 {
                value.require_policy(&policy, &different)?;
            }
            value.read_control(DENIED)?;
            value.stage(1, Some(""), Some(""))?;
            value.complete()?;
            let mut other = StartupObservation::new(Condition::Restored);
            observed(&mut other, &different, 1)?;
            value.equal_policy(&other)
        })();
        ensure!(
            result.is_err(),
            "registry startup policy mismatch accepted mode={mode}"
        );
    }
    let count = Cell::new(0);
    let mut emit = |_: &str| {
        count.set(count.get() + 1);
        Ok(())
    };
    let mut bounded = BoundedEmitter::new(&mut emit);
    bounded.emit(&"a".repeat(4096))?;
    ensure!(
        bounded.emit("x").is_err() && count.get() == 1,
        "registry output budget advanced after rejection"
    );
    for condition in [
        Condition::Original,
        Condition::Readable,
        Condition::Restored,
    ] {
        let value = StartupObservation::new(condition);
        require_role(&value, Some(condition.expected()), true, 0)?;
        for expected in [
            None,
            Some(1),
            Some(if condition == Condition::Readable {
                DENIED
            } else {
                0
            }),
        ] {
            ensure!(
                require_role(&value, expected, true, 0).is_err(),
                "registry startup role accepted wrong expected condition"
            );
        }
        for bit in 0..20 {
            ensure!(
                require_role(&value, Some(condition.expected()), true, 1 << bit).is_err(),
                "registry startup role accepted a conflicting role"
            );
        }
        ensure!(
            require_role(&value, Some(condition.expected()), false, 0).is_err(),
            "untrusted registry role accepted"
        );
    }
    for mode in 0..6 {
        let order = RefCell::new(Vec::new());
        let (operation, address) = fault("fixed operation");
        let operation = RefCell::new(Some(operation));
        let result = execute_startup(
            |value| {
                order.borrow_mut().push(value.condition.label());
                if value.condition == Condition::Readable && mode < 2 {
                    let error = operation.borrow_mut().take().unwrap();
                    return Err(if mode == 1 { qualified(error) } else { error });
                }
                observed(
                    value,
                    &policy,
                    if value.condition == Condition::Readable {
                        0
                    } else {
                        DENIED as u32
                    },
                )?;
                if value.condition == Condition::Restored && mode == 4 {
                    return Err(operation.borrow_mut().take().unwrap());
                }
                Ok(())
            },
            || {
                Ok(Trial {
                    restore: Box::new(|| {
                        order.borrow_mut().push("restore");
                        if mode == 2 {
                            anyhow::bail!("restoration")
                        };
                        Ok(())
                    }),
                    defer: Box::new(|| {
                        order.borrow_mut().push("defer");
                        Ok(())
                    }),
                })
            },
            |line| {
                if mode == 3 && line.contains("condition=readable")
                    || mode == 5 && line.contains("_COMPARISON")
                {
                    return Err(operation.borrow_mut().take().unwrap());
                }
                Ok(())
            },
        );
        let error = result.unwrap_err();
        ensure!(
            order.borrow().contains(&"restored") == (mode >= 4)
                && order.borrow().contains(&"defer") == (mode == 0)
                && order.borrow().contains(&"restore") == (mode != 0),
            "registry startup cleanup qualification differs"
        );
        if mode != 2 {
            ensure!(
                same(&error, address),
                "registry startup replaced original operation failure"
            );
        }
    }
    for mode in 0..8 {
        let order = RefCell::new(Vec::new());
        let (operation, address) = fault("qualified operation");
        let operation = RefCell::new(Some(operation));
        let (restoration, restore_address) = fault("restoration");
        let restoration = RefCell::new(Some(restoration));
        let (reporting, report_address) = fault("reporting");
        let reporting = RefCell::new(Some(reporting));
        let error = execute_startup(
            |value| {
                order.borrow_mut().push(value.condition.label());
                if value.condition == Condition::Readable && [3, 4, 7].contains(&mode) {
                    return Err(qualified(operation.borrow_mut().take().unwrap()));
                }
                let exit = if value.condition == Condition::Readable {
                    if mode < 2 { DENIED as u32 } else { 0 }
                } else if value.condition == Condition::Original && [2, 5, 7].contains(&mode) {
                    0
                } else if value.condition == Condition::Restored && mode == 6 {
                    0xc0150002
                } else {
                    DENIED as u32
                };
                observed(value, &policy, exit)
            },
            || {
                order.borrow_mut().push("begin");
                if mode == 2 {
                    return Err(operation.borrow_mut().take().unwrap());
                }
                Ok(Trial {
                    restore: Box::new(|| {
                        order.borrow_mut().push("restore");
                        if mode == 0 || mode == 4 {
                            return Err(restoration.borrow_mut().take().unwrap());
                        }
                        Ok(())
                    }),
                    defer: Box::new(|| {
                        order.borrow_mut().push("defer");
                        Ok(())
                    }),
                })
            },
            |line| {
                if mode == 1 && line.contains("condition=readable")
                    || mode == 5 && line.contains("condition=original")
                    || mode == 6 && line.contains("condition=restored")
                {
                    return Err(reporting.borrow_mut().take().unwrap());
                }
                Ok(())
            },
        )
        .unwrap_err();
        ensure!(
            !order.borrow().contains(&"defer")
                && order.borrow().contains(&"restored") == (mode == 6),
            "qualified registry startup failure deferred or advanced"
        );
        if mode == 3 {
            ensure!(
                same(&error, address),
                "qualified registry startup replaced original"
            );
            continue;
        }
        let mut failures = Vec::new();
        flattened(&error, &mut failures);
        ensure!(
            failures.len() == 2,
            "registry startup failure census differs"
        );
        if mode == 4 {
            ensure!(
                same(failures[0], address) && same(failures[1], restore_address),
                "registry startup restoration error order differs"
            );
        } else {
            let label = if [2, 5, 7].contains(&mode) {
                "original"
            } else if mode == 6 {
                "restored"
            } else {
                "readable"
            };
            ensure!(
                failures[0]
                    .to_string()
                    .contains(&format!("condition={label}"))
                    && same(
                        failures[1],
                        if mode == 0 {
                            restore_address
                        } else if mode == 2 || mode == 7 {
                            address
                        } else {
                            report_address
                        }
                    ),
                "registry startup lost diagnostic before later error"
            );
        }
    }
    let authority = wire::AuthorityObservation::default();
    authority.require_role(Some(0), true, 0)?;
    for expected in [None, Some(1), Some(DENIED)] {
        ensure!(
            authority.require_role(expected, true, 0).is_err(),
            "authority observation accepted wrong expected role"
        );
    }
    ensure!(
        authority.require_role(Some(0), false, 0).is_err(),
        "authority observation accepted untrusted preflight"
    );
    for bit in 0..20 {
        ensure!(
            authority.require_role(Some(0), true, 1 << bit).is_err(),
            "authority observation accepted a conflicting role"
        );
    }
    let (first, address) = fault("startup diagnostic");
    let (later, later_address) = fault("later operation");
    let mut retained = StartupComparison {
        started: false,
        retained: Some(first),
    };
    let combined = retained.preserve_failure(Some(later)).unwrap();
    let group = combined.downcast_ref::<Failures>().unwrap();
    ensure!(
        group.errors.len() == 2
            && same(&group.errors[0], address)
            && same(&group.errors[1], later_address)
            && retained.preserve_failure(None).is_none(),
        "retained registry startup failure changed identity/order or remained latched"
    );
    let mut session = StartupComparison::default();
    session.run(
        |value| {
            observed(
                value,
                &policy,
                if value.condition() == Condition::Readable {
                    0
                } else {
                    DENIED as u32
                },
            )
        },
        || {
            Ok(Trial {
                restore: Box::new(|| Ok(())),
                defer: Box::new(|| Ok(())),
            })
        },
        |_| Ok(()),
    )?;
    let repeated = Cell::new(0);
    ensure!(
        session
            .run(
                |_| {
                    repeated.set(1);
                    Ok(())
                },
                || {
                    repeated.set(1);
                    Ok(Trial {
                        restore: Box::new(|| Ok(())),
                        defer: Box::new(|| Ok(())),
                    })
                },
                |_| {
                    repeated.set(1);
                    Ok(())
                }
            )
            .is_err()
            && repeated.get() == 0,
        "registry startup comparison repeated after consuming its attempt"
    );
    Ok(())
}

pub fn check_supported_validation() -> Result<()> {
    for mode in 0..5 {
        let order = RefCell::new(Vec::new());
        let (restoration, restore_address) = fault("restore");
        let (compare, compare_address) = fault("compare");
        let result = finish_supported(
            mode != 1 && mode != 2,
            || {
                order.borrow_mut().push("restore");
                if mode == 3 { Err(restoration) } else { Ok(()) }
            },
            || {
                order.borrow_mut().push("defer");
                if mode == 2 {
                    Err(anyhow::anyhow!("restore"))
                } else {
                    Ok(())
                }
            },
            || {
                order.borrow_mut().push("compare");
                if mode == 4 { Err(compare) } else { Ok(()) }
            },
        );
        let expected = if mode == 1 || mode == 2 {
            vec!["defer"]
        } else if mode == 3 {
            vec!["restore"]
        } else {
            vec!["restore", "compare"]
        };
        ensure!(
            *order.borrow() == expected && result.is_ok() == (mode == 0),
            "supported registry restoration gating differs"
        );
        if mode == 3 {
            ensure!(
                same(&result.unwrap_err(), restore_address),
                "supported registry replaced restoration error"
            );
        } else if mode == 4 {
            ensure!(
                same(&result.unwrap_err(), compare_address),
                "supported registry replaced surface error"
            );
        }
    }
    let mut state = SupportedState::default();
    ensure!(
        !state.enter_run(None)? && state.require_readable().is_err(),
        "inactive supported registry role became readable"
    );
    state.activate("fixed-run")?;
    ensure!(
        state.require_available().is_err() && state.enter_run(Some("other-run")).is_err(),
        "nested or foreign supported registry role accepted"
    );
    ensure!(
        state.enter_run(Some("fixed-run"))? && state.enter_run(Some("fixed-run")).is_err(),
        "supported registry nested run accepted"
    );
    state.end_run(true)?;
    state.qualify()?;
    ensure!(
        state.require_readable()? == 0
            && state.scratch_qualified("fixed-run")
            && !state.scratch_qualified("foreign"),
        "supported registry qualification differs"
    );
    state.enter_run(Some("fixed-run"))?;
    state.end_run(false)?;
    ensure!(
        state.require_readable().is_err() && state.enter_run(None).is_err(),
        "uncertain supported cleanup regained admission"
    );
    let restore = Cell::new(0);
    let deferred = Cell::new(0);
    ensure!(
        state
            .finish(
                || {
                    restore.set(1);
                    Ok(())
                },
                || {
                    deferred.set(1);
                    Ok(())
                },
                || Ok(())
            )
            .is_err()
            && restore.get() == 0
            && deferred.get() == 1,
        "uncertain supported policy was restored without qualified cleanup"
    );
    Ok(())
}

pub fn check_authority_validation() -> Result<()> {
    use registry_authority::protocol;
    let primary = protocol::record("primary", 2, 1)
        .map_err(|_| anyhow::anyhow!("fixed authority fixture"))?;
    let child = protocol::record("descendant", 0, 0)
        .map_err(|_| anyhow::anyhow!("fixed authority fixture"))?;
    let text = format!("{primary}{child}");
    wire::validate_wire(0, Some(&text), Some(""))?;
    wire::validate_wire(0, Some(&text.replace('\n', "\r\n")), Some(""))?;
    wire::require_root_only(&text.replace("\"accessible\":1", "\"accessible\":0"))?;
    ensure!(
        wire::require_root_only(&text).is_err(),
        "supported policy accepted immediate child reads"
    );
    wire::validate_wire(
        0,
        Some(
            &text
                .replace("\"accessible\":1", "\"accessible\":256")
                .replace("\"subkeys\":2", "\"subkeys\":256"),
        ),
        Some(""),
    )?;
    let invalid = vec![
        primary.clone(),
        format!("{child}{primary}"),
        format!("{primary}{primary}"),
        format!("{text}\n"),
        text.replace("\"mutation_denied\":true", "\"mutation_denied\":false"),
        text.replace("\"accessible\":1", "\"accessible\":3"),
        text.replace("\"subkeys\":2", "\"subkeys\":257"),
        text.replace(
            "\"read_surface_approved\":false",
            "\"read_surface_approved\":true",
        ),
        text.replace("\"read\":true", "\"read\":true,\"unknown\":0"),
        "x".repeat(2049),
        text.replace("\"accessible\":1", "\"accessible\":-1"),
        text.replace("\"accessible\":1", "\"accessible\":01"),
        text.replace("\"version\":1", "\"version\":2"),
        text.replace("descendant", "descendánt"),
    ];
    for invalid in invalid {
        ensure!(
            wire::validate_wire(0, Some(&invalid), Some("")).is_err(),
            "malformed authority record accepted"
        );
    }
    ensure!(
        wire::validate_wire(0, None, Some("")).is_err(),
        "missing authority record accepted"
    );
    for field in [
        "lpac",
        "mutation_denied",
        "no_reparse",
        "read",
        "restricted",
        "x64",
    ] {
        ensure!(
            wire::validate_wire(
                0,
                Some(&format!(
                    "{primary}{}",
                    child.replace(&format!("\"{field}\":true"), &format!("\"{field}\":false"))
                )),
                Some("")
            )
            .is_err(),
            "authority boolean was unqualified"
        );
    }
    for code in [1, 259, 0xc0000022, u32::MAX] {
        ensure!(
            wire::validate_wire(code, Some(&text), Some("")).is_err(),
            "authority nonzero exit accepted"
        );
    }
    for errors in [Some("x"), None] {
        ensure!(
            wire::validate_wire(0, Some(&text), errors).is_err(),
            "authority missing/error stderr accepted"
        );
    }
    let mut observation = wire::AuthorityObservation::default();
    ensure!(
        observation
            .stage(
                1,
                Some("private-stdout-sentinel"),
                Some("private-error-sentinel")
            )
            .is_err()
            && !observation.recorded()
            && observation.wire().is_none(),
        "failed authority transport became an observation"
    );
    for mode in 0..9 {
        let order = RefCell::new(Vec::new());
        let (operation, address) = fault("authority operation");
        let operation = RefCell::new(Some(operation));
        let (cleanup, cleanup_address) = fault("authority restore");
        let cleanup = RefCell::new(Some(cleanup));
        let result = execute_authority(
            || {
                order.borrow_mut().push("observe");
                if mode == 1 || mode == 2 {
                    return Err(qualified(operation.borrow_mut().take().unwrap()));
                }
                if mode == 3 {
                    return Err(operation.borrow_mut().take().unwrap());
                }
                Ok(())
            },
            || {
                order.borrow_mut().push("begin");
                if mode == 7 {
                    return Err(operation.borrow_mut().take().unwrap());
                }
                Ok(Trial {
                    restore: Box::new(|| {
                        order.borrow_mut().push("restore");
                        if mode == 2 || mode == 8 {
                            return Err(cleanup.borrow_mut().take().unwrap());
                        }
                        Ok(())
                    }),
                    defer: Box::new(|| {
                        order.borrow_mut().push("defer");
                        Ok(())
                    }),
                })
            },
            || {
                order.borrow_mut().push("before");
                if mode == 6 {
                    return Err(operation.borrow_mut().take().unwrap());
                }
                Ok(())
            },
            || {
                order.borrow_mut().push("after");
                if mode == 4 {
                    return Err(operation.borrow_mut().take().unwrap());
                }
                Ok(())
            },
            || {
                order.borrow_mut().push("emit");
                if mode == 5 {
                    return Err(operation.borrow_mut().take().unwrap());
                }
                Ok(())
            },
        );
        ensure!(
            result.is_ok() == (mode == 0)
                && order.borrow().contains(&"defer") == (mode == 3)
                && order.borrow().contains(&"after") == [0, 4, 5].contains(&mode),
            "registry authority transaction order differs"
        );
        if mode == 1 || (3..8).contains(&mode) {
            ensure!(
                same(&result.unwrap_err(), address),
                "registry authority replaced original failure"
            );
        } else if mode == 8 {
            ensure!(
                same(&result.unwrap_err(), cleanup_address),
                "registry authority replaced restoration failure"
            );
        } else if mode == 2 {
            let error = result.unwrap_err();
            let group = error.downcast_ref::<Failures>().unwrap();
            ensure!(
                same(&group.errors[0], address) && same(&group.errors[1], cleanup_address),
                "registry authority aggregate order differs"
            );
        }
    }
    super::surface::check_validation()?;
    wire::check_validation()?;
    super::completion::check_validation()?;
    Ok(())
}

#[path = "registry_causal_checks.rs"]
mod causal;
pub use causal::check_validation as check_causal_validation;
