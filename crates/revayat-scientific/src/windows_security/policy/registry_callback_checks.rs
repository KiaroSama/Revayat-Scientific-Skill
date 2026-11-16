//! Frozen retained callback, cleanup and fresh-negative-baseline products.
use super::*;
use crate::windows_security::scratch::cleanup::QualifiedModuleCallbackFailure;
use controls::CallbackLatch;
fn pointer(error: &anyhow::Error) -> *const (dyn std::error::Error + Send + Sync) {
    error.as_ref() as *const _
}
fn identical(error: &anyhow::Error, address: *const (dyn std::error::Error + Send + Sync)) -> bool {
    std::ptr::addr_eq(pointer(error), address)
}
fn qualified() -> Result<anyhow::Error> {
    completion::check_callback_completion(fault("fixed callback").0)
}
pub fn check_validation() -> Result<()> {
    for mode in 0..5 {
        let (primary, address) = fault("fixed diagnostic");
        let primary = RefCell::new(Some(primary));
        let qualified = if mode == 1 {
            Some(completion::check_callback_completion(
                primary.borrow_mut().take().unwrap(),
            )?)
        } else {
            None
        };
        let qualified_address = qualified.as_ref().map(pointer);
        let qualified = RefCell::new(qualified);
        let cleanup = completion::check_capture_validation()?;
        let cleanup_address = pointer(&cleanup);
        let cleanup = RefCell::new(Some(cleanup));
        let order = RefCell::new(Vec::<String>::new());
        let visits = Cell::new(0);
        let latch = RefCell::new(CallbackLatch::default());
        let result = (|| {
            let original = after_restoration(
                || {
                    execute_causal(
                        |_| {
                            let label = ["original", "modified", "restored"][visits.get()];
                            visits.set(visits.get() + 1);
                            let mut trace = |exit| {
                                ensure!(label == "original" && exit == DENIED as u32);
                                order.borrow_mut().push("trace".into());
                                match mode {
                                    1 => Err(qualified.borrow_mut().take().unwrap()),
                                    2 => Err(primary.borrow_mut().take().unwrap()),
                                    4 => {
                                        let mut original = primary.borrow_mut().take();
                                        Err(completion::completion_failure(
                                            &mut original,
                                            vec![cleanup.borrow_mut().take().unwrap()],
                                            true,
                                            true,
                                        )
                                        .unwrap())
                                    }
                                    _ => Ok("fixed trace".into()),
                                }
                            };
                            let code = controls::observe_modules(
                                label,
                                |manifest| {
                                    order.borrow_mut().push(format!(
                                        "{label}:{}",
                                        if manifest { "id2" } else { "plain" }
                                    ));
                                    if manifest
                                        && label != "modified"
                                        && !(mode == 3 && label == "original")
                                    {
                                        controls::module_result(true, DENIED as u32, "", "")
                                    } else {
                                        Ok(controls_checks::MODULE_SUCCESS.into())
                                    }
                                },
                                || {
                                    order.borrow_mut().push(format!("{label}:ordinary"));
                                    Ok(DENIED as u32)
                                },
                                |_| Ok(()),
                                Some(&mut trace),
                                Some(&mut latch.borrow_mut()),
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
            ensure!(original == DENIED as u32);
            order.borrow_mut().push("fresh-ordinary".into());
            latch.borrow_mut().require_negative(original)
        })();
        if mode == 2 || mode == 4 {
            ensure!(
                !latch.borrow().pending()
                    && order.borrow().join(",") == "original:plain,original:id2,trace",
                "unqualified callback cleanup advanced into the trial"
            );
            let error = result.unwrap_err();
            if mode == 2 {
                ensure!(same(&error, address), "callback primary changed identity");
            } else {
                let group = error.downcast_ref::<Failures>().unwrap();
                ensure!(
                    group.errors.len() == 2
                        && same(&group.errors[0], address)
                        && identical(&group.errors[1], cleanup_address),
                    "callback cleanup was qualified or changed order"
                );
            }
        } else {
            ensure!(
                order.borrow().join(",")
                    == format!(
                        "original:plain,original:id2,{}original:ordinary,begin,modified:plain,modified:id2,modified:ordinary,restore,restored:plain,restored:id2,restored:ordinary,comparison,query,fresh-ordinary",
                        if mode == 3 { "" } else { "trace," }
                    ),
                "qualified callback blocked restored controls or fresh negative baseline"
            );
            if mode == 0 {
                ensure!(result.is_ok(), "successful callback invented a diagnostic");
            } else {
                let error = result.unwrap_err();
                let carrier = error
                    .downcast_ref::<QualifiedModuleCallbackFailure<anyhow::Error>>()
                    .unwrap();
                if mode == 1 {
                    ensure!(
                        identical(&error, qualified_address.unwrap())
                            && same(&carrier.original, address),
                        "retained callback carrier or original was replaced"
                    );
                }
            }
        }
        ensure!(
            !latch.borrow().pending(),
            "callback latch did not clear after final propagation"
        );
    }
    for later_fails in [false, true] {
        let mut latch = CallbackLatch::default();
        let retained = qualified()?;
        let retained_address = pointer(&retained);
        latch.retain(retained)?;
        let (later, later_address) = fault("fixed subsequent");
        let result = latch
            .preserve(if later_fails { Some(later) } else { None })
            .unwrap();
        if later_fails {
            let group = result.downcast_ref::<Failures>().unwrap();
            ensure!(
                group.errors.len() == 2
                    && identical(&group.errors[0], retained_address)
                    && same(&group.errors[1], later_address),
                "retained diagnostic and later failure changed order/identity"
            );
        } else {
            ensure!(
                identical(&result, retained_address),
                "retained diagnostic was replaced"
            );
        }
        ensure!(!latch.pending() && latch.preserve(None).is_none());
        let (next, next_address) = fault("fixed next");
        ensure!(same(&latch.preserve(Some(next)).unwrap(), next_address));
    }
    for code in [DENIED as u32, 0, 259, 0xC0150002, u32::MAX] {
        let valid = code == DENIED as u32;
        let mut latch = CallbackLatch::default();
        ensure!(latch.require_negative(code).is_ok() == valid);
        let retained = qualified()?;
        let retained_address = pointer(&retained);
        latch.retain(retained)?;
        let error = latch.require_negative(code).unwrap_err();
        if valid {
            ensure!(
                identical(&error, retained_address),
                "valid fresh baseline erased callback diagnostic"
            );
        } else {
            let group = error.downcast_ref::<Failures>().unwrap();
            ensure!(
                group.errors.len() == 2
                    && identical(&group.errors[0], retained_address)
                    && !group.errors[1].is::<QualifiedModuleCallbackFailure<anyhow::Error>>(),
                "negative baseline failure did not retain callback first"
            );
        }
        ensure!(!latch.pending() && latch.preserve(None).is_none());
    }
    Ok(())
}
