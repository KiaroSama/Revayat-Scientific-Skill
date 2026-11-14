use super::*;
use std::sync::Arc;
#[derive(Clone, Debug)]
struct Named(Arc<str>);
impl std::fmt::Display for Named {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_ref())
    }
}
impl std::error::Error for Named {}
fn named(id: &Arc<str>) -> anyhow::Error {
    Named(id.clone()).into()
}
fn same(error: &anyhow::Error, id: &Arc<str>) -> bool {
    error
        .downcast_ref::<Named>()
        .is_some_and(|e| Arc::ptr_eq(&e.0, id))
}
fn group(error: &anyhow::Error) -> Result<&[anyhow::Error]> {
    Ok(&error
        .downcast_ref::<Failures>()
        .ok_or_else(|| anyhow::anyhow!("ordered entry failure group absent"))?
        .errors)
}
fn address(error: &anyhow::Error) -> usize {
    let value: &(dyn std::error::Error + Send + Sync) = error.as_ref();
    value as *const _ as *const () as usize
}
pub fn check_validation() -> Result<()> {
    super::super::diagnostics::check_validation()?;
    resource_checks()?;
    check_entry_comparison()?;
    let resource = Arc::<str>::from("fixed resource diagnostic");
    let entry = Arc::<str>::from("fixed entry diagnostic");
    let undebugged = Arc::<str>::from("fixed undebugged diagnostic");
    let later = Cell::new(0);
    let caught = execute_trace(
        || {
            finish_trace(
                Some(named(&resource)),
                vec![],
                true,
                true,
                || Ok("fixed resource".into()),
                |_| Ok(()),
            )
        },
        || {
            later.set(later.get() + 1);
            execute_trace(
                || {
                    finish_trace(
                        Some(named(&entry)),
                        vec![],
                        true,
                        true,
                        || Ok("fixed entry".into()),
                        |_| Ok(()),
                    )
                },
                || {
                    later.set(later.get() + 1);
                    Err(named(&undebugged))
                },
            )
        },
    )
    .unwrap_err();
    let outer = group(&caught)?;
    let inner = group(&outer[1])?;
    ensure!(
        later.get() == 2
            && outer.len() == 2
            && same(&outer[0], &resource)
            && inner.len() == 2
            && same(&inner[0], &entry)
            && same(&inner[1], &undebugged),
        "resource/entry/undebugged failure precedence differs"
    );
    Ok(())
}
fn check_entry_comparison() -> Result<()> {
    super::super::entry::check_explicit_entry_validation()?;
    super::super::entry::check_entry_event_validation()?;
    super::super::fixtures::self_host::check_entry_host_validation()?;
    let primary = Arc::<str>::from("fixed entry observation");
    let later = Arc::<str>::from("fixed undebugged observation");
    let mut cleanup = Some(super::super::capture::check_strict_cleanup()?);
    let cleanup_address = address(cleanup.as_ref().unwrap());
    for mode in 0..7 {
        let order = RefCell::new(Vec::new());
        let result = execute_trace(
            || {
                order.borrow_mut().push("trace");
                match mode {
                    4 => Err(named(&primary)),
                    5 => finish_trace(
                        Some(named(&primary)),
                        vec![cleanup.take().unwrap()],
                        true,
                        true,
                        || Ok("fixed".into()),
                        |_| Ok(()),
                    ),
                    6 => finish_trace(
                        Some(named(&primary)),
                        vec![],
                        true,
                        false,
                        || Ok("fixed".into()),
                        |_| Ok(()),
                    ),
                    1 | 3 => finish_trace(
                        Some(named(&primary)),
                        vec![],
                        true,
                        true,
                        || Ok("fixed".into()),
                        |_| Ok(()),
                    ),
                    _ => Ok(()),
                }
            },
            || {
                order.borrow_mut().push("undebugged");
                if mode == 2 || mode == 3 {
                    return Err(named(&later));
                }
                Ok(())
            },
        );
        if result.is_ok() {
            order.borrow_mut().push("main");
        }
        ensure!(
            order.borrow().as_slice()
                == if mode == 0 {
                    &["trace", "undebugged", "main"][..]
                } else if mode <= 3 {
                    &["trace", "undebugged"][..]
                } else {
                    &["trace"][..]
                },
            "entry trace/undebugged/main ordering differs"
        );
        if mode == 0 {
            result?;
        } else {
            let caught = result.unwrap_err();
            match mode {
                1 | 4 | 6 => ensure!(same(&caught, &primary), "entry primary identity replaced"),
                2 => ensure!(
                    same(&caught, &later),
                    "undebugged failure identity replaced"
                ),
                3 | 5 => {
                    let errors = group(&caught)?;
                    ensure!(
                        errors.len() == 2
                            && same(&errors[0], &primary)
                            && (if mode == 3 {
                                same(&errors[1], &later)
                            } else {
                                address(&errors[1]) == cleanup_address
                            }),
                        "entry primary/cleanup ordering differs"
                    );
                }
                _ => unreachable!(),
            }
        }
    }
    let emitted = Cell::new(0);
    finish_trace(
        None,
        vec![],
        true,
        true,
        || Ok("fixed".into()),
        |_| {
            emitted.set(emitted.get() + 1);
            Ok(())
        },
    )?;
    ensure!(emitted.get() == 1, "entry qualified metadata count differs");
    let reporting = Arc::<str>::from("fixed entry report");
    let qualified = finish_trace(
        Some(named(&primary)),
        vec![],
        true,
        true,
        || Ok("fixed".into()),
        |_| Err(named(&reporting)),
    )
    .unwrap_err();
    let carrier = qualified
        .downcast_ref::<super::super::dispatch::QualifiedFailure>()
        .unwrap();
    let errors = group(carrier.original())?;
    ensure!(
        same(&errors[0], &primary) && same(&errors[1], &reporting),
        "entry primary/reporting error order differs"
    );
    ensure!(
        !finish_trace(
            Some(named(&primary)),
            vec![],
            false,
            false,
            || Ok("fixed".into()),
            |_| {
                emitted.set(emitted.get() + 1);
                Ok(())
            }
        )
        .unwrap_err()
        .is::<super::super::dispatch::QualifiedFailure>(),
        "unobserved entry became qualified"
    );
    let order = RefCell::new(Vec::new());
    let caught = execute_trace(
        || {
            order.borrow_mut().push("created");
            finish_trace(
                Some(named(&primary)),
                vec![],
                false,
                true,
                || Ok("fixed".into()),
                |_| {
                    order.borrow_mut().push("metadata");
                    Ok(())
                },
            )
        },
        || {
            order.borrow_mut().push("undebugged");
            Ok(())
        },
    )
    .unwrap_err();
    ensure!(
        same(&caught, &primary) && order.borrow().as_slice() == ["created"],
        "entry prerequisites emitted metadata or ran later diagnostics"
    );
    Ok(())
}
