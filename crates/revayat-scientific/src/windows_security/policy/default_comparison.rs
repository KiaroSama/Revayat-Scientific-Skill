//! Three-condition default-DACL intervention with exact recovery ownership.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    Baseline,
    UserAllow,
    BaselineAgain,
}
impl Condition {
    pub fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::UserAllow => "user-allow",
            Self::BaselineAgain => "baseline-again",
        }
    }
    pub fn from_index(index: usize) -> Result<Self> {
        match index {
            0 => Ok(Self::Baseline),
            1 => Ok(Self::UserAllow),
            2 => Ok(Self::BaselineAgain),
            _ => anyhow::bail!("unsupported child default-DACL condition"),
        }
    }
}
pub struct Observation {
    pub condition: Condition,
    pub baseline: Option<Vec<u8>>,
    pub opened: bool,
    pub exit: u32,
}
impl Drop for Observation {
    fn drop(&mut self) {
        if let Some(bytes) = self.baseline.as_mut() {
            bytes.fill(0);
        }
    }
}
impl Observation {
    pub fn record(&self) -> String {
        format!(
            "WINDOWS_DEFAULT_DACL_CONDITION condition={} event_fresh_open={} python_exit=0x{:08X} process_job_handle_cleanup=True key_readable=True target_admitted=False production_grant=False cause_claimed=False",
            self.condition.name(),
            if self.opened { "True" } else { "False" },
            self.exit
        )
    }
}
pub struct Lease<'a> {
    pub restore: Box<dyn FnMut() -> Result<()> + 'a>,
    pub defer: Box<dyn FnMut() -> Result<()> + 'a>,
}
pub fn execute<'a>(
    mut observe: impl FnMut(Condition) -> Result<Observation>,
    begin: impl FnOnce() -> Result<Lease<'a>>,
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let mut lease = begin()?;
    let mut values = Vec::<Observation>::new();
    let mut clean = true;
    let operation = (|| {
        for condition in [
            Condition::Baseline,
            Condition::UserAllow,
            Condition::BaselineAgain,
        ] {
            clean = false;
            let value = observe(condition)?;
            clean = true;
            values.push(value);
            let value = values.last().unwrap();
            need(
                value.condition == condition && value.baseline.is_some(),
                "comparison",
                None,
            )?;
            if values.len() > 1 {
                need(
                    child_acl_equal(
                        values[0].baseline.as_ref().unwrap(),
                        value.baseline.as_ref().unwrap(),
                    )?,
                    "comparison",
                    None,
                )?;
            }
            need(
                condition != Condition::UserAllow || value.opened,
                "comparison",
                None,
            )?;
            emit(&value.record())?;
        }
        need(
            values[0].opened == values[2].opened && values[0].exit == values[2].exit,
            "comparison",
            None,
        )
    })();
    let recovery = if clean {
        (lease.restore)()
    } else {
        (lease.defer)()
    };
    match (operation, recovery) {
        (Err(primary), Err(cleanup)) => {
            return Err(Failures {
                errors: vec![primary, cleanup],
            }
            .into());
        }
        (Err(error), _) | (_, Err(error)) => return Err(error),
        _ => {}
    }
    emit(&format!(
        "WINDOWS_DEFAULT_DACL_DIFFERENTIAL startup_changed={} production_grant=False cause_claimed=False",
        if values[0].exit != values[1].exit {
            "True"
        } else {
            "False"
        }
    ))
}

/// The original comparison validator uses the same transaction as native callers.
pub fn check_validation() -> Result<()> {
    use std::cell::{Cell, RefCell};
    let baseline = encode_acl(2, &[])?;
    let order = RefCell::new(Vec::new());
    let count = Cell::new(0);
    execute(
        |condition| {
            count.set(count.get() + 1);
            order.borrow_mut().push(condition.name());
            Ok(Observation {
                condition,
                baseline: Some(baseline.clone()),
                opened: true,
                exit: if condition == Condition::UserAllow {
                    0
                } else {
                    0xc0150002
                },
            })
        },
        || {
            order.borrow_mut().push("begin");
            Ok(Lease {
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
        |_| {
            order.borrow_mut().push("emit");
            Ok(())
        },
    )?;
    need(
        count.get() == 3
            && *order.borrow()
                == [
                    "begin",
                    "baseline",
                    "emit",
                    "user-allow",
                    "emit",
                    "baseline-again",
                    "emit",
                    "restore",
                    "emit",
                ],
        "comparison",
        None,
    )?;
    for fail_at in 0..4 {
        let (visits, restores, deferred) = (Cell::new(0), Cell::new(0), Cell::new(0));
        let result = execute(
            |condition| {
                visits.set(visits.get() + 1);
                if visits.get() == fail_at + 1 {
                    anyhow::bail!("fixed child failure");
                }
                Ok(Observation {
                    condition,
                    baseline: Some(baseline.clone()),
                    opened: true,
                    exit: u32::from(condition == Condition::BaselineAgain),
                })
            },
            || {
                Ok(Lease {
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
        );
        need(
            result.is_err()
                && deferred.get() == usize::from(fail_at < 3)
                && restores.get() == usize::from(fail_at == 3)
                && visits.get() == (fail_at + 1).min(3),
            "comparison",
            None,
        )?;
    }
    #[derive(Debug)]
    struct Marker(std::sync::Arc<()>);
    impl std::fmt::Display for Marker {
        fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            out.write_str("fixed comparison failure")
        }
    }
    impl std::error::Error for Marker {}
    for mode in 0..3 {
        let primary = std::sync::Arc::new(());
        let cleanup = std::sync::Arc::new(());
        let (visits, restores, deferred) = (Cell::new(0), Cell::new(0), Cell::new(0));
        let result = execute(
            |condition| {
                visits.set(visits.get() + 1);
                if mode == 0 {
                    return Err(Marker(primary.clone()).into());
                }
                Ok(Observation {
                    condition,
                    baseline: Some(baseline.clone()),
                    opened: true,
                    exit: 0,
                })
            },
            || {
                Ok(Lease {
                    restore: Box::new(|| {
                        restores.set(restores.get() + 1);
                        if mode == 2 {
                            Err(Marker(cleanup.clone()).into())
                        } else {
                            Ok(())
                        }
                    }),
                    defer: Box::new(|| {
                        deferred.set(deferred.get() + 1);
                        Err(Marker(cleanup.clone()).into())
                    }),
                })
            },
            |_| {
                if mode == 1 {
                    Err(Marker(primary.clone()).into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        if mode == 0 {
            let group = result
                .downcast_ref::<Failures>()
                .context("comparison failures not grouped")?;
            need(
                group.errors.len() == 2
                    && std::sync::Arc::ptr_eq(
                        &group.errors[0]
                            .downcast_ref::<Marker>()
                            .context("comparison primary identity missing")?
                            .0,
                        &primary,
                    )
                    && std::sync::Arc::ptr_eq(
                        &group.errors[1]
                            .downcast_ref::<Marker>()
                            .context("comparison cleanup identity missing")?
                            .0,
                        &cleanup,
                    )
                    && deferred.get() == 1
                    && restores.get() == 0
                    && visits.get() == 1,
                "comparison",
                None,
            )?;
        } else {
            need(
                std::sync::Arc::ptr_eq(
                    &result
                        .downcast_ref::<Marker>()
                        .context("comparison failure identity missing")?
                        .0,
                    if mode == 1 { &primary } else { &cleanup },
                ) && restores.get() == 1
                    && deferred.get() == 0
                    && visits.get() == if mode == 1 { 1 } else { 3 },
                "comparison",
                None,
            )?;
        }
    }
    need(
        Condition::from_index(3).is_err()
            && Observation {
                condition: Condition::Baseline,
                baseline: None,
                opened: false,
                exit: 0xc0150002,
            }
            .record()
            .contains("python_exit=0xC0150002"),
        "comparison",
        None,
    )
}
