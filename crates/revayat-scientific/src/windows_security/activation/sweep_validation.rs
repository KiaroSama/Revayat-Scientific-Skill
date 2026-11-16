//! Original ManualActivationComparison.CheckValidation matrices using the shared operation seam.
use super::*;
use std::{
    cell::{Cell, RefCell},
    fmt,
    sync::Arc,
};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Manual,
    Explicit,
    Dll,
}
impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::Manual => "WINDOWS_MANUAL_ACTIVATION",
            Self::Explicit => "WINDOWS_EXPLICIT_ID2_ACTIVATION",
            Self::Dll => "WINDOWS_DLL_RESOURCE_ACTIVATION",
        }
    }
    fn flag(self) -> &'static str {
        match self {
            Self::Manual => "manual_only=True",
            Self::Explicit => "explicit_id2_only=True",
            Self::Dll => "dll_file_request_only=True",
        }
    }
    fn success(self) -> String {
        if self == Self::Dll {
            dll_request::SUCCESS.into()
        } else {
            format!(
                "{} entry_reached=True created=True win32_error=0x00000000",
                self.label()
            )
        }
    }
    fn denial(self) -> String {
        if self == Self::Dll {
            dll_request::DENIAL.into()
        } else {
            format!(
                "{} entry_reached=True created=False win32_error=0x00000005",
                self.label()
            )
        }
    }
}
fn run<'a>(
    kind: Kind,
    observe: impl FnMut(&str, i32) -> Result<String>,
    begin: impl FnOnce() -> Result<Trial<'a>>,
    emit: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    match kind {
        Kind::Manual => execute_manual(1, observe, begin, emit),
        Kind::Explicit => execute_manual(2, observe, begin, emit),
        Kind::Dll => execute_dll(observe, begin, emit),
    }
}
/// Runs the exact original success/difference products, twelve failure positions for each role,
/// and rejection of invalid/manual-original role values before any observation or lease effect.
pub fn check_manual_activation_validation() -> Result<()> {
    dll_request::check_wire_validation()?;
    for kind in [Kind::Manual, Kind::Explicit, Kind::Dll] {
        check_positive(kind)?;
        check_faults(kind)?;
    }
    for role in [-1, 0, 3, i32::MAX] {
        let effects = Cell::new(0);
        let result = execute_manual(
            role,
            |_, _| {
                effects.set(effects.get() + 1);
                Ok(Kind::Manual.denial())
            },
            || {
                effects.set(effects.get() + 1);
                anyhow::bail!("unexpected invalid-role lease")
            },
            |_| {
                effects.set(effects.get() + 1);
                Ok(())
            },
        );
        ensure!(
            result.is_err() && effects.get() == 0,
            "invalid independent activation role reached an effect"
        );
    }
    Ok(())
}
fn check_positive(kind: Kind) -> Result<()> {
    for original_success in [false, true] {
        for changed in [false, true] {
            let original = if original_success {
                kind.success()
            } else {
                kind.denial()
            };
            let different = if original_success {
                kind.denial()
            } else {
                kind.success()
            };
            let order = RefCell::new(Vec::<String>::new());
            let visits = Cell::new(0);
            let expected = format!(
                "{}_DIFFERENTIAL original_restored_equal=True result_changed={} {} target_admitted=False cause_claimed=False python_equivalence_claimed=False production_grant=False",
                kind.label(),
                if changed { "True" } else { "False" },
                kind.flag()
            );
            run(
                kind,
                |condition, exit| {
                    ensure!(
                        exit == if condition == "modified" { 0 } else { DENIED },
                        "activation sweep expected exit differs"
                    );
                    visits.set(visits.get() + 1);
                    order.borrow_mut().push(if kind == Kind::Dll {
                        condition.into()
                    } else {
                        format!("{condition}:clean")
                    });
                    Ok(if changed && condition == "modified" {
                        different.clone()
                    } else {
                        original.clone()
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
                    let differential = line.starts_with(&format!("{}_DIFFERENTIAL ", kind.label()));
                    order
                        .borrow_mut()
                        .push(if kind == Kind::Dll || !differential {
                            "emit".into()
                        } else {
                            "comparison".into()
                        });
                    if differential {
                        ensure!(line == expected, "activation differential metadata differs");
                    } else {
                        ensure!(line.starts_with(&format!("{}_CONDITION condition=",kind.label()))
                && line.ends_with("python_equivalence_claimed=False cause_claimed=False production_grant=False"),"activation condition metadata differs");
                    }
                    Ok(())
                },
            )?;
            if kind != Kind::Dll {
                order.borrow_mut().push("main".into());
            }
            let expected_order: &[&str] = if kind == Kind::Dll {
                &[
                    "original", "emit", "begin", "modified", "emit", "restore", "restored", "emit",
                    "emit",
                ]
            } else {
                &[
                    "original:clean",
                    "emit",
                    "begin",
                    "modified:clean",
                    "emit",
                    "restore",
                    "restored:clean",
                    "emit",
                    "comparison",
                    "main",
                ]
            };
            ensure!(
                visits.get() == 3 && *order.borrow() == expected_order,
                "activation success/restoration order differs"
            );
        }
    }
    Ok(())
}
#[derive(Debug)]
struct Marker {
    name: &'static str,
}
#[derive(Debug)]
struct Witness(Arc<Marker>);
impl fmt::Display for Witness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0.name)
    }
}
impl std::error::Error for Witness {}
fn witness(value: &Arc<Marker>) -> anyhow::Error {
    Witness(value.clone()).into()
}
fn is_witness(error: &anyhow::Error, value: &Arc<Marker>) -> bool {
    error
        .downcast_ref::<Witness>()
        .is_some_and(|error| Arc::ptr_eq(&error.0, value))
}
fn owner_address(error: &anyhow::Error) -> *const () {
    let inner: &(dyn std::error::Error + Send + Sync) = error.as_ref();
    (inner as *const (dyn std::error::Error + Send + Sync)).cast::<()>()
}
fn check_faults(kind: Kind) -> Result<()> {
    let primary = Arc::new(Marker {
        name: if kind == Kind::Dll {
            "fixed DLL sweep operation"
        } else {
            "fixed manual operation"
        },
    });
    let recovery = Arc::new(Marker {
        name: if kind == Kind::Dll {
            "fixed DLL sweep recovery"
        } else {
            "fixed manual recovery"
        },
    });
    let strict = super::super::capture::check_strict_cleanup()?;
    let strict_address = owner_address(&strict);
    let mut strict = Some(strict);
    for mode in 0..12 {
        let visits = Cell::new(0);
        let begins = Cell::new(0);
        let restores = Cell::new(0);
        let defers = Cell::new(0);
        let emits = Cell::new(0);
        let later = Cell::new(0);
        let result = (|| {
            run(
                kind,
                |condition, exit| {
                    visits.set(visits.get() + 1);
                    ensure!(
                        exit == if condition == "modified" { 0 } else { DENIED },
                        "activation fault expected exit differs"
                    );
                    let visit = visits.get();
                    if mode == 0 && visit == 1
                        || matches!(mode, 3 | 11) && visit == 2
                        || mode == 8 && visit == 3
                    {
                        return Err(witness(&primary));
                    }
                    if mode == 4 && visit == 2 {
                        return Ok("private-sentinel".into());
                    }
                    if mode == 5 && visit == 2 {
                        return Err(strict
                            .take()
                            .ok_or_else(|| anyhow::anyhow!("strict capture failure reused"))?);
                    }
                    Ok(if mode == 9 && visit == 3 {
                        kind.success()
                    } else {
                        kind.denial()
                    })
                },
                || {
                    begins.set(begins.get() + 1);
                    if mode == 2 {
                        return Err(witness(&primary));
                    }
                    Ok(Trial {
                        restore: Box::new(|| {
                            restores.set(restores.get() + 1);
                            if mode == 7 {
                                return Err(witness(&recovery));
                            }
                            Ok(())
                        }),
                        defer: Box::new(|| {
                            defers.set(defers.get() + 1);
                            if mode == 11 {
                                return Err(witness(&recovery));
                            }
                            Ok(())
                        }),
                    })
                },
                |_| {
                    emits.set(emits.get() + 1);
                    if mode == 1 && emits.get() == 1
                        || mode == 6 && emits.get() == 2
                        || mode == 10 && emits.get() == 4
                    {
                        return Err(witness(&primary));
                    }
                    Ok(())
                },
            )?;
            later.set(later.get() + 1);
            Ok(())
        })();
        let error = result
            .err()
            .ok_or_else(|| anyhow::anyhow!("activation fault reached continuation"))?;
        ensure!(
            later.get() == 0,
            "activation fault reached later diagnostics"
        );
        if mode <= 2 {
            ensure!(
                visits.get() == 1
                    && begins.get() == usize::from(mode == 2)
                    && restores.get() == 0
                    && defers.get() == 0,
                "activation early failure changed registry policy"
            );
        }
        if (3..=6).contains(&mode) || mode == 11 {
            ensure!(
                visits.get() == 2 && begins.get() == 1 && restores.get() == 0 && defers.get() == 1,
                "activation uncertain modified pass restored or skipped deferral"
            );
        }
        if (7..=10).contains(&mode) {
            ensure!(
                begins.get() == 1
                    && restores.get() == 1
                    && defers.get() == 0
                    && visits.get() == if mode == 7 { 2 } else { 3 },
                "activation qualified pass restoration order differs"
            );
        }
        if matches!(mode, 0 | 1 | 2 | 3 | 6 | 8 | 10) {
            ensure!(
                is_witness(&error, &primary),
                "activation original operation failure was replaced"
            );
        }
        if mode == 5 {
            ensure!(
                owner_address(&error) == strict_address,
                "strict capture cleanup failure was replaced or qualified"
            );
        }
        if mode == 7 {
            ensure!(
                is_witness(&error, &recovery),
                "activation restoration failure was replaced"
            );
        }
        if mode == 4 {
            ensure!(
                error.to_string()
                    == if kind == Kind::Dll {
                        "fixed DLL resource request contract failed"
                    } else {
                        "fixed self activation contract failed"
                    },
                "activation invalid-result refusal differs"
            );
        }
        if mode == 9 {
            ensure!(
                error.to_string() == "fixed manual activation comparison contract failed",
                "activation restored mismatch refusal differs"
            );
        }
        if mode == 11 {
            let group = error
                .downcast_ref::<Failures>()
                .ok_or_else(|| anyhow::anyhow!("activation operation/recovery group missing"))?;
            ensure!(
                group.errors.len() == 2
                    && is_witness(&group.errors[0], &primary)
                    && is_witness(&group.errors[1], &recovery),
                "activation operation/recovery errors reordered or replaced"
            );
        }
    }
    ensure!(
        strict.is_none(),
        "activation strict-capture fault did not execute"
    );
    Ok(())
}
