use super::super::super::storage_policy::{self, PolicyFailure};
use super::*;
pub(super) fn acquisition() -> Result<()> {
    storage_policy::check_validation()?;
    let raw = Arc::new(());
    for acquisition in [true, false] {
        let executed = Cell::new(false);
        let caught = acquired::<()>(
            || {
                if acquisition {
                    return Err(error(&raw));
                }
                Ok(None)
            },
            || Err(error(&raw)),
            || {
                executed.set(true);
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap_err();
        let safe = caught.downcast_ref::<PrivateFailure>().unwrap();
        ensure!(
            same(safe.original(), &raw)
                && !executed.get()
                && !format!("{safe:?}").contains("sentinel"),
            "SxS acquisition private error/ordering differs"
        );
    }
    for failure in 0..6 {
        let order = RefCell::new(String::new());
        let reads = Cell::new(0);
        let result = start_sequence(
            || {
                reads.set(reads.get() + 1);
                Ok(
                    if failure == 1 && reads.get() == 1
                        || failure == 2 && reads.get() == 2
                        || failure == 5 && reads.get() == 3
                    {
                        0.0
                    } else {
                        1.0
                    },
                )
            },
            || {
                order.borrow_mut().push('i');
                Ok(())
            },
            || {
                order.borrow_mut().push('s');
                if failure == 3 {
                    return Err(error(&raw));
                }
                Ok(())
            },
            || Ok(failure != 4),
            || {
                order.borrow_mut().push('b');
                Ok(())
            },
        );
        ensure!(
            *order.borrow()
                == if failure == 1 {
                    ""
                } else if failure == 2 {
                    "i"
                } else if failure >= 3 {
                    "is"
                } else {
                    "isb"
                }
                && result.is_ok() == (failure == 0),
            "SxS start sequence callback/clock ordering differs"
        );
    }
    let reads = Cell::new(0);
    let caught = start_sequence(
        || {
            reads.set(reads.get() + 1);
            Ok(1.0)
        },
        || Ok(()),
        || Ok(()),
        || Ok(false),
        || Err(error(&raw)),
    )
    .unwrap_err();
    ensure!(
        reads.get() == 2
            && caught.to_string()
                == "fixed SxS trace failed stage=post-tool raw_error_withheld=True",
        "SxS failed starter consumed post-tool clock or binder"
    );
    Ok(())
}
pub(super) fn failures() -> Result<()> {
    let (policy, owner, package) = storage_policy::fixture(true, 1);
    ensure!(
        storage_policy::require(&policy, true, &owner, &package)
            .unwrap_err()
            .to_string()
            == "fixed SxS storage policy rejected predicate=owner",
        "SxS first owner predicate differs"
    );
    for stage in 0..8 {
        let calls = Cell::new(0);
        storage_step(stage, || {
            calls.set(calls.get() + 1);
            Ok(())
        })?;
        ensure!(calls.get() == 1, "storage stage suppressed callback");
        for (kind, native, hresult) in [
            (ExceptionKind::Win32(5), "00000005", "80004005"),
            (
                ExceptionKind::IoHresult(0x80070005),
                "unavailable",
                "80070005",
            ),
            (ExceptionKind::DerivedWin32(99), "unavailable", "80004005"),
        ] {
            let raw: anyhow::Error =
                StorageException::new(kind, anyhow::anyhow!("C:\\private-path-sentinel")).into();
            let original = address(&raw);
            let caught = storage_step::<()>(stage, || Err(raw)).unwrap_err();
            let safe = caught.downcast_ref::<PrivateFailure>().unwrap();
            ensure!(
                address(safe.original()) == original
                    && safe.to_string()
                        == format!(
                            "fixed SxS trace failed stage=storage-{} exception_hresult={hresult} exception_win32={native} policy_predicate=unavailable raw_error_withheld=True",
                            StorageStage::try_from(stage)?.label()
                        )
                    && !format!("{safe:?}").contains("sentinel")
                    && safe.to_string().len() <= 256,
                "storage failure typed projection differs"
            );
        }
    }
    for stage in [-1, 8, i32::MAX] {
        let calls = Cell::new(0);
        ensure!(
            storage_step(stage, || {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .is_err()
                && calls.get() == 0,
            "invalid storage stage executed callback"
        );
    }
    for predicate in 0..11 {
        let predicate = Predicate::try_from(predicate)?;
        let caught = storage_step(2, || storage_policy::need(false, predicate)).unwrap_err();
        let safe = caught.downcast_ref::<PrivateFailure>().unwrap();
        ensure!(
            safe.original().is::<PolicyFailure>()
                && safe.to_string().contains(&format!(
                    "policy_predicate={} raw_error_withheld=True",
                    predicate.label()
                )),
            "storage policy predicate redaction changed"
        );
    }
    for (corruption, expected) in [
        (1, "owner"),
        (2, "protected"),
        (3, "rules"),
        (4, "canonical"),
        (5, "inherited"),
    ] {
        let bytes = storage_policy::fixture(true, corruption).0;
        ensure!(
            storage_policy::require(&bytes, true, &owner, &package)
                .unwrap_err()
                .to_string()
                == format!("fixed SxS storage policy rejected predicate={expected}"),
            "storage first predicate order changed"
        );
    }
    storage_policy::require(&storage_policy::fixture(true, 0).0, true, &owner, &package)?;
    storage_policy::require(
        &storage_policy::fixture(false, 0).0,
        false,
        &owner,
        &package,
    )?;
    let first: anyhow::Error = StorageException::new(
        ExceptionKind::IoHresult(0x80070005),
        anyhow::anyhow!("private-io-sentinel"),
    )
    .into();
    let first_id = address(&first);
    let second: anyhow::Error = StorageException::new(
        ExceptionKind::Win32(5),
        anyhow::anyhow!("private-stop-sentinel"),
    )
    .into();
    let second_id = address(&second);
    let caught = execute_capture(
        || storage_step(4, || Err(first)),
        || Ok(()),
        || Err(second),
        |_| anyhow::bail!("parse must not run"),
    )
    .unwrap_err();
    let group = &caught.downcast_ref::<Failures>().unwrap().errors;
    ensure!(
        group.len() == 2
            && address(
                group[0]
                    .downcast_ref::<PrivateFailure>()
                    .unwrap()
                    .original()
            ) == first_id
            && address(
                group[1]
                    .downcast_ref::<PrivateFailure>()
                    .unwrap()
                    .original()
            ) == second_id
            && !format!("{caught:?}").contains("sentinel"),
        "SxS primary/stop private identity lost"
    );
    Ok(())
}
