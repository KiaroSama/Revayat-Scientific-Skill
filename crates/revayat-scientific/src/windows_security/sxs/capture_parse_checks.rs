use super::super::super::{check_reporting_validation, failure_evidence, storage_policy};
use super::*;
pub(super) fn check() -> Result<()> {
    check_reporting_validation()?;
    let raw = Arc::new(());
    for (index, label) in [
        "etl-policy",
        "etl-length",
        "text-absent",
        "parse-tool",
        "text-policy",
        "text-read",
        "evidence-output",
    ]
    .into_iter()
    .enumerate()
    {
        let caught = at_parse(index as i32, || Err::<(), _>(error(&raw))).unwrap_err();
        let safe = caught.downcast_ref::<PrivateFailure>().unwrap();
        ensure!(
            same(safe.original(), &raw)
                && safe.to_string()
                    == format!("fixed SxS trace failed stage={label} raw_error_withheld=True")
                && !format!("{safe:?}").contains("sentinel"),
            "SxS parse stage redaction/identity differs"
        );
        let pointer = address(&caught);
        let retained = at_parse(index as i32, || Err::<(), _>(caught)).unwrap_err();
        ensure!(
            address(&retained) == pointer,
            "SxS parse replaced existing safe failure"
        );
    }
    let (_, owner, package) = storage_policy::fixture(false, 0);
    for (stage, label) in [(0, "etl-policy"), (4, "text-policy")] {
        at_parse(stage, || {
            storage_policy::require(
                &storage_policy::fixture(false, 0).0,
                false,
                &owner,
                &package,
            )
        })?;
        let caught = at_parse(stage, || {
            storage_policy::require(
                &storage_policy::fixture(false, 1).0,
                false,
                &owner,
                &package,
            )
        })
        .unwrap_err();
        ensure!(
            caught.to_string()
                == format!(
                    "fixed SxS trace failed stage={label} policy_predicate=owner raw_error_withheld=True"
                ),
            "parse policy predicate missing"
        );
    }
    for invalid in [-1, 7, i32::MAX] {
        let calls = Cell::new(0);
        ensure!(
            at_parse(invalid, || {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .is_err()
                && calls.get() == 0,
            "invalid parse stage executed callback"
        );
    }
    let first =
        crate::windows_security::policy::registry_comparison::wire::transport_failure(1, None);
    let first_id = address(&first);
    let caught = execute_capture(
        || Err(first),
        || Ok(()),
        || Ok(()),
        |_| {
            at_parse(5, || {
                failure_evidence(&[], "private-manifest-sentinel").map(|_| ())
            })
        },
    )
    .unwrap_err();
    let caught = crate::windows_security::policy::registry_comparison::wire::sanitize(caught);
    let group = &caught.downcast_ref::<Failures>().unwrap().errors;
    ensure!(
        group.len() == 2
            && address(&group[0]) == first_id
            && group[1].is::<PrivateFailure>()
            && group[1].to_string()
                == "fixed SxS trace failed stage=evidence-length-input-shape comparison=minimum observed_bytes=0 maximum_bytes=1048576 even=not-evaluated evidence-prefix status=array signature=absent transferred_bytes=0 raw_error_withheld=True"
            && !format!("{caught:?}").contains("sentinel"),
        "receipt/parse private failure order differs"
    );
    let original = group[1]
        .downcast_ref::<PrivateFailure>()
        .unwrap()
        .original();
    let ordered = &original.downcast_ref::<Failures>().unwrap().errors;
    ensure!(
        ordered.len() == 2
            && ordered[0]
                .downcast_ref::<PrivateFailure>()
                .unwrap()
                .stage()
                .starts_with("evidence-length-input-shape")
            && ordered[1].downcast_ref::<PrivateFailure>().unwrap().stage()
                == "evidence-prefix status=array signature=absent transferred_bytes=0",
        "rejected evidence supplementary observations lost"
    );
    Ok(())
}
