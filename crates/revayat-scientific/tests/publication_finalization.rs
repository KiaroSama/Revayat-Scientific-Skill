#[path = "common/pdf.rs"]
mod common;

use revayat_scientific::{pdf, publication};
use std::fs;

#[test]
fn source_changes_at_final_cleanup_boundaries_restore_previous_report() {
    for mutation in [
        publication::Boundary::BeforeCleanup,
        publication::Boundary::BeforeBackupDisposal,
    ] {
        let fixture = common::Fixture::new();
        fixture.save(common::document(1));
        fixture.previous();
        let mut replacement = None;
        let result = pdf::write_report_observed(
            &serde_json::json!({"page_count": 1, "quantity": "-0.25 mV"}),
            &fixture.output,
            std::slice::from_ref(&fixture.source),
            |boundary, _| {
                if boundary == pdf::PdfBoundary::Publication(mutation) {
                    fixture.save(common::document(2));
                    replacement = Some(fs::read(&fixture.source)?);
                }
                Ok(())
            },
        );
        let replacement = replacement.expect("the final mutation must execute");
        assert!(result.is_err(), "stale report accepted at {mutation:?}");
        fixture.preserved();
        assert_eq!(fs::read(&fixture.source).unwrap(), replacement);
        assert_eq!(fs::read_dir(fixture.temp.path()).unwrap().count(), 2);
    }
}

#[cfg(unix)]
#[test]
fn rollback_preserves_restrictive_destination_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let stage = temp.path().join("candidate");
    let destination = temp.path().join("approved");
    fs::write(&stage, b"replacement").unwrap();
    fs::write(&destination, b"private approved bytes").unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).unwrap();
    let mut reached = false;
    let error =
        publication::publish_observed(&[(stage, destination.clone())], &[], None, |boundary, _| {
            if boundary == publication::Boundary::AfterCommit {
                reached = true;
                anyhow::bail!("controlled rollback request");
            }
            Ok(())
        })
        .unwrap_err();
    assert!(reached && error.to_string().contains("controlled rollback request"));
    assert_eq!(fs::read(&destination).unwrap(), b"private approved bytes");
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[test]
fn final_batch_gate_runs_after_all_observers_and_can_restore_the_whole_batch() {
    use publication::{Boundary, Cancellation};
    for failure in ["none", "ordinary", "signal", "requested"] {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let entries: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|name| {
                let stage = temp.path().join(format!("stage-{name}"));
                let output = temp.path().join(format!("output-{name}"));
                fs::write(&stage, format!("candidate {name}")).unwrap();
                fs::write(&output, format!("approved {name}")).unwrap();
                (stage, output)
            })
            .collect();
        let mut cleanup = 0;
        let mut backups = Vec::new();
        let mut gates = 0;
        let result = publication::publish_observed(&entries, &[], None, |boundary, path| {
            match boundary {
                Boundary::BeforeCleanup => cleanup += 1,
                Boundary::BeforeBackupDisposal => backups.push(path.to_owned()),
                Boundary::BeforeFinalize => {
                    gates += 1;
                    assert_eq!(cleanup, 2);
                    assert_eq!(backups.len(), 2);
                    for (index, (_, output)) in entries.iter().enumerate() {
                        let name = if index == 0 { "a" } else { "b" };
                        assert_eq!(fs::read_to_string(output)?, format!("candidate {name}"));
                        assert_eq!(
                            fs::read_to_string(&backups[index])?,
                            format!("approved {name}")
                        );
                    }
                    match failure {
                        "ordinary" => anyhow::bail!("final source validation failed"),
                        "signal" => return Err(Cancellation::Signal.into()),
                        "requested" => return Err(Cancellation::Requested.into()),
                        _ => (),
                    }
                }
                _ => (),
            }
            Ok(())
        });
        assert_eq!(gates, 1);
        assert_eq!(
            cleanup, 2,
            "cleanup observers must not run again during rollback"
        );
        if failure == "none" {
            result.unwrap();
        } else {
            let error = result.unwrap_err();
            match failure {
                "signal" => assert_eq!(
                    error.downcast_ref::<Cancellation>(),
                    Some(&Cancellation::Signal)
                ),
                "requested" => assert_eq!(
                    error.downcast_ref::<Cancellation>(),
                    Some(&Cancellation::Requested)
                ),
                _ => assert!(error.to_string().contains("final source validation failed")),
            }
        }
        for (index, (_, output)) in entries.iter().enumerate() {
            let name = if index == 0 { "a" } else { "b" };
            let kind = if failure == "none" {
                "candidate"
            } else {
                "approved"
            };
            assert_eq!(
                fs::read_to_string(output).unwrap(),
                format!("{kind} {name}")
            );
        }
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    }
}
