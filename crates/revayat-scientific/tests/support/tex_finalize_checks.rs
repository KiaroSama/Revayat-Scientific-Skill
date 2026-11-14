use super::{Backend, Fixture, config};
use anyhow::Result;
use revayat_scientific::tex_container as tex;
use std::fs;
#[derive(Debug)]
struct BackendFailure;
impl std::fmt::Display for BackendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("injected typed backend failure")
    }
}
impl std::error::Error for BackendFailure {}
pub(super) fn primary_and_recovery() -> Result<()> {
    for report_fails in [false, true] {
        let f = Fixture::new()?;
        let mut backend = Backend::new();
        backend.cleanup_fail = true;
        let mut reported = None;
        let error = tex::compile_document_with_lifecycle(
            &f.source,
            &f.output,
            config(),
            None,
            &mut |args, timeout| {
                if args.iter().any(|a| a == "run") {
                    let _ = backend.execute(args, timeout)?;
                    return Err(BackendFailure.into());
                }
                backend.execute(args, timeout)
            },
            |_, _, _| Ok(()),
            (
                |_: &tex::RuntimeConfig, _: &std::path::Path, _: &str| Ok(None),
                |_: Option<&std::path::Path>| Ok(()),
                |directory: &std::path::Path, run: &str| {
                    reported = Some(directory.to_owned());
                    if report_fails {
                        anyhow::bail!("injected recovery report failure");
                    }
                    fs::write(
                        directory.join("recovery.json"),
                        serde_json::to_vec(
                            &serde_json::json!({"run_id":run,"status":"cleanup_not_verified"}),
                        )?,
                    )?;
                    Ok(())
                },
            ),
        )
        .unwrap_err();
        assert!(error.downcast_ref::<BackendFailure>().is_some());
        let chain = format!("{error:#}");
        assert!(chain.contains("daemon unavailable"));
        if report_fails {
            assert!(chain.contains("injected recovery report failure"));
        }
        let retained = reported.unwrap();
        assert!(retained.is_dir());
        assert!(retained.join("input/child.tex").is_file());
        if !report_fails {
            assert!(retained.join("recovery.json").is_file());
        }
        f.unchanged()?;
        // The enclosing owned fixture retains recovery through assertions; its
        // TempDir disposes only these synthetic files after the fake backend exits.
    }
    ordering_and_acknowledgement()?;
    console_evidence()
}

fn console_evidence() -> Result<()> {
    let scratch = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.scratch");
    fs::create_dir_all(&scratch)?;
    let fixture = tempfile::tempdir_in(scratch)?;
    let source = fixture.path().join("source.tex");
    fs::write(&source, b"Scientific input")?;
    let outgoing = fixture.path().join("output");
    let evidence = fixture.path().join("evidence");
    fs::create_dir(&outgoing)?;
    fs::create_dir(&evidence)?;
    let name = "console-pass-1.log";
    fs::write(
        outgoing.join(name),
        b"Undefined control sequence\nl.9 PRIVATE_MANUSCRIPT_LINE",
    )?;
    let run = "b".repeat(32);
    tex::retain_fixture_console(&source, &outgoing, &run, Some(&evidence), false)?;
    assert_eq!(fs::read_dir(&evidence)?.count(), 0);
    tex::retain_fixture_console(&source, &outgoing, &run, Some(&evidence), true)?;
    assert_eq!(fs::read_dir(&evidence)?.count(), 1);
    let retained = fs::read(evidence.join(format!("fixture-tex-{run}-{name}")))?;
    assert!(
        retained
            .windows(b"Undefined control sequence".len())
            .any(|s| s == b"Undefined control sequence")
    );
    Ok(())
}

fn ordering_and_acknowledgement() -> Result<()> {
    use std::cell::RefCell;
    for failure in ["none", "register", "acknowledge"] {
        let f = Fixture::new()?;
        let events = RefCell::new(Vec::new());
        let staged = RefCell::new(None);
        let mut backend = Backend::new();
        let result = tex::compile_document_with_lifecycle(
            &f.source,
            &f.output,
            config(),
            None,
            &mut |args, timeout| {
                events
                    .borrow_mut()
                    .push(if args.iter().any(|a| a == "run") {
                        "run"
                    } else {
                        "cleanup"
                    });
                backend.execute(args, timeout)
            },
            |_, _, _| Ok(()),
            (
                |_: &tex::RuntimeConfig, directory: &std::path::Path, _: &str| {
                    events.borrow_mut().push("register");
                    *staged.borrow_mut() = Some(directory.to_owned());
                    if failure == "register" {
                        anyhow::bail!("injected registration failure");
                    }
                    let receipt = directory.join("receipt-test.json");
                    fs::write(&receipt, b"synthetic owned receipt")?;
                    Ok(Some(receipt))
                },
                |receipt: Option<&std::path::Path>| {
                    events.borrow_mut().push("acknowledge");
                    let receipt = receipt.unwrap();
                    assert_eq!(fs::read(receipt)?, b"synthetic owned receipt");
                    assert_eq!(events.borrow().iter().rev().nth(1), Some(&"cleanup"));
                    if failure == "acknowledge" {
                        anyhow::bail!("injected acknowledgement failure");
                    }
                    fs::remove_file(receipt)?;
                    Ok(())
                },
                |_: &std::path::Path, _: &str| {
                    events.borrow_mut().push("report");
                    Ok(())
                },
            ),
        );
        let events = events.into_inner();
        assert_eq!(events[0], "register");
        if failure == "register" {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("registration failure")
            );
            assert_eq!(events, ["register"]);
            assert_eq!(backend.calls, 0);
            f.clean_staging()?;
            f.unchanged()?;
        } else {
            assert_eq!(events[1], "run");
            assert_eq!(events.last(), Some(&"acknowledge"));
            assert_eq!(backend.cleanup_calls, 1);
            assert!(!backend.alive);
            if failure == "acknowledge" {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("acknowledgement failed")
                );
                let stage = staged.into_inner().unwrap();
                assert!(stage.join("receipt-test.json").is_file());
                assert!(stage.join("input/child.tex").is_file());
                f.unchanged()?;
            } else {
                result?;
                f.clean_staging()?;
            }
        }
    }
    Ok(())
}
