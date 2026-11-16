//! Original source36 direct role/result/ownership/host-positive checks.
use super::super::{io, source};
use super::*;
use crate::windows_security::{
    activation::{Failures, capture},
    image::{self, PeImage},
};
use std::{
    cell::{Cell, RefCell},
    fs,
    sync::Arc,
};
pub fn check_self_validation(work: &Path) -> Result<()> {
    super::wire_checks::check_wire_roles()?;
    require_role(true, &[false; 9])?;
    for index in 0..10 {
        let mut flags = [false; 9];
        if index < 9 {
            flags[index] = true;
        }
        ensure!(
            require_role(index < 9, &flags).is_err(),
            "self activation role overlap accepted"
        );
    }
    let role = SelfRole::Original;
    let good = role.success() + "\n";
    let denied = role.denied() + "\n";
    check_result_refusal(&good)?;
    ensure!(
        role.script(1033) == "LANGUAGE 9,1\n2 24 \"self-activation-payload.bin\"\n",
        "self resource script differs"
    );
    let parsed =
        |exit, text: &str, errors: &str| result(exit, Some(text), Some(errors), role, |_| Ok(()));
    ensure!(
        parsed(0, &good, "")? == role.success() && parsed(0, &denied, "")? == role.denied(),
        "self result literals differ"
    );
    require_host(&parsed(0, &good, "")?, role)?;
    ensure!(
        require_host(&parsed(0, &denied, "")?, role).is_err(),
        "negative self host latched positive"
    );
    require_positive(true)?;
    ensure!(
        require_positive(false).is_err(),
        "unprepared self positive admitted"
    );
    for role in [SelfRole::Original, SelfRole::Manual, SelfRole::ExplicitId2] {
        for mode in 0..4 {
            let order = RefCell::new(Vec::new());
            let primary = Arc::new(anyhow::anyhow!("fixed host operation"));
            let cleanup = Arc::new(capture::check_strict_cleanup()?);
            let caught = complete_host(
                role,
                || {
                    order.borrow_mut().push("run");
                    if mode == 1 || mode == 3 {
                        Err(super::wire_checks::identified(&primary))
                    } else {
                        Ok(role.success())
                    }
                },
                || {
                    order.borrow_mut().push("close");
                    if mode == 2 || mode == 3 {
                        Err(super::wire_checks::identified(&cleanup))
                    } else {
                        Ok(())
                    }
                },
                || {
                    order.borrow_mut().push("accept");
                    Ok(())
                },
            )
            .err();
            ensure!(
                *order.borrow()
                    == if mode == 0 {
                        vec!["run", "close", "accept"]
                    } else {
                        vec!["run", "close"]
                    },
                "self host qualification order differs"
            );
            match mode {
                0 => ensure!(caught.is_none(), "successful self host refused"),
                1 => ensure!(
                    super::wire_checks::same(caught.as_ref().unwrap(), &primary),
                    "self operation failure replaced"
                ),
                2 => ensure!(
                    super::wire_checks::same(caught.as_ref().unwrap(), &cleanup),
                    "self close failure replaced"
                ),
                _ => {
                    let group = caught.as_ref().unwrap().downcast_ref::<Failures>().unwrap();
                    ensure!(
                        group.errors.len() == 2
                            && super::wire_checks::same(&group.errors[0], &primary)
                            && super::wire_checks::same(&group.errors[1], &cleanup),
                        "self operation/cleanup order or identity lost"
                    );
                }
            }
        }
    }
    for exit in [1, 120, 121, 0xc0000022, 0xc0150002, u32::MAX] {
        ensure!(
            parsed(exit, &good, "").is_err() && parsed(exit, "", "").is_err(),
            "nonzero self process exit accepted"
        );
    }
    for bad in [
        String::new(),
        good.repeat(2),
        good.trim_end_matches('\n').into(),
        good.replace('\n', "\r\n"),
        good.replace("00000000", "00000005"),
        denied.replace("00000005", "00000000"),
        good.replace("entry_reached=True", "entry_reached=False"),
        denied.replace("False", "false"),
        "private-sentinel".into(),
        "x".repeat(129),
    ] {
        ensure!(
            parsed(0, &bad, "").is_err(),
            "malformed self result accepted"
        );
    }
    ensure!(
        parsed(0, &good, "private-sentinel").is_err() && parsed(0, &good, " ").is_err(),
        "self stderr accepted"
    );
    ensure!(
        condition("original", Some(&parsed(0, &denied, "")?), role)?.ends_with(
            "python_equivalence_claimed=False cause_claimed=False production_grant=False"
        ) && condition("private-sentinel", Some(&role.success()), role).is_err()
            && condition("modified", Some("private-sentinel"), role).is_err(),
        "self condition widened attribution or accepted unknown data"
    );
    let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    io::require_identity(b"abc", 3, hash)?;
    ensure!(
        io::require_identity(b"abc", 4, hash).is_err()
            && io::require_identity(b"abd", 3, hash).is_err(),
        "self fixture identity drift accepted"
    );
    let directory = tempfile::Builder::new()
        .prefix("self-activation-validation-")
        .tempdir_in(work)?;
    let path = directory.path().join("owned.bin");
    io::create(&path, b"abc", 1048576)?.close()?;
    ensure!(
        io::create(&path, &[9], 1048576).is_err() && fs::read(&path)? == b"abc",
        "self collision changed sentinel"
    );
    let image = directory.path().join("startup-self-activation.exe");
    let sidecar = directory
        .path()
        .join("startup-self-activation.exe.manifest");
    fs::write(&sidecar, b"unchanged")?;
    ensure!(
        io::no_overrides(&image).is_err() && fs::read(&sidecar)? == b"unchanged",
        "self sidecar collision changed sentinel"
    );
    fs::remove_file(&sidecar)?;
    source::directory_link(&directory.path().join("absent"), &sidecar)?;
    ensure!(
        io::no_overrides(&image).is_err() && crate::identity::is_link(&sidecar)?,
        "self dangling sidecar changed or accepted"
    );
    source::remove_directory_link(&sidecar)?;
    image::check_self_activation_validation()?;
    let bytes = image::self_activation_validation_fixture(SelfRole::ExplicitId2);
    let image = PeImage::parse(&bytes, 0x10000000)?;
    image.qualify_self_activation(SelfRole::ExplicitId2, 1033, &[1, 2, 3, 4])?;
    crate::windows_security::activation::entry::check_entry_lifetime_validation(&image)
}
fn check_result_refusal(good: &str) -> Result<()> {
    let reports = Cell::new(0);
    ensure!(
        result(0, Some(good), Some(""), SelfRole::Original, |_| {
            reports.set(reports.get() + 1);
            Ok(())
        })? == good.trim_end_matches('\n')
            && reports.get() == 0,
        "successful self fixture emitted refusal"
    );
    for (exit, text, errors, stage, code, chars, stderr) in [
        (
            0xc0000022,
            "".to_owned(),
            "",
            "transport",
            "0xC0000022",
            0,
            "False",
        ),
        (
            u32::MAX,
            "private-sentinel".into(),
            "private-sentinel",
            "transport",
            "0xFFFFFFFF",
            16,
            "True",
        ),
        (
            0,
            "x".repeat(128),
            "",
            "grammar",
            "0x00000000",
            128,
            "False",
        ),
        (
            0,
            "x".repeat(129),
            "",
            "transport",
            "0x00000000",
            129,
            "False",
        ),
        (
            0,
            good.replace("00000000", "00000005"),
            "",
            "consistency",
            "0x00000000",
            79,
            "False",
        ),
    ] {
        let line = RefCell::new(String::new());
        let count = Cell::new(0);
        let error = result(
            exit,
            Some(&text),
            Some(errors),
            SelfRole::Original,
            |value| {
                *line.borrow_mut() = value.into();
                count.set(count.get() + 1);
                Ok(())
            },
        )
        .unwrap_err();
        ensure!(
            error.to_string() == "fixed self activation contract failed"
                && count.get() == 1
                && *line.borrow()
                    == format!(
                        "WINDOWS_SELF_ACTIVATION_REFUSAL stage={stage} raw_process_exit={code} stdout_chars={chars} stderr_present={stderr}"
                    ),
            "self refusal changed stage/bounds/privacy"
        );
    }
    let reporting = Arc::new(anyhow::anyhow!("fixed reporting fixture"));
    let error = result(
        1,
        Some("private-sentinel"),
        Some(""),
        SelfRole::Original,
        |_| Err(super::wire_checks::identified(&reporting)),
    )
    .unwrap_err();
    let group = error.downcast_ref::<Failures>().unwrap();
    ensure!(
        group.errors.len() == 2
            && group.errors[0].to_string() == "fixed self activation contract failed"
            && super::wire_checks::same(&group.errors[1], &reporting),
        "self reporting replaced original refusal"
    );
    Ok(())
}
pub fn check_entry_host_validation() -> Result<()> {
    let operation = Arc::new(anyhow::anyhow!("fixed host observation"));
    let cleanup = Arc::new(anyhow::anyhow!("fixed lease close"));
    let reporting = Arc::new(anyhow::anyhow!("fixed report"));
    for resource in [false, true] {
        for mode in 0..6 {
            let order = RefCell::new(Vec::new());
            let caught = complete_entry_host(
                |retain| {
                    order.borrow_mut().push("process-cleanup");
                    retain("fixed-metadata")?;
                    if mode == 1 || mode == 5 {
                        Err(super::wire_checks::identified(&operation))
                    } else {
                        Ok(SelfRole::ExplicitId2.success())
                    }
                },
                || {
                    order.borrow_mut().push("lease-close");
                    if mode == 2 || mode == 5 {
                        Err(super::wire_checks::identified(&cleanup))
                    } else {
                        Ok(())
                    }
                },
                |line| {
                    let metadata = line == "fixed-metadata";
                    order.borrow_mut().push(if metadata {
                        "metadata"
                    } else {
                        "positive-report"
                    });
                    if mode == if metadata { 3 } else { 4 } {
                        Err(super::wire_checks::identified(&reporting))
                    } else {
                        Ok(())
                    }
                },
                || {
                    order.borrow_mut().push("latch");
                    Ok(())
                },
                resource,
            )
            .err();
            let expected = match mode {
                0 => vec![
                    "process-cleanup",
                    "lease-close",
                    "metadata",
                    "positive-report",
                    "latch",
                ],
                3 => vec!["process-cleanup", "lease-close", "metadata"],
                4 => vec![
                    "process-cleanup",
                    "lease-close",
                    "metadata",
                    "positive-report",
                ],
                _ => vec!["process-cleanup", "lease-close"],
            };
            ensure!(
                *order.borrow() == expected,
                "entry host reporting/cleanup/latch order differs"
            );
            match mode {
                0 => ensure!(caught.is_none(), "successful entry host refused"),
                1..=4 => ensure!(
                    super::wire_checks::same(
                        caught.as_ref().unwrap(),
                        if mode == 1 {
                            &operation
                        } else if mode == 2 {
                            &cleanup
                        } else {
                            &reporting
                        }
                    ),
                    "entry host single failure identity changed"
                ),
                _ => {
                    let group = caught.as_ref().unwrap().downcast_ref::<Failures>().unwrap();
                    ensure!(
                        group.errors.len() == 2
                            && super::wire_checks::same(&group.errors[0], &operation)
                            && super::wire_checks::same(&group.errors[1], &cleanup),
                        "entry host operation/lease failure order changed"
                    );
                }
            }
        }
    }
    Ok(())
}
