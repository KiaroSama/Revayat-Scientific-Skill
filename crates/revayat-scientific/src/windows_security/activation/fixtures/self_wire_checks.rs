//! Exact original/manual/explicit-ID2 result and refusal matrices from source36.
use super::*;
use crate::windows_security::activation::{Failures, capture, self_result::PRE_CALL_RECEIPT};
use std::{
    cell::{Cell, RefCell},
    error::Error,
    fmt,
    sync::Arc,
};
#[derive(Debug)]
pub(super) struct Identity(pub Arc<anyhow::Error>);
impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fixed self fixture failure")
    }
}
impl Error for Identity {}
pub(super) fn identified(error: &Arc<anyhow::Error>) -> anyhow::Error {
    Identity(error.clone()).into()
}
pub(super) fn same(error: &anyhow::Error, expected: &Arc<anyhow::Error>) -> bool {
    error
        .downcast_ref::<Identity>()
        .is_some_and(|v| Arc::ptr_eq(&v.0, expected))
}
fn parsed(role: SelfRole, exit: u32, text: Option<&str>, errors: Option<&str>) -> Result<String> {
    result(exit, text, errors, role, |_| Ok(()))
}
pub(super) fn check_wire_roles() -> Result<()> {
    for role in [SelfRole::Manual, SelfRole::ExplicitId2] {
        let completed = role.success();
        let denied = role.denied();
        let prefix = if role == SelfRole::ExplicitId2 {
            PRE_CALL_RECEIPT
        } else {
            ""
        };
        let good = format!("{prefix}{completed}\n");
        let bad = format!("{prefix}{denied}\n");
        ensure!(
            parsed(role, 0, Some(&good), Some(""))? == completed
                && parsed(role, 0, Some(&bad), Some(""))? == denied,
            "self fixture role result literals differ"
        );
        ensure!(
            role.script(1033)
                == format!(
                    "LANGUAGE 9,1\n{} 24 \"{}-payload.bin\"\n",
                    if role == SelfRole::Manual { 101 } else { 2 },
                    role.stem()
                ),
            "self role resource script differs"
        );
        if role == SelfRole::ExplicitId2 {
            ensure!(
                PRE_CALL_RECEIPT.len() == 25
                    && good.len() == 112
                    && bad.len() == 113
                    && role.image_name() == "startup-explicit-id2.exe"
                    && role.stem() == "explicit-id2",
                "explicit ID2 receipt/role widths differ"
            );
            for malformed in [
                prefix.into(),
                prefix[..24].into(),
                format!("{completed}\n"),
                format!("{completed}\n{prefix}"),
                format!("{prefix}{good}"),
                format!("{good}{prefix}"),
                format!("{prefix}{completed}"),
                format!("{}{completed}\n", prefix.replace('\n', "\r\n")),
                format!("{prefix}{}\n", SelfRole::Manual.success()),
                format!("{good}x"),
            ] {
                ensure!(
                    parsed(role, 0, Some(&malformed), Some("")).is_err(),
                    "explicit pre-call grammar accepted wrong ordering/boundary"
                );
            }
            for other in [SelfRole::Original, SelfRole::Manual] {
                ensure!(
                    parsed(other, 0, Some(&good), Some("")).is_err()
                        && parsed(role, 0, Some(&(other.success() + "\n")), Some("")).is_err(),
                    "explicit cross-role wire accepted"
                );
            }
            ensure!(
                parsed(role, 0, None, Some("")).is_err()
                    && parsed(role, 0, Some(&good), None).is_err(),
                "null explicit transport accepted"
            );
        } else {
            ensure!(
                parsed(SelfRole::Original, 0, Some(&good), Some("")).is_err()
                    && parsed(
                        role,
                        0,
                        Some(&(SelfRole::Original.success() + "\n")),
                        Some("")
                    )
                    .is_err(),
                "manual/original wire confusion accepted"
            );
        }
        for malformed in [
            String::new(),
            good.repeat(2),
            good.trim_end_matches('\n').into(),
            good.replace('\n', "\r\n"),
            good.replace("00000000", "00000005"),
            bad.replace("00000005", "00000000"),
            "private-sentinel".into(),
            "x".repeat(129),
        ] {
            ensure!(
                parsed(role, 0, Some(&malformed), Some("")).is_err(),
                "malformed self role wire accepted"
            );
        }
        for exit in [1, 120, 121, 0xc0000022, u32::MAX] {
            ensure!(
                parsed(role, exit, Some(&good), Some("")).is_err(),
                "self role nonzero process exit accepted"
            );
        }
        if role == SelfRole::ExplicitId2 {
            ensure!(
                parsed(role, 122, Some(&good), Some("")).is_err(),
                "explicit pre-call write failure accepted"
            );
        }
        ensure!(
            parsed(role, 0, Some(&good), Some("private-sentinel")).is_err(),
            "self role stderr accepted"
        );
        let reports = Cell::new(0);
        ensure!(
            result(0, Some(&good), Some(""), role, |_| {
                reports.set(reports.get() + 1);
                Ok(())
            })? == completed
                && reports.get() == 0,
            "successful role emitted refusal"
        );
        let refusal = RefCell::new(String::new());
        ensure!(
            result(0xc0000022, Some(""), Some(""), role, |line| {
                *refusal.borrow_mut() = line.into();
                Ok(())
            })
            .is_err(),
            "nonzero role transport accepted"
        );
        ensure!(
            *refusal.borrow()
                == format!(
                    "{}_REFUSAL stage=transport raw_process_exit=0xC0000022 stdout_chars=0 stderr_present=False{}",
                    role.label(),
                    if role == SelfRole::ExplicitId2 {
                        " pre_call_receipt_observed=False"
                    } else {
                        ""
                    }
                ),
            "role refusal projection differs"
        );
        let reporting = Arc::new(anyhow::anyhow!("fixed role reporting"));
        let error = result(1, Some("private-sentinel"), Some(""), role, |_| {
            Err(identified(&reporting))
        })
        .unwrap_err();
        let group = error.downcast_ref::<Failures>().unwrap();
        ensure!(
            group.errors.len() == 2
                && group.errors[0].to_string() == "fixed self activation contract failed"
                && same(&group.errors[1], &reporting),
            "role reporting replaced original refusal"
        );
        require_host(&completed, role)?;
        ensure!(
            require_host(&denied, role).is_err()
                && condition("original", Some(&SelfRole::Original.success()), role).is_err(),
            "self role host/condition confusion accepted"
        );
        ensure!(
            condition("original", Some(&completed), role)?
                == format!(
                    "{}_CONDITION condition=original {completed} python_equivalence_claimed=False cause_claimed=False production_grant=False",
                    role.label()
                ),
            "self role condition differs"
        );
        let cleanup = Arc::new(capture::check_strict_cleanup()?);
        let accepted = Cell::new(false);
        let error = complete_host(
            role,
            || Ok(completed.clone()),
            || Err(identified(&cleanup)),
            || {
                accepted.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        ensure!(
            !accepted.get() && same(&error, &cleanup),
            "uncertain capture close latched positive or changed error"
        );
        if role == SelfRole::ExplicitId2 {
            check_explicit_boundaries(&completed, &good)?;
        }
    }
    let prepared = super::super::prepared::PreparedSet::default();
    for invalid in [-1, 3, i32::MAX] {
        ensure!(
            stem(invalid).is_err() && label(invalid).is_err() && image_name(invalid).is_err(),
            "undefined self role reached label/stem/image ingress"
        );
        ensure!(
            prepared.self_prepared(None, invalid).is_err()
                && source_bytes("private-sentinel", invalid).is_err(),
            "undefined self role reached prepared/source ingress"
        );
        ensure!(
            result_for_role(0, Some("private-sentinel"), Some(""), invalid, |_| panic!(
                "undefined role emitted refusal"
            ))
            .is_err(),
            "undefined self role reached wire effects"
        );
        ensure!(
            prepared.hold_self(None, invalid).is_err()
                && super::super::prepared::self_build_request(None, None, invalid).is_err(),
            "undefined self role reached hold/build effects"
        );
    }
    let resource = "pub const RESOURCE_ID: u16 = 2;";
    ensure!(
        super::super::source::replace_once("unrelated", resource, "fixed").is_err()
            && super::super::source::replace_once(&resource.repeat(2), resource, "fixed").is_err()
            && super::super::source::replace_once(
                resource,
                resource,
                "pub const RESOURCE_ID: u16 = 101;"
            )? == "pub const RESOURCE_ID: u16 = 101;"
            && super::super::source::replace_once(
                "WINDOWS_SELF_ACTIVATIONWINDOWS_SELF_ACTIVATION",
                "WINDOWS_SELF_ACTIVATION",
                "WINDOWS_MANUAL_ACTIVATION"
            )
            .is_err(),
        "manual source uniqueness contract differs"
    );
    Ok(())
}
fn check_explicit_boundaries(completed: &str, success: &str) -> Result<()> {
    let role = SelfRole::ExplicitId2;
    let marker = PRE_CALL_RECEIPT;
    for (text, seen) in [
        (marker.to_owned(), true),
        (format!("{marker}private-sentinel"), true),
        (marker[..24].into(), false),
        (format!("private-sentinel{marker}"), false),
        (marker.replace('\n', "\r\n"), false),
        (format!("{completed}\n{marker}"), false),
    ] {
        let metadata = RefCell::new(String::new());
        ensure!(
            result(0xc0000022, Some(&text), Some(""), role, |line| {
                *metadata.borrow_mut() = line.into();
                Ok(())
            })
            .is_err(),
            "explicit failed transport accepted"
        );
        ensure!(
            *metadata.borrow()
                == format!(
                    "WINDOWS_EXPLICIT_ID2_ACTIVATION_REFUSAL stage=transport raw_process_exit=0xC0000022 stdout_chars={} stderr_present=False pre_call_receipt_observed={}",
                    text.len(),
                    if seen { "True" } else { "False" }
                ),
            "explicit receipt observation projection differs"
        );
    }
    for value in [
        success.trim_end_matches('\n').into(),
        marker.into(),
        format!("{completed}\n"),
        completed.repeat(2),
        completed.replace("True", "true"),
        completed.replace("00000000", "00000005"),
        "x".repeat(128),
    ] {
        ensure!(
            condition("original", Some(&value), role).is_err(),
            "malformed explicit condition accepted"
        );
    }
    ensure!(
        condition("original", None, role).is_err(),
        "null explicit condition accepted"
    );
    for length in [128, 129] {
        let metadata = RefCell::new(String::new());
        ensure!(
            result(0, Some(&"x".repeat(length)), Some(""), role, |line| {
                *metadata.borrow_mut() = line.into();
                Ok(())
            })
            .is_err(),
            "explicit bound malformed capture accepted"
        );
        ensure!(
            *metadata.borrow()
                == format!(
                    "WINDOWS_EXPLICIT_ID2_ACTIVATION_REFUSAL stage={} raw_process_exit=0x00000000 stdout_chars={length} stderr_present=False pre_call_receipt_observed=False",
                    if length == 128 {
                        "grammar"
                    } else {
                        "transport"
                    }
                ),
            "explicit refusal bound stage differs"
        );
    }
    Ok(())
}
