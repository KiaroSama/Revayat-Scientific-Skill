//! Shared fixed token-query formatting/finalization and original portable validator matrices.
use super::profile_validation::{ace, sid};
use super::{default_acl_summary, encode_acl, within};
use crate::windows_security::activation::Failures;
use anyhow::{Result, ensure};
use std::{cell::Cell, fmt, sync::Arc};

/// This describes the exact observed result, including permitted LPAC success; it proves no cause.
pub fn startup_outcome(context: &str, opened: bool, handle: usize, error: u32) -> Result<String> {
    let valid = handle != 0 && handle != usize::MAX;
    ensure!(
        matches!(context, "host" | "lpac")
            && if opened {
                valid && error == 0
            } else {
                handle == 0 && error != 0
            },
        "token-query result/context/handle is inconsistent"
    );
    Ok(format!(
        "WINDOWS_STARTUP_TOKEN context={context} desired_access=0x00000008 opened={} win32_error={error} cause_claimed=False child_equivalence_claimed=False",
        if opened { "True" } else { "False" }
    ))
}

/// Shared operation/finalization ordering; owners retain original error objects without formatting them.
pub fn finish<T>(result: Result<T>, mut errors: Vec<anyhow::Error>) -> Result<T> {
    if errors.is_empty() {
        return result;
    }
    if let Err(primary) = result {
        errors.insert(0, primary);
    }
    Err(Failures { errors }.into())
}
/// Original finally-block helper: an already propagating primary alone is not thrown twice.
pub fn finish_cleanup(primary: Option<anyhow::Error>, errors: Vec<anyhow::Error>) -> Result<()> {
    if errors.is_empty() {
        return Ok(());
    }
    finish(primary.map_or(Ok(()), Err), errors)
}

/// TokenDefaultMetadata.CheckValidation, against the same production diagnostic parsers.
pub fn check_default_metadata_validation() -> Result<()> {
    let user = sid(5, &[21, 1, 2, 3, 500]);
    let package = sid(15, &[2, 3]);
    let entries = [
        ace(1, 0, 2, &user)?,
        ace(0, 0, 8, &user)?,
        ace(0, 0, 0x20019, &package)?,
        ace(0, 10, 0x10000000, &user)?,
    ];
    let valid = encode_acl(2, &entries)?;
    let summary = default_acl_summary(Some(&valid), &user, &package)?.record(valid.len());
    ensure!(
        summary.contains("user_allow_mask=0x00000008")
            && summary.contains("user_deny_mask=0x00000002")
            && summary.contains("package_allow_mask=0x00020019")
            && summary.contains("inherit_only_count=1")
            && summary.contains("effective_access_proved=False")
            && !summary.contains("S-1-5-21-1-2-3-500")
            && !summary.contains("S-1-15-2-3"),
        "default-DACL summary parser lost bounds or privacy"
    );
    let empty = encode_acl(2, &[])?;
    let empty_summary = default_acl_summary(Some(&empty), &user, &package)?.record(empty.len());
    ensure!(
        empty_summary.contains("ace_count=0"),
        "empty default-DACL fixture not distinguished"
    );
    let mut padded = valid.clone();
    padded.extend([0; 4]);
    let length = padded.len() as u16;
    padded[2..4].copy_from_slice(&length.to_le_bytes());
    ensure!(
        default_acl_summary(Some(&padded), &user, &package)?
            .record(padded.len())
            .contains("user_allow_mask=0x00000008"),
        "legitimate ACL padding changed parser summary"
    );
    let null = default_acl_summary(None, &user, &package)?.record(0);
    ensure!(
        null.contains("default_dacl_null=True")
            && !empty_summary.contains("default_dacl_null=True"),
        "null and empty default-DACL summaries conflated"
    );
    let reversed = encode_acl(2, &[entries[1].clone(), entries[0].clone()])?;
    ensure!(
        default_acl_summary(Some(&reversed), &user, &package)?
            .record(reversed.len())
            .contains("canonical_order=False"),
        "misordered default-DACL ACEs reported canonical"
    );
    let mutations = [
        (0, vec![1]),
        (1, vec![1]),
        (2, vec![0]),
        (4, 65u16.to_le_bytes().to_vec()),
        (10, 3u16.to_le_bytes().to_vec()),
        (10, 65532u16.to_le_bytes().to_vec()),
        (16, vec![2]),
        (17, vec![16]),
    ];
    for (index, (at, value)) in mutations.iter().enumerate() {
        let mut bad = valid.clone();
        bad[*at..*at + value.len()].copy_from_slice(value);
        ensure!(
            default_acl_summary(Some(&bad), &user, &package).is_err(),
            "malformed default-DACL ACL span accepted fixture={index}"
        );
    }
    let mut callback = entries.to_vec();
    callback[1] = ace(9, 0, 8, &user)?;
    callback[1].extend([0; 4]);
    let length = callback[1].len() as u16;
    callback[1][2..4].copy_from_slice(&length.to_le_bytes());
    let callback = encode_acl(2, &callback)?;
    ensure!(
        default_acl_summary(Some(&callback), &user, &package)?
            .record(callback.len())
            .contains("recognized_all=False"),
        "callback default-DACL ACE treated as unconditional grant"
    );
    ensure!(
        within(100, 16, 100, 16, 4)
            && !within(100, 16, 101, 4, 4)
            && !within(100, 16, 108, 9, 4)
            && !within(100, 16, 99, 1, 1)
            && !within(u64::MAX - 8, 8, 1, 1, 1),
        "default-DACL native range fixture failed"
    );
    Ok(())
}

#[derive(Debug)]
struct ValidationCause(Arc<()>);
impl fmt::Display for ValidationCause {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("fixed validation cause")
    }
}
impl std::error::Error for ValidationCause {}

/// StartupTokenAccess.CheckValidation: exact records, seven refusal cases, and all cleanup attempts.
pub fn check_startup_token_validation() -> Result<()> {
    ensure!(
        startup_outcome("host", true, 1, 0)?
            == "WINDOWS_STARTUP_TOKEN context=host desired_access=0x00000008 opened=True win32_error=0 cause_claimed=False child_equivalence_claimed=False"
            && startup_outcome("lpac", false, 0, 5)?
                == "WINDOWS_STARTUP_TOKEN context=lpac desired_access=0x00000008 opened=False win32_error=5 cause_claimed=False child_equivalence_claimed=False",
        "fixed token-query result formatting differs"
    );
    for (context, opened, handle, code) in [
        ("private-sentinel", true, 1, 0),
        ("host", true, 0, 0),
        ("host", true, usize::MAX, 0),
        ("host", true, 1, 5),
        ("lpac", false, 1, 5),
        ("lpac", false, usize::MAX, 5),
        ("lpac", false, 0, 0),
    ] {
        let failure = startup_outcome(context, opened, handle, code)
            .err()
            .ok_or_else(|| anyhow::anyhow!("inconsistent token-query result accepted"))?;
        ensure!(
            !failure.to_string().contains("private-sentinel"),
            "token-query refusal leaked private label"
        );
    }
    let primary = Arc::new(());
    let first = Arc::new(());
    let second = Arc::new(());
    let attempts = Cell::new(0);
    let attempt = |cause: Option<&Arc<()>>| -> Result<()> {
        attempts.set(attempts.get() + 1);
        match cause {
            Some(cause) => Err(ValidationCause(cause.clone()).into()),
            None => Ok(()),
        }
    };
    let errors = [attempt(Some(&first)), attempt(Some(&second)), attempt(None)]
        .into_iter()
        .filter_map(Result::err)
        .collect();
    finish_cleanup(Some(ValidationCause(primary.clone()).into()), Vec::new())?;
    let failure = finish_cleanup(Some(ValidationCause(primary.clone()).into()), errors)
        .err()
        .ok_or_else(|| anyhow::anyhow!("token-query cleanup lost failure"))?;
    let group = failure
        .downcast_ref::<Failures>()
        .ok_or_else(|| anyhow::anyhow!("token-query cleanup lost error group"))?;
    ensure!(
        attempts.get() == 3 && group.errors.len() == 3,
        "token-query cleanup lost primary/order or attempt"
    );
    for (error, expected) in group.errors.iter().zip([&primary, &first, &second]) {
        ensure!(
            error
                .downcast_ref::<ValidationCause>()
                .is_some_and(|actual| Arc::ptr_eq(&actual.0, expected)),
            "token-query cleanup replaced original error object"
        );
    }
    ensure!(
        !failure.to_string().contains("fixed validation cause")
            && !format!("{failure:?}").contains("fixed validation cause"),
        "token-query cleanup expanded private causes"
    );
    Ok(())
}
