//! Creation diagnostics exercise the controller's real decision seam, not a kernel sandbox.
use super::creation::{CreationFailure, creation_result, retain_cleanup};
use super::{Handle, Profile, null_mut, wide};
use std::cell::{Cell, RefCell};

const OPERATIONS: [&str; 2] = ["CreateRestrictedToken", "CreateProcessAsUserW"];

#[test]
fn failed_creation_captures_once_before_cleanup_and_retains_the_original_code() {
    for operation in OPERATIONS {
        for code in [0, 5, 87, 1314, u32::MAX] {
            let last_error = Cell::new(code);
            let reads = Cell::new(0);
            let events = RefCell::new(Vec::new());
            let result = creation_result(0, false, operation, || {
                reads.set(reads.get() + 1);
                events.borrow_mut().push("last-error");
                last_error.get()
            });
            events.borrow_mut().push("cleanup");
            last_error.set(8);
            let error = retain_cleanup(result, 2).unwrap_err();
            let primary = error.downcast_ref::<CreationFailure>().unwrap();
            assert_eq!(primary.operation, operation);
            assert_eq!(primary.code, Some(code));
            assert_eq!(reads.get(), 1);
            assert_eq!(*events.borrow(), ["last-error", "cleanup"]);
            let display = error.to_string();
            assert!(display.contains(&format!("operation={operation}")));
            assert!(display.contains(&format!("winerror={code} winerror_hex={code:08X}")));
            assert!(display.contains("cleanup also failed in 2 owned operations"));
        }
    }
}

#[test]
fn successful_creation_never_reads_stale_error() {
    for operation in OPERATIONS {
        for success in [1, -1] {
            let result = creation_result(success, true, operation, || {
                panic!("successful creation must not read last-error")
            });
            retain_cleanup(result, 0).unwrap();
        }
    }
}

#[test]
fn successful_api_with_invalid_handles_is_a_separate_failure_before_resume() {
    for operation in OPERATIONS {
        let resumed = Cell::new(false);
        let result = (|| {
            creation_result(1, false, operation, || {
                panic!("invalid success outputs must not read stale last-error")
            })?;
            resumed.set(true);
            Ok(())
        })();
        let error = retain_cleanup(result, 1).unwrap_err();
        let primary = error.downcast_ref::<CreationFailure>().unwrap();
        assert_eq!(primary.operation, operation);
        assert_eq!(primary.code, None);
        assert!(!resumed.get());
        assert!(error.to_string().contains("invalid handles"));
        assert!(!error.to_string().contains("winerror="));
    }
}

#[test]
fn invalid_creation_outputs_never_become_cleanup_owners() {
    let invalid = [std::ptr::null_mut(), -1isize as super::Handle];
    for handle in invalid {
        let mut token = super::Owned::creation_output(handle);
        assert!(token.0.is_null());
        // This is the empty-owner branch: no CloseHandle or other native call.
        token.close().unwrap();
        for thread_handle in invalid {
            let mut process = super::Owned::creation_output(handle);
            let mut thread = super::Owned::creation_output(thread_handle);
            assert!(process.0.is_null() && thread.0.is_null());
            process.close().unwrap();
            thread.close().unwrap();
        }
    }
}

#[test]
fn valid_partial_process_remains_owned_for_reaping_after_invalid_thread() {
    // A fake value is never passed to Win32, closed or dropped as a live owner.
    let handle = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();
    for invalid in [std::ptr::null_mut(), -1isize as super::Handle] {
        let mut process = super::Owned::creation_output(handle);
        let thread = super::Owned::creation_output(invalid);
        let retained = std::mem::replace(&mut process.0, std::ptr::null_mut());
        assert_eq!(retained, handle);
        assert!(thread.0.is_null());
    }
    let source = include_str!("authority_run.rs");
    let cleanup = source
        .split_once("let mut cleanup = Vec::new();")
        .unwrap()
        .1;
    assert!(cleanup.contains("if !process.0.is_null() {"));
    assert!(cleanup.contains("WaitForSingleObject(process.0, 0)"));
    assert!(cleanup.contains("TerminateProcess(process.0, 125)"));
    assert!(cleanup.contains("WaitForSingleObject(process.0, 2000)"));
}

#[test]
fn cleanup_does_not_replace_success_or_expose_an_unrelated_primary_payload() {
    assert_eq!(retain_cleanup(Ok(17), 0).unwrap(), 17);
    assert!(retain_cleanup(Ok(()), 1).is_err());
    let error =
        retain_cleanup::<()>(Err(anyhow::anyhow!("private-payload-canary")), 1).unwrap_err();
    assert_eq!(
        error.to_string(),
        "authority cleanup also failed in 1 owned operations"
    );
    assert!(!error.to_string().contains("private-payload-canary"));
    assert_eq!(error.root_cause().to_string(), "private-payload-canary");
}

fn immediate_capture(source: &str, call: &str, status: &str, operation: &str) -> bool {
    let compact = source.split_whitespace().collect::<String>();
    let Some((_, after_call)) = compact.split_once(call) else {
        return false;
    };
    let Some((_, after_ffi)) = after_call.split_once("};") else {
        return false;
    };
    let Some((statement, _)) = after_ffi.split_once(';') else {
        return false;
    };
    statement.starts_with(&format!("letcreation=creation_result({status},"))
        && statement.contains(&format!("\"{operation}\",||unsafe{{GetLastError()}}"))
}

#[test]
fn actual_creation_calls_capture_before_any_followup_statement() {
    let source = format!(
        "{}\n{}",
        include_str!("authority.rs"),
        include_str!("authority_run.rs")
    );
    let source = source.as_str();
    for (call, status, operation) in [
        ("CreateRestrictedToken(", "success", "CreateRestrictedToken"),
        ("CreateProcessAsUserW(", "created", "CreateProcessAsUserW"),
    ] {
        assert!(immediate_capture(source, call, status, operation));
        let (before, after) = source.split_once(call).unwrap();
        let delayed = after.replacen(
            "let creation = creation_result(",
            "let _ = cleanup_before_capture();\n    let creation = creation_result(",
            1,
        );
        let changed = format!("{before}{call}{delayed}");
        assert_ne!(changed, source);
        assert!(!immediate_capture(&changed, call, status, operation));
    }
    let body = source.split_once("let execution = (|| {").unwrap().1;
    assert!(body.contains("restricted = restricted_primary()?;"));
    assert!(body.find("creation?;").unwrap() < body.find("AssignProcessToJobObject(").unwrap());
    assert!(body.find("creation?;").unwrap() < body.find("NtResumeProcess(").unwrap());
    assert!(body.contains("retain_cleanup(execution, cleanup.len())"));
    assert!(
        body.find("observer.before_create()?").unwrap()
            < body.find("CreateProcessAsUserW(").unwrap()
    );
    assert!(
        body.find("job.finish()").unwrap()
            < body
                .find("observer.after_reap(process_reaped && job_reaped)")
                .unwrap()
    );
    assert!(
        body.find("Lifecycle::Qualified").unwrap() < body.find("observer.before_resume(").unwrap()
    );
    assert!(body.find("observer.before_resume(").unwrap() < body.find("NtResumeProcess(").unwrap());
    assert!(
        source.find("profile.sid_text()?").unwrap()
            < source.find("observer.prepare(&sid)").unwrap()
    );
}

#[test]
fn successful_profile_creation_owns_deletion_even_with_null_sid_and_frees_independently() {
    for has_sid in [false, true] {
        for (free_fails, delete_fails) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let calls = std::cell::RefCell::new(Vec::new());
            let mut profile = Profile {
                name: wide("Scientific.Security.0123456789abcdef0123456789abcdef"),
                sid: if has_sid {
                    1usize as Handle
                } else {
                    null_mut()
                },
                created: true,
                outer_recovery: false,
            };
            let result = profile.close_with(
                |_| {
                    calls.borrow_mut().push("free");
                    if free_fails {
                        anyhow::bail!("fixed free");
                    }
                    Ok(())
                },
                |_| {
                    calls.borrow_mut().push("delete");
                    if delete_fails {
                        anyhow::bail!("fixed delete");
                    }
                    Ok(())
                },
            );
            assert_eq!(
                *calls.borrow(),
                if has_sid {
                    vec!["free", "delete"]
                } else {
                    vec!["delete"]
                }
            );
            assert_eq!(result.is_err(), (has_sid && free_fails) || delete_fails);
            profile
                .close_with(
                    |_| panic!("SID retried"),
                    |_| panic!("profile deletion retried"),
                )
                .unwrap();
        }
    }
    let mut profile = Profile {
        name: wide("unused"),
        sid: null_mut(),
        created: false,
        outer_recovery: false,
    };
    profile
        .close_with(|_| panic!("nonowned SID"), |_| panic!("nonowned profile"))
        .unwrap();
    let mut owned = Profile {
        name: wide("owned by outer recovery"),
        sid: 1usize as Handle,
        created: true,
        outer_recovery: true,
    };
    let freed = Cell::new(false);
    owned
        .close_with(
            |_| {
                freed.set(true);
                Ok(())
            },
            |_| panic!("worker deleted outer-owned profile"),
        )
        .unwrap();
    assert!(freed.get());
}

#[test]
fn observer_preparation_failure_closes_actual_profile_once_and_preserves_primary() {
    // Exercise the same existing aggregation helper with both real cleanup-result branches.
    for cleanup_fails in [false, true] {
        let cleanup: anyhow::Result<()> = if cleanup_fails {
            Err(anyhow::anyhow!("private-profile-close-sentinel"))
        } else {
            Ok(())
        };
        let error = retain_cleanup::<()>(
            Err(anyhow::anyhow!("private-prepare-sentinel")),
            usize::from(cleanup.is_err()),
        )
        .unwrap_err();
        assert_eq!(error.root_cause().to_string(), "private-prepare-sentinel");
        if cleanup_fails {
            assert_eq!(
                error.to_string(),
                "authority cleanup also failed in 1 owned operations"
            );
            assert!(!error.to_string().contains("sentinel"));
        }
    }
    // Source guard binds that helper to the real owner, once and before any process API.
    let source = include_str!("authority_run.rs");
    let boundary = source
        .split_once("if let Err(primary) = observer.prepare(&sid) {")
        .unwrap()
        .1
        .split_once("\n    }")
        .unwrap()
        .0;
    assert_eq!(boundary.matches("profile.close()").count(), 1);
    assert!(
        boundary
            .split_whitespace()
            .collect::<String>()
            .contains("returnretain_cleanup(Err(primary),usize::from(profile.close().is_err()));")
    );
    assert!(!boundary.contains("CreateProcess") && !boundary.contains("NtResumeProcess"));
    assert!(
        source.find("observer.prepare(&sid)").unwrap()
            < source.find("CreateProcessAsUserW(").unwrap()
    );
}

fn metadata_fixture(kind: i32, words: &mut [u64]) -> std::result::Result<usize, u32> {
    assert_eq!(words.len() * 8, 65536);
    assert!(words.iter().all(|word| *word == 0));
    let start = words.as_ptr() as u64;
    let bytes = unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), 65536) };
    let user = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    match kind {
        6 => {
            bytes[..8].copy_from_slice(&(start + 8).to_le_bytes());
            bytes[8..16].copy_from_slice(&[2, 0, 28, 0, 1, 0, 0, 0]);
            bytes[16..24].copy_from_slice(&[0, 0, 20, 0, 8, 0, 0, 0]);
            bytes[24..36].copy_from_slice(&user);
            Ok(36)
        }
        1 | 31 => {
            bytes[..8].copy_from_slice(&(start + 16).to_le_bytes());
            bytes[16..28].copy_from_slice(&user);
            if kind == 31 {
                bytes[23] = 15;
                bytes[24] = 2;
            }
            Ok(28)
        }
        _ => panic!("unexpected metadata query class"),
    }
}

#[test]
fn token_metadata_copies_each_bounded_query_before_reuse_and_closes_once() {
    let order = RefCell::new(Vec::new());
    let record = super::read_default_metadata(
        |kind, words| {
            order.borrow_mut().push(kind);
            metadata_fixture(kind, words)
        },
        || {
            order.borrow_mut().push(-1);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(*order.borrow(), [6, 1, 31, -1]);
    assert!(record.contains("user_allow_mask=0x00000008"));
    assert!(record.ends_with("effective_access_proved=False"));
    assert!(!record.contains("S-1-") && !record.contains("0x1000"));
    let closes = Cell::new(0);
    let null = super::read_default_metadata(
        |kind, words| {
            assert_eq!(kind, 6);
            assert!(words.iter().all(|word| *word == 0));
            Ok(8)
        },
        || {
            closes.set(closes.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        null,
        "WINDOWS_DEFAULT_DACL status=summary default_dacl_null=True effective_access_proved=False"
    );
    assert_eq!(closes.get(), 1);
}

#[test]
fn token_metadata_query_and_shape_uncertainty_are_diagnostic_but_close_failure_is_fatal() {
    for (failed, stage) in [
        (6, "query-default"),
        (1, "identity-query"),
        (31, "identity-query"),
    ] {
        let closes = Cell::new(0);
        let result = super::read_default_metadata(
            |kind, words| {
                if kind == failed {
                    Err(5)
                } else {
                    metadata_fixture(kind, words)
                }
            },
            || {
                closes.set(closes.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        let code = if failed == 6 { 5 } else { 0 };
        assert_eq!(
            result,
            format!(
                "WINDOWS_DEFAULT_DACL status=unknown stage={stage} native_error={code} effective_access_proved=False"
            )
        );
        assert_eq!(closes.get(), 1);
    }
    for (returned, stage) in [
        (7, "default-length"),
        (65537, "default-length"),
        (8, "default-pointer"),
    ] {
        let result = super::read_default_metadata(
            |_, words| {
                words[0] = words.as_ptr() as u64 + 8;
                Ok(returned)
            },
            || Ok(()),
        )
        .unwrap();
        assert!(result.contains(&format!("stage={stage} native_error=0")));
    }
    for fail_query in [false, true] {
        let closes = Cell::new(0);
        let error = super::read_default_metadata(
            |kind, words| {
                if fail_query {
                    Err(5)
                } else {
                    metadata_fixture(kind, words)
                }
            },
            || {
                closes.set(closes.get() + 1);
                Err(anyhow::anyhow!("private-close-sentinel"))
            },
        )
        .unwrap_err();
        assert_eq!(closes.get(), 1);
        assert!(!error.to_string().contains("sentinel"));
    }
    // Original metadata uses signed GetLastWin32Error formatting, never private error text.
    let record = super::read_default_metadata(|_, _| Err(u32::MAX), || Ok(())).unwrap();
    assert_eq!(
        record,
        "WINDOWS_DEFAULT_DACL status=unknown stage=query-default native_error=-1 effective_access_proved=False"
    );
    for (kind, stage) in [
        (6, "ace-spans"),
        (1, "identity-query"),
        (31, "identity-query"),
    ] {
        let record = super::read_default_metadata(
            |query, words| {
                let returned = metadata_fixture(query, words)?;
                if query == kind {
                    if query == 6 {
                        words[1] &= !0xff; // Invalid ACL revision, preserve the length field.
                    } else {
                        words[0] = 0;
                    }
                }
                Ok(returned)
            },
            || Ok(()),
        )
        .unwrap();
        assert!(record.contains(&format!("stage={stage} native_error=0")));
    }
    let source = include_str!("authority_run.rs");
    let position = source
        .find("let metadata = default_metadata(process.0)?;")
        .unwrap();
    assert!(source.find("Lifecycle::Qualified").unwrap() < position);
    assert!(position < source.find("observer.before_resume(").unwrap());
    assert!(position < source.find("NtResumeProcess(").unwrap());
    assert!(source.contains("observer.token_metadata(&metadata)?;"));
    let observer = include_str!("authority_observer.rs");
    assert!(observer.contains("println!(\"{record}\")") && observer.contains("stdout().flush()?"));
    assert!(!observer.contains("stdout().lock()"));
    assert!(observer.contains("std::panic::catch_unwind") && observer.contains("map_err(|_|"));
    let acquisition = include_str!("authority.rs")
        .split_once("fn default_metadata(")
        .unwrap()
        .1;
    assert!(acquisition.contains("OpenProcessToken(process, 8, &mut raw)"));
    assert!(
        !acquisition.contains("SetTokenInformation") && !acquisition.contains("DuplicateToken")
    );
}

#[test]
fn actual_host_metadata_and_invalid_process_keep_the_diagnostic_nonadmission_contract() {
    // Hosted Windows only: no child, token mutation, impersonation or permission change.
    let record = super::default_metadata(unsafe { super::GetCurrentProcess() }).unwrap();
    assert!(record.starts_with("WINDOWS_DEFAULT_DACL status="));
    assert!(record.ends_with("effective_access_proved=False"));
    assert!(!record.contains("S-1-") && !record.contains("effective_access_proved=True"));
    let invalid = super::default_metadata(std::ptr::null_mut()).unwrap();
    assert!(
        invalid.starts_with("WINDOWS_DEFAULT_DACL status=unknown stage=open-token native_error=")
    );
    assert!(!invalid.contains("native_error=0 "));
    assert!(invalid.ends_with("effective_access_proved=False"));
}

#[test]
fn startup_token_observation_uses_the_same_qualified_child_before_resume() {
    let source = include_str!("authority_run.rs");
    let position = source
        .find("super::super::super::sxs::observe_startup_token(")
        .unwrap();
    assert!(source.find("Lifecycle::Qualified").unwrap() < position);
    assert!(position < source.find("observer.before_resume(").unwrap());
    assert!(position < source.find("NtResumeProcess(").unwrap());
    let body = &source[position..source.find("observer.before_resume(").unwrap()];
    assert!(
        body.contains("process.0")
            && body.contains("&sid")
            && body.contains("observer.startup_token(lines)")
    );
    assert_eq!(source.matches("CreateProcessAsUserW(").count(), 1);
    let output = include_str!("authority_observer.rs");
    assert!(
        output.contains("fn startup_token(") && output.contains("self.token_metadata(record)?;")
    );
}

#[test]
fn startup_registry_observation_keeps_the_same_child_and_precedes_resume() {
    let source = include_str!("authority_run.rs");
    let position = source
        .find("startup_access::observe_child(process.0, &sid,")
        .unwrap();
    assert!(source.find("Lifecycle::Qualified").unwrap() < position);
    assert!(position < source.find("observer.before_resume(").unwrap());
    assert!(position < source.find("NtResumeProcess(").unwrap());
    assert!(source.contains("observer.startup_registry(lines)"));
    assert_eq!(source.matches("CreateProcessAsUserW(").count(), 1);
}

#[test]
fn uncertain_profile_registry_close_retains_profile_before_any_profile_delete() {
    let source = include_str!("authority_run.rs");
    let cleanup = source
        .split_once("let mut cleanup = Vec::new();")
        .unwrap()
        .1;
    let registry = cleanup.find("profile_registry.close()").unwrap();
    let retain = cleanup.find("profile.retain()").unwrap();
    let close = cleanup.rfind("profile.close()").unwrap();
    assert!(registry < retain && retain < close);
    assert!(source.contains("profile_registry.prepare(process.0, &sid,"));
    assert_eq!(source.matches("CreateProcessAsUserW(").count(), 1);
}

#[test]
fn no_observer_remains_the_public_default_without_a_host_launch_fallback() {
    let source = include_str!("authority_run.rs");
    assert!(source.contains("run_observed(image, &mut NoObserver)"));
    assert!(!source.contains("CreateProcessW("));
    assert_eq!(
        source
            .matches("observer.before_resume(process.0, &sid, &target)?;")
            .count(),
        1
    );
}
