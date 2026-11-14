//! Source-derived activation contracts. Native fixture calls are Windows-only, not LPAC proof.
use revayat_scientific::windows_security::activation::*;
use std::cell::RefCell;
use std::mem::{offset_of, size_of};

#[test]
fn actctx_x64_layout_and_fixed_roles_do_not_alias() {
    check_startup_activation_validation().unwrap();
    check_fixed_dll_validation().unwrap();
    check_policy_result_validation().unwrap();
    check_manual_activation_validation().unwrap();
    automatic::check_validation().unwrap();
    csr::check_validation().unwrap();
    csr::check_module_validation().unwrap();
    preparation::check_validation().unwrap();
    let (_validation_work, validation_root) = super::owned_fixture_directory();
    native_pass::check_validation(&validation_root).unwrap();
    fixtures::child::check_child_validation(&validation_root).unwrap();
    fixtures::dll_request::check_dll_request_validation().unwrap();
    fixtures::default::check_default_validation(&validation_root).unwrap();
    fixtures::self_host::check_self_validation(&validation_root).unwrap();
    fixtures::source::check_self_source_validation().unwrap();
    fixtures::module::check_module_validation(&validation_root).unwrap();
    boundary::check_validation().unwrap();
    module_callback::check_validation().unwrap();
    if size_of::<usize>() == 8 {
        assert_eq!(size_of::<ActCtx>(), 56);
        assert_eq!(
            [
                offset_of!(ActCtx, size),
                offset_of!(ActCtx, flags),
                offset_of!(ActCtx, source),
                offset_of!(ActCtx, architecture),
                offset_of!(ActCtx, language),
                offset_of!(ActCtx, directory),
                offset_of!(ActCtx, resource),
                offset_of!(ActCtx, application),
                offset_of!(ActCtx, module)
            ],
            [0, 4, 8, 16, 18, 24, 32, 40, 48]
        );
    }
    for (role, flags, resource) in [
        (CallRole::Executable, 0x2e, 1),
        (CallRole::DllResource, 0x2e, 2),
        (CallRole::HostDll, 8, 2),
        (CallRole::StandaloneManifest, 0, 0),
    ] {
        let context = ActCtx::fixed(role, 0x1000, 0x2000, 1033);
        assert_eq!(
            (
                context.size,
                context.flags,
                context.resource,
                context.module,
                context.architecture
            ),
            (56, flags, resource, 0, 0)
        );
        assert_eq!(context.source, 0x1000);
        assert_eq!(context.language, if flags & 2 != 0 { 1033 } else { 0 });
        assert_eq!(context.directory, if flags & 4 != 0 { 0x2000 } else { 0 });
        assert_eq!(
            context.application,
            if flags & 0x20 != 0 { 0x1000 } else { 0 }
        );
    }
    for error in [0, 5, 8, 14001, u32::MAX] {
        let calls = RefCell::new(Vec::new());
        let result = creation_outcome(usize::MAX, || {
            calls.borrow_mut().push("error");
            error
        })
        .unwrap();
        calls.borrow_mut().push("cleanup");
        assert_eq!(*calls.borrow(), ["error", "cleanup"]);
        assert_eq!(
            result,
            ActivationOutcome {
                created: false,
                error
            }
        );
    }
    assert_eq!(
        creation_outcome(7, || panic!("success must not read stale last-error")).unwrap(),
        ActivationOutcome {
            created: true,
            error: 0
        }
    );
    assert!(creation_outcome(0, || panic!("null is not an API failure code")).is_err());
}

#[test]
fn host_context_requires_absent_thread_token_not_denied_query_or_valid_impersonation() {
    require_absent_thread_token(false, 1008, 0).unwrap();
    for (opened, error, token) in [
        (true, 0, 7),
        (true, 0, 0),
        (false, 5, 0),
        (false, 1008, 7),
        (false, 1008, usize::MAX),
        (false, 0, 0),
    ] {
        assert!(require_absent_thread_token(opened, error, token).is_err());
    }
}

#[test]
fn finalization_reverts_before_independent_cleanup_and_preserves_failure_order() {
    revayat_scientific::windows_security::diagnostic_validation::check_startup_image_access_validation().unwrap();
    let order = RefCell::new(Vec::new());
    let cleanup: Vec<Box<dyn FnMut() -> anyhow::Result<()> + '_>> = vec![
        Box::new(|| {
            order.borrow_mut().push("close1");
            anyhow::bail!("first-close")
        }),
        Box::new(|| {
            order.borrow_mut().push("close2");
            Ok(())
        }),
    ];
    let failure = finalize_comparison(
        Some(anyhow::anyhow!("primary")),
        true,
        || {
            order.borrow_mut().push("revert");
            Ok(())
        },
        || {
            order.borrow_mut().push("fatal");
        },
        cleanup,
        || {
            order.borrow_mut().push("emit");
            anyhow::bail!("report")
        },
    )
    .unwrap_err();
    assert_eq!(*order.borrow(), ["revert", "close1", "close2", "emit"]);
    let failures = failure.downcast_ref::<Failures>().unwrap();
    assert_eq!(
        failures
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["primary", "first-close", "report"]
    );
    for throwing in [false, true] {
        order.borrow_mut().clear();
        let cleanup: Vec<Box<dyn FnMut() -> anyhow::Result<()> + '_>> = vec![Box::new(|| {
            order.borrow_mut().push("cleanup");
            Ok(())
        })];
        assert!(
            finalize_comparison(
                None,
                true,
                || {
                    order.borrow_mut().push("revert");
                    anyhow::bail!(if throwing {
                        "revert threw"
                    } else {
                        "revert false"
                    })
                },
                || {
                    order.borrow_mut().push("fatal");
                },
                cleanup,
                || {
                    order.borrow_mut().push("emit");
                    Ok(())
                }
            )
            .is_err()
        );
        assert_eq!(*order.borrow(), ["revert", "fatal"]);
    }
    assert!(bounded_report(&["x".repeat(12286)], "\r\n").is_ok());
    assert!(bounded_report(&["x".repeat(12287)], "\r\n").is_err());
    assert!(bounded_report(&vec!["fixed".to_owned(); 15], "\n").is_ok());
    assert!(bounded_report(&vec!["fixed".to_owned(); 16], "\n").is_err());
}

#[test]
fn debug_context_distinguishes_owned_traps_from_exact_setter_readback() {
    revayat_scientific::windows_security::diagnostic_validation::check_debug_control_validation()
        .unwrap();
    for slot in 0..2 {
        for rtm in [0, 0x10000] {
            for fixed in [0, 0x400] {
                let enabled = 1 << (slot * 2);
                let status = 0xfffe0ff0 | rtm | (1 << slot);
                assert!(owned_trap_status(status, enabled | fixed, enabled, slot));
                for foreign in [4, 8, 0x2000, 0x4000, 0x8000, 0x100000000] {
                    assert!(!owned_trap_status(status | foreign, enabled, enabled, slot));
                }
                for foreign in [
                    2,
                    0x100,
                    0x200,
                    0x800,
                    0x2000,
                    0x10000,
                    0x40000,
                    0x100000000,
                ] {
                    assert!(!owned_trap_status(status, enabled | foreign, enabled, slot));
                }
                for wrong in [
                    status ^ 0x800,
                    status ^ 0x10,
                    status | 0x1000,
                    status | (1 << (1 - slot)),
                ] {
                    assert!(!owned_trap_status(wrong, enabled, enabled, slot));
                }
                assert!(!owned_trap_status(status, enabled, enabled, 1 - slot));
                assert!(!owned_trap_status(status, 0, 0, slot));
            }
        }
    }
    assert!(owned_trap_site(7, 7, true, true, 100, 100));
    for (thread, first, enabled, instruction, configured) in [
        (8, true, true, 100, 100),
        (7, false, true, 100, 100),
        (7, true, false, 100, 100),
        (7, true, true, 101, 100),
        (7, true, true, 0, 0),
    ] {
        assert!(!owned_trap_site(
            thread,
            7,
            first,
            enabled,
            instruction,
            configured
        ));
    }
    let original = vec![0; CONTEXT_SIZE];
    for offset in [72, 80, 88, 96, 104, 112] {
        let mut changed = original.clone();
        changed[offset] = 1;
        assert!(!raw_debug_equal(&original, &changed).unwrap());
        assert!(unchanged_control_integer(&original, &changed).unwrap());
    }
    for offset in [56, 66, 68, 120, 128, 136, 152, 248] {
        let mut changed = original.clone();
        changed[offset] = 1;
        assert!(!unchanged_control_integer(&original, &changed).unwrap());
    }
    assert!(raw_debug_equal(&original[..100], &original).is_err());
    assert!(trap_qualifiers(0xffff0ff1).contains("transaction_context=unknown"));
    assert!(trap_qualifiers(0xfffe0ff1).contains("rtm_bit_set=False"));
    assert!(trap_qualifiers(0xffff0ff1).contains("rtm_bit_set=True"));
    assert!(trap_qualifiers(0xfffe0ff1).contains("bld_bit_set=True"));
}

#[test]
fn event_cleanup_refuses_uncertain_double_close_and_preserves_overflow_owner() {
    let mut ledger = EventCleanup::default();
    let mut handle = 17;
    let mut closes = 0;
    assert!(
        ledger
            .close(&mut handle, |_| {
                closes += 1;
                anyhow::bail!("close")
            })
            .is_err()
    );
    assert_eq!((handle, closes, ledger.unresolved()), (0, 1, 1));
    handle = 17;
    assert!(
        ledger
            .close(&mut handle, |_| {
                closes += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!((handle, closes), (0, 1));
    handle = 18;
    ledger
        .close(&mut handle, |_| {
            closes += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!((handle, closes, ledger.unresolved()), (0, 2, 1));
    assert!(ledger.require_clean().is_err());
    let mut full = EventCleanup::default();
    for value in 100..360 {
        let mut handle = value;
        assert!(full.close(&mut handle, |_| anyhow::bail!("close")).is_err());
        assert_eq!(handle, 0);
    }
    handle = 400;
    assert!(
        full.close(&mut handle, |_| panic!("overflow may not discard owner"))
            .is_err()
    );
    assert_eq!((handle, full.unresolved()), (400, 260));
    assert!(full.overflowed());
}

#[test]
fn event_failure_restores_before_release_then_continues_exactly_once() {
    let order = RefCell::new(Vec::new());
    let releases: Vec<Box<dyn FnMut() -> anyhow::Result<()> + '_>> = vec![
        Box::new(|| {
            order.borrow_mut().push("close");
            anyhow::bail!("close")
        }),
        Box::new(|| {
            order.borrow_mut().push("close2");
            Ok(())
        }),
    ];
    let error = activation_event(
        || {
            order.borrow_mut().push("operation");
            anyhow::bail!("operation")
        },
        || {
            order.borrow_mut().push("restore");
            anyhow::bail!("restore")
        },
        releases,
        || {
            order.borrow_mut().push("continue");
            anyhow::bail!("continue")
        },
    )
    .unwrap_err();
    assert_eq!(
        *order.borrow(),
        ["operation", "restore", "close", "close2", "continue"]
    );
    assert_eq!(
        error
            .downcast_ref::<Failures>()
            .unwrap()
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["operation", "restore", "close", "continue"]
    );
    order.borrow_mut().clear();
    let releases: Vec<Box<dyn FnMut() -> anyhow::Result<()> + '_>> = vec![Box::new(|| {
        order.borrow_mut().push("close");
        anyhow::bail!("close")
    })];
    assert!(
        activation_event(
            || {
                order.borrow_mut().push("operation");
                Ok(())
            },
            || {
                order.borrow_mut().push("restore");
                Ok(())
            },
            releases,
            || {
                order.borrow_mut().push("continue");
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(
        *order.borrow(),
        ["operation", "close", "restore", "continue"]
    );
}

#[cfg(windows)]
#[test]
fn actual_host_activation_context_and_collector_negative_control_release_owned_handles() {
    use revayat_scientific::windows_security::activation::native::{
        ManifestRole, observe_manifest,
    };
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let run = "a".repeat(32);
    revayat_scientific::windows_security::activation::native::check_assembly_validation(
        root.path(),
    )
    .unwrap();
    let events_start = revayat_scientific::windows_security::sxs::native_events::utc_now().unwrap();
    for role in [ManifestRole::Host, ManifestRole::CollectorControl] {
        let path = root.path().join(role.filename());
        let expected = role.bytes(&run).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(&expected).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let proof = observe_manifest(&path, &run, role).unwrap();
        assert_eq!(proof.created, role == ManifestRole::Host);
        assert_eq!(
            proof.error,
            if role == ManifestRole::Host { 0 } else { 14001 }
        );
        assert_eq!(
            proof.assemblies,
            if role == ManifestRole::Host { 1 } else { 0 }
        );
        assert_eq!(
            proof.assembly_metadata.len(),
            if role == ManifestRole::Host {
                proof.assemblies as usize + 1
            } else {
                0
            }
        );
        for line in &proof.assembly_metadata {
            assert!(line.ends_with("cause_claimed=False"));
            assert!(!line.contains(&root.path().to_string_lossy().to_string()));
        }
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        let mut changed = expected;
        changed.push(b' ');
        std::fs::write(&path, &changed).unwrap();
        assert!(observe_manifest(&path, &run, role).is_err());
    }
    let host =
        revayat_scientific::windows_security::activation::native::observe_explicit_host_fixture()
            .unwrap();
    assert_eq!(
        host,
        "WINDOWS_EXPLICIT_ID2_ACTIVATION entry_reached=True created=True win32_error=0x00000000"
    );
    let fixture =
        revayat_scientific::executable_paths::binary_directory(&std::env::current_exe().unwrap())
            .unwrap()
            .join("startup-explicit-id2.exe");
    let python = root.path().join("python.exe");
    std::fs::create_dir(root.path().join("DLLs")).unwrap();
    std::fs::copy(&fixture, &python).unwrap();
    std::fs::copy(&fixture, root.path().join("DLLs").join("_ctypes.pyd")).unwrap();
    let dll = revayat_scientific::windows_security::activation::native::observe_fixed_dll(&python)
        .unwrap();
    assert!(dll.outcome.created && dll.outcome.error == 0 && dll.outcome.released);
    assert!(
        dll.metadata
            .contains("resource_type=24 resource_id=2 resource_language=1033")
    );
    assert!(
        dll.metadata.contains(
            "cache_reset_claimed=False cause_claimed=False child_equivalence_claimed=False"
        )
    );
    assert!(
        revayat_scientific::windows_security::activation::native::observe_fixed_dll(&python)
            .is_err()
    );
    let events_end = revayat_scientific::windows_security::sxs::native_events::utc_now().unwrap();
    let lines = revayat_scientific::windows_security::sxs::native_events::observe_startup_events(
        &root.path().join("python.exe"),
        &events_start,
        &events_end,
    )
    .unwrap_or_else(|error| panic!("{}", diagnostics::summary(&error)));
    let summary = lines.last().unwrap();
    assert!(summary.starts_with("WINDOWS_SXS_EVENTS phase=modified-preflight scanned_count="));
    assert!(summary.ends_with("producer_verified=False cause_claimed=False"));
    for line in &lines {
        assert!(!line.contains(&root.path().to_string_lossy().to_string()));
        assert!(!line.contains("Dependent Assembly"));
    }
}
