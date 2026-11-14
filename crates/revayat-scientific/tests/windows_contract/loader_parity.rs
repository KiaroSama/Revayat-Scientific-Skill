//! Bounded loader text and requested-byte ownership. No diagnostic configuration is installed.
use revayat_scientific::windows_security::activation::loader::*;
fn encoded(text: &str, unicode: bool) -> Vec<u8> {
    if unicode {
        text.encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    } else {
        [text.as_bytes(), &[0]].concat()
    }
}

#[test]
fn loader_records_preserve_closed_labels_without_paths_or_absolute_addresses() {
    let text =
        "LdrpCallInitRoutine kernelbase.dll status=0xC0000142 C:\\private\\canary 0x123456789ABC";
    let expected = "phase=failure format_valid=True routine=LdrpCallInitRoutine module=kernelbase.dll status=0xC0000142";
    for unicode in [false, true] {
        assert_eq!(
            classify(&encoded(text, unicode), u16::from(unicode)).unwrap(),
            expected
        );
    }
    for (bytes, unicode) in [
        (vec![], 0),
        (vec![0; 4097], 0),
        (vec![65], 0),
        (vec![65, 0, 66, 0], 0),
        (vec![255, 0], 0),
        (vec![65, 0, 0], 1),
        (vec![0, 216, 0, 0], 1),
        (encoded(text, false), 2),
    ] {
        assert!(classify(&bytes, unicode).is_err());
    }
    for text in [
        "C:\\host\\secret.dll arbitraryRoutine 0xFFFFFFFF",
        "passwordstatus=0xDEADBEEF",
        "status 0xDEADBEEF",
        "status=0xDEADBEEFprivate",
        "privateLdrpInitializeProcess privatekernelbase.dll",
    ] {
        assert_eq!(
            classify(&encoded(text, false), 0).unwrap(),
            "phase=unknown format_valid=True"
        );
    }
    assert_eq!(classify(&encoded("status = 0xdeadbeef status:0xC0000022 status=0x00000000 status=0x80000000 status=0xFFFFFFFF", false), 0).unwrap(),
        "phase=failure format_valid=True status=0xDEADBEEF,0xC0000022,0x00000000,0x80000000");
}

#[test]
fn exact_failure_templates_refuse_wrapping_substitution_and_partial_statuses() {
    let records = [
        (
            "Probing for the manifest of DLL \"C:\\private-canary\\hidden.dll\" failed with status 0xc0000022",
            "dll_manifest_probe_failed",
            "C0000022",
        ),
        (
            "Querying the active activation context failed with status 0x00000001",
            "active_actctx_query_failed",
            "00000001",
        ),
        (
            "SXS: Unable to open registry key \\Registry\\private-canary Status = 0xC0000034",
            "sxs_registry_key_open_failed",
            "C0000034",
        ),
        (
            "SXS: Unable to open storage root subkey private-canary; Status = 0xFFFFFFFF",
            "sxs_storage_root_subkey_open_failed",
            "FFFFFFFF",
        ),
        (
            "SXS: RtlGetAssemblyStorageRoot() unable to resolve storage map entry.  Status = 0x80000000",
            "sxs_storage_map_resolution_failed",
            "80000000",
        ),
        (
            "Initializing the current directory to \"C:\\private-canary\" failed with status 0x00000000",
            "current_directory_init_failed",
            "00000000",
        ),
        (
            "Calling LdrpInitializeKernel32Functions failed with status 0xC0000022",
            "kernel32_functions_init_failed",
            "C0000022",
        ),
        (
            "LdrpCodeAuthzInitialize failed with status 0xDEADBEEF",
            "code_authz_init_failed",
            "DEADBEEF",
        ),
    ];
    for (record, label, status) in records {
        let expected = format!(
            "diagnostic_template={label} diagnostic_status32=0x{status} diagnostic_cause_claimed=False"
        );
        for prefix in [
            "",
            "12ab:34CD @ 00000001 - LdrpInitializeProcess - ERROR: ",
            "12345678:ABCDEF01 @ 1234567890 - LdrpProcessWork - ERROR: ",
        ] {
            for ending in ["", "\n", "\r\n"] {
                assert_eq!(
                    failure_template(&format!("{prefix}{record}{ending}")),
                    Some(expected.clone())
                );
            }
        }
        for bad in [
            format!(" {record}"),
            format!("{record} "),
            format!("{record}extra"),
            format!("{record}\r"),
            format!("{record}\n\n"),
            format!("{record}\n{record}"),
            record.replace("0x", "0X"),
            record[..record.len() - 1].to_owned(),
            format!("{record}0"),
            format!("{}G", &record[..record.len() - 1]),
            record.to_lowercase(),
            format!("12ab:34cd @ 00000001 - LdrpInit - WARNING: {record}"),
            format!("123:34cd @ 00000001 - LdrpInit - ERROR: {record}"),
            format!("12ab:34cd @ 0000001 - LdrpInit - ERROR: {record}"),
            format!(
                "12ab:34cd @ 00000001 - LdrpInit - ERROR: 12ab:34cd @ 00000001 - LdrpInit - ERROR: {record}"
            ),
        ] {
            assert!(failure_template(&bad).is_none());
        }
    }
    for decoy in [
        "Probing for the manifest of DLL \"0xDEADBEEF\" failed with status 0xC0000022",
        "Probing for the manifest of DLL \"bad\"name\" failed with status 0xC0000022",
        "SXS: Unable to open registry key one Status = two Status = 0xC0000022",
    ] {
        assert!(failure_template(decoy).is_none());
    }
}

#[test]
fn debug_string_ceiling_and_breakpoint_qualification_consume_real_requests() {
    let mut budget = DebugStringBudget::default();
    assert!(budget.take(false));
    assert!(!budget.take(false));
    assert!(budget.take(true));
    for _ in 0..16 {
        budget.charge(4096).unwrap();
    }
    assert_eq!(budget.requested(), 65536);
    for length in [0, 1, 4097, usize::MAX] {
        assert!(budget.charge(length).is_err());
        assert_eq!(budget.requested(), 65536);
    }
    let mut calls = 0;
    assert!(
        accept_initial(11, 11, 0x80000003, true, false, || {
            calls += 1;
            Ok(())
        })
        .unwrap()
    );
    for (thread, code, first, seen) in [
        (12, 0x80000003, true, false),
        (11, 0x80000004, true, false),
        (11, 0x80000003, false, false),
        (11, 0x80000003, true, true),
    ] {
        assert!(
            !accept_initial(thread, 11, code, first, seen, || {
                calls += 1;
                Ok(())
            })
            .unwrap()
        );
    }
    assert_eq!(calls, 1);
    assert!(
        accept_initial(11, 11, 0x80000003, true, false, || anyhow::bail!(
            "incomplete"
        ))
        .is_err()
    );
}
