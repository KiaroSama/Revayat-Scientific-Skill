//! Original LoaderSnaps.CheckValidation and its two called fixture matrices.
use super::*;
use crate::windows_security::scratch;
use std::{cell::Cell, sync::Arc};
fn payload(text: &str, format: u16) -> Vec<u8> {
    if format == 0 {
        text.bytes().chain([0]).collect()
    } else {
        text.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }
}
pub fn check_loader_snaps_validation() -> Result<()> {
    let run = "a".repeat(32);
    let nonce = "b".repeat(32);
    let owned = binding(&run, &nonce, false)?;
    require_state(
        &run,
        &std::env::temp_dir().join(format!("security-windows-{run}")),
    )?;
    ensure!(
        require_state(
            &run,
            &std::env::temp_dir().join(format!("security-windows-{}", "c".repeat(32)))
        )
        .is_err(),
        "foreign loader-snaps state was accepted"
    );
    let receipt = super::receipt(&run, &nonce, false)?;
    ensure!(
        parse_receipt(&receipt, &run, false)? == owned,
        "loader-snaps receipt positive check failed"
    );
    for bad in [
        receipt.replace("startup-native.exe", "python.exe"),
        format!("{receipt}extra\n"),
        super::receipt(&"c".repeat(32), &nonce, false)?,
        receipt.replace(&nonce, "bad"),
    ] {
        ensure!(
            parse_receipt(&bad, &run, false).is_err(),
            "malformed loader-snaps receipt accepted"
        );
    }
    let python = super::receipt(&run, &nonce, true)?;
    ensure!(
        parse_receipt(&python, &run, true)? == binding(&run, &nonce, true)?
            && binding(&run, &nonce, true)? != owned
            && image_name(true) == "startup-python.exe",
        "fixed clone ownership role binding failed"
    );
    for role in [false, true] {
        ensure!(
            parse_receipt(&super::receipt(&run, &nonce, !role)?, &run, role).is_err(),
            "cross-role diagnostic receipt accepted"
        );
    }
    let attempts = Cell::new(0);
    let primary = scratch::failure("fixed diagnostic operation failure");
    let first = scratch::failure("fixed first cleanup failure");
    let second = scratch::failure("fixed second cleanup failure");
    let failure = super::super::trusted_setup::finish_cleanup(
        Some(primary.clone()),
        vec![
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                Err(first.clone())
            }),
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                Err(second.clone())
            }),
        ],
    )
    .unwrap_err();
    let group = failure
        .downcast_ref::<scratch::Failures>()
        .ok_or_else(|| anyhow::anyhow!("diagnostic cleanup lost aggregate"))?;
    ensure!(
        attempts.get() == 2
            && group.errors.len() == 3
            && Arc::ptr_eq(&group.errors[0], &primary)
            && Arc::ptr_eq(&group.errors[1], &first)
            && Arc::ptr_eq(&group.errors[2], &second),
        "diagnostic cleanup lost failures or abandoned a role"
    );
    let text =
        "LdrpCallInitRoutine kernelbase.dll status=0xC0000142 C:\\private\\canary 0x123456789ABC";
    let ascii = payload(text, 0);
    let classified = classify_loader_string(&ascii, 0, false);
    ensure!(
        classified.contains("routine=LdrpCallInitRoutine")
            && classified.contains("module=kernelbase.dll")
            && classified.contains("status=0xC0000142")
            && !classified.contains("private")
            && !classified.contains("123456"),
        "loader classifier lost fixed labels or privacy"
    );
    ensure!(
        classify_loader_string(&payload(text, 1), 1, false) == classified,
        "loader Unicode classifier differs from ASCII"
    );
    for (input, format) in [
        (vec![], 0),
        (vec![0; 4097], 0),
        (vec![65], 0),
        (vec![65, 0, 66, 0], 0),
        (vec![255, 0], 0),
        (vec![65, 0, 0], 1),
        (vec![0, 216, 0, 0], 1),
        (ascii, 2),
    ] {
        ensure!(
            classify_loader_string(&input, format, false) == "phase=unknown format_valid=False",
            "malformed loader bytes accepted"
        );
    }
    for format in [0, 1] {
        let bytes = payload(
            "LdrpInitializeProcess failed python311.dll status=0xC0000022 C:\\private\\canary 0x123456789ABC",
            format,
        );
        ensure!(
            classify_loader_string(&bytes, format, true)
                == "phase=failure format_valid=True routine=LdrpInitializeProcess module_mentioned=python311.dll access_denied_literal_present=True"
                && !classify_loader_string(&bytes, format, false).contains("python311.dll"),
            "Python classifier widened native labels or leaked content"
        );
    }
    let missing = python_evidence(
        "LdrpProcessWork - ERROR: Unable to load DLL: C:\\private\\unknown.dll, Parent Module: C:\\private\\python311.dll; C0000022",
    );
    ensure!(
        missing.contains("message_kind=dll_load_failure")
            && missing.contains("module_mentioned=python311.dll")
            && missing.contains("access_denied_literal_present=True")
            && !missing.contains("unknown.dll")
            && !missing.contains("failed_module"),
        "Python diagnostic role/redaction differs"
    );
    ensure!(
        python_evidence("manifest assembly SXS image import C00000220 secret.dll")
            == " access_denied_literal_present=False",
        "generic words or embedded status became Python evidence"
    );
    ensure!(
        python_evidence(
            "Activation context generation failed; Dependent Assembly public could not be found"
        )
        .contains("message_kind=activation_context_failure,assembly_resolution_failure"),
        "multiple fixed message kinds hidden"
    );
    check_failure_templates()?;
    check_phrase_presence()?;
    for text in [
        "C:\\host\\secret.dll arbitraryRoutine 0xFFFFFFFF",
        "passwordstatus=0xDEADBEEF",
        "status 0xDEADBEEF",
        "status=0xDEADBEEFprivate",
    ] {
        ensure!(
            classify_loader_string(&payload(text, 0), 0, false)
                == "phase=unknown format_valid=True",
            "unknown string or non-label status disclosed content"
        );
    }
    Ok(())
}
fn check_failure_templates() -> Result<()> {
    for index in 0..FAILURE_RECORDS.len() {
        let record = FAILURE_RECORDS[index];
        let expected = format!(
            " diagnostic_template={} diagnostic_status32=0x{} diagnostic_cause_claimed=False",
            FAILURE_IDS[index], FAILURE_STATUSES[index]
        );
        for prefix in [
            "",
            "12ab:34CD @ 00000001 - LdrpInitializeProcess - ERROR: ",
            "12345678:ABCDEF01 @ 1234567890 - LdrpProcessWork - ERROR: ",
        ] {
            for ending in ["", "\n", "\r\n"] {
                for format in [0, 1] {
                    let bytes = payload(&format!("{prefix}{record}{ending}"), format);
                    let python = classify_loader_string(&bytes, format, true);
                    ensure!(
                        python.ends_with(&expected)
                            && !python.contains("private-canary")
                            && !python.contains("12ab")
                            && !classify_loader_string(&bytes, format, false)
                                .contains("diagnostic_template="),
                        "loader failure template parity/privacy differs"
                    );
                }
            }
        }
        for invalid in [
            format!(" {record}"),
            format!("{record} "),
            format!("{record}extra"),
            format!("{record}\r"),
            format!("{record}\n\n"),
            format!("{record}\n{record}"),
            record.replace("0x", "0X"),
            record[..record.len() - 1].into(),
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
            ensure!(
                loader::failure_template(&invalid).is_none(),
                "malformed loader failure template accepted"
            );
        }
    }
    for decoy in [
        String::new(),
        "private 0xC0000022".into(),
        FAILURE_RECORDS[0].replace("private-canary", "0xDEADBEEF"),
        FAILURE_RECORDS[0].replace(
            "private-canary",
            "Calling LdrpInitializeKernel32Functions failed with status ",
        ),
        FAILURE_RECORDS[2].replace("private-canary", "one Status = two"),
        FAILURE_RECORDS[0].replace("hidden.dll", "bad\"name"),
        FAILURE_RECORDS[2].replace("private-canary", "one\ttwo"),
        FAILURE_RECORDS[0].replace("private-canary", "one\u{2028}two"),
        "x".repeat(4097),
    ] {
        ensure!(
            loader::failure_template(&decoy).is_none(),
            "loader failure substitution/oversize decoy accepted"
        );
    }
    Ok(())
}
fn check_phrase_presence() -> Result<()> {
    use phrases::PHRASES;
    for (index, (id, phrase)) in PHRASES.iter().enumerate() {
        let ids = if index == 8 {
            "mrdata_init,process_init"
        } else {
            id
        };
        let expected = format!(" diagnostic_phrase_ids={ids} phrase_presence_only=True");
        ensure!(
            phrase_presence(phrase) == expected
                && phrase_presence(&phrase.repeat(2)) == expected
                && phrase_presence(&phrase.to_lowercase()).is_empty(),
            "phrase presence/deduplication/case differs"
        );
        for format in [0, 1] {
            let bytes = payload(
                &format!("opaque-private-canary[{phrase}] 0xDEADBEEF"),
                format,
            );
            let python = classify_loader_string(&bytes, format, true);
            ensure!(
                python.ends_with(&expected)
                    && !python.contains("private-canary")
                    && !python.contains("DEADBEEF")
                    && !python.contains("diagnostic_template=")
                    && !python.contains("diagnostic_status32=")
                    && !classify_loader_string(&bytes, format, false)
                        .contains("diagnostic_phrase_ids="),
                "phrase gained attribution or leaked opaque data"
            );
        }
    }
    let text = PHRASES
        .iter()
        .rev()
        .map(|(_, phrase)| *phrase)
        .collect::<Vec<_>>()
        .join("|");
    let all = phrase_presence(&text);
    ensure!(
        all == format!(
            " diagnostic_phrase_ids={} phrase_presence_only=True",
            PHRASES
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>()
                .join(",")
        ) && all.len() <= 1024
            && all.is_ascii()
            && phrase_presence("failed error SXS status private-canary").is_empty(),
        "phrase ordering/output bound/unknown differs"
    );
    for index in [12, 15, 17] {
        ensure!(
            classify_loader_string(&payload(PHRASES[index].1, 0), 0, true)
                .starts_with("phase=unknown format_valid=True"),
            "nonfailure phrase changed phase"
        );
    }
    Ok(())
}
const FAILURE_RECORDS: [&str; 8] = [
    "Probing for the manifest of DLL \"C:\\private-canary\\hidden.dll\" failed with status 0xc0000022",
    "Querying the active activation context failed with status 0x00000001",
    "SXS: Unable to open registry key \\Registry\\private-canary Status = 0xC0000034",
    "SXS: Unable to open storage root subkey private-canary; Status = 0xFFFFFFFF",
    "SXS: RtlGetAssemblyStorageRoot() unable to resolve storage map entry.  Status = 0x80000000",
    "Initializing the current directory to \"C:\\private-canary\" failed with status 0x00000000",
    "Calling LdrpInitializeKernel32Functions failed with status 0xC0000022",
    "LdrpCodeAuthzInitialize failed with status 0xDEADBEEF",
];
const FAILURE_IDS: [&str; 8] = [
    "dll_manifest_probe_failed",
    "active_actctx_query_failed",
    "sxs_registry_key_open_failed",
    "sxs_storage_root_subkey_open_failed",
    "sxs_storage_map_resolution_failed",
    "current_directory_init_failed",
    "kernel32_functions_init_failed",
    "code_authz_init_failed",
];
const FAILURE_STATUSES: [&str; 8] = [
    "C0000022", "00000001", "C0000034", "FFFFFFFF", "80000000", "00000000", "C0000022", "DEADBEEF",
];
