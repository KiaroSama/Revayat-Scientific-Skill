//! Original RegistryAuthorityComparison failure projection and RegistryLoaderEvidence assertions.
use super::*;
use std::error::Error;
use std::sync::Arc;
const ORIGINAL: &str = "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=import-ctypes:import-ctypes-native\n";
fn accepted(text: &str) -> Result<()> {
    ensure!(
        failure_detail(text).is_some(),
        "fixed registry failure receipt lost known fields"
    );
    Ok(())
}
fn refused(text: &str) -> Result<()> {
    let error = transport_failure(1, Some(text));
    let rendered = format!("{error:?} {error}");
    ensure!(
        rendered.contains("unqualified")
            && !rendered.contains("sentinel")
            && !rendered.contains("native_error=")
            && !rendered.contains("restrictions="),
        "registry failure projection accepted or leaked invalid metadata"
    );
    Ok(())
}
pub fn check_validation() -> Result<()> {
    for kind in protocol::NETWORK_CHECKS {
        for status in [None, Some(0u32), Some(10013), Some(u32::MAX)] {
            let suffix = status.map_or(String::new(), |code| format!(" native_error={code:08X}"));
            let frame = format!(
                "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=mutation:{kind}{suffix}\n"
            );
            accepted(&frame)?;
            let error = validate_wire(1, None, Some(&frame)).unwrap_err();
            ensure!(
                error.to_string().contains("primary_exit=0x00000001")
                    && error.to_string().contains(&format!("mutation:{kind}")),
                "a known network refusal must remain an actual failed worker"
            );
        }
    }
    for invalid in [
        "mutation:network-private native_error=0000271D",
        "mutation:network-startup native_error=private-sentinel",
        "mutation:network-startup native_error=0000271d",
        "mutation:network-startup native_error=0000271D extra=private-sentinel",
        "panic:network-startup native_error=0000271D",
    ] {
        refused(&format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors={invalid}\n"
        ))?;
    }
    for phase in protocol::PANIC_CHECKS {
        let frame = format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=panic:{phase}\n"
        );
        accepted(&frame)?;
        let failed = validate_wire(101, None, Some(&frame)).unwrap_err();
        ensure!(
            failed.to_string().contains("primary_exit=0x00000065")
                && failed
                    .to_string()
                    .contains(&format!("errors=panic:{phase}")),
            "actual panic exit must remain fatal with its closed operation"
        );
    }
    refused(
        "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=panic:private-sentinel\n",
    )?;
    let wire = "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000007 errors=descendant:transport,root:control,close:cleanup\n";
    let error = validate_wire(1, Some("private-stdout-sentinel"), Some(wire)).unwrap_err();
    ensure!(
        error.to_string()
            == "fixed registry authority failed primary_exit=0x00000001 child_exit=00000007 errors=descendant:transport,root:control,close:cleanup raw_error_withheld=True"
            && error.source().is_none()
            && !format!("{error:?}").contains("private"),
        "registry authority failure projection changed"
    );
    for code in [7, 259, 0xc0000022, u32::MAX] {
        let error = validate_wire(
            code,
            Some("private-stdout-sentinel"),
            Some("private-error-sentinel"),
        )
        .unwrap_err();
        ensure!(
            error
                .to_string()
                .contains(&format!("primary_exit=0x{code:08X}"))
                && error.to_string().contains("unqualified")
                && !format!("{error:?}").contains("sentinel"),
            "registry authority raw failure escaped redaction"
        );
    }
    for stage in protocol::TOKEN_CHECKS {
        accepted(&format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000007 errors=descendant:transport,token:{stage},close:cleanup\n"
        ))?;
        accepted(&format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=token:{stage}\n"
        ))?;
    }
    for prefix in ["ti-", "tf-"] {
        for stage in PYTHON_TOKEN_STAGES.split('|') {
            for kind in ["control", "other", "native"] {
                accepted(&format!(
                    "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000007 errors=descendant:transport,{prefix}{stage}:{kind},close:cleanup\n"
                ))?;
            }
        }
    }
    for invalid in [
        "ti-private:control",
        "tf-openx:control",
        "ti-open:import",
        "token-initial:control",
        "ti-restrictions-len1:control restrictions=1:00000001:none",
        "tf-restrictions-query:control restrictions=0:00000004:00000005",
        "ti-open:control native_error=00000005",
    ] {
        refused(&format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors={invalid}\n"
        ))?;
    }
    for stage in protocol::DESCENDANT_CHECKS {
        accepted(&format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=descendant:{stage}\n"
        ))?;
    }
    for stage in protocol::NATIVE_CHECKS {
        for code in ["00000000", "00000005", "FFFFFFFF"] {
            accepted(&format!(
                "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=descendant:{stage},close:cleanup native_error={code}\n"
            ))?;
        }
    }
    for invalid in [
        "descendant:control-create-process native_error=ffffffff",
        "descendant:control-create-process native_error=000000005",
        "descendant:control-create-process native_error=private-sentinel",
        "descendant:control-create-process native_error=00000005 native_error=00000005",
        "descendant:control-create-process restrictions=0:00000004:00000005 native_error=00000005",
        "token:control-restrictions-query restrictions=0:00000004:00000005 native_error=00000005",
        "token:control-open native_error=00000005",
        "root:control-create-process native_error=00000005",
        "descendant:control native_error=00000005",
        "descendant:control-input-handle native_error=00000005",
        "descendant:control-capture-eof native_error=00000005",
        "descendant:control-private-sentinel",
    ] {
        refused(&format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors={invalid}\n"
        ))?;
    }
    for query in [
        "0:00000004:00000005",
        "0:00000000:00000000",
        "1:00000000:none",
        "0:FFFFFFFF:FFFFFFFF",
    ] {
        for events in [
            "token:control-restrictions-query",
            "descendant:transport,token:control-restrictions-query,close:cleanup",
        ] {
            accepted(&format!(
                "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000007 errors={events} restrictions={query}\n"
            ))?;
        }
    }
    for query in [
        "1:00000001:none",
        "1:00000004:none",
        "1:00000000:00000005",
        "0:00000004:none",
        "2:00000000:none",
        "0:ffffffff:00000005",
        "0:000000004:00000005",
        "0:00000004:private-sentinel",
        "0:00000004:00000005:extra",
        "0:00000004:00000005 restrictions=0:00000004:00000005",
    ] {
        refused(&format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=token:control-restrictions-query restrictions={query}\n"
        ))?;
    }
    for stage in ["primary-fields", "open"] {
        refused(&format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=token:control-{stage} restrictions=0:00000004:00000005\n"
        ))?;
    }
    for event in [
        "token:control-private-sentinel",
        "root:control-open",
        "token:control-openx",
    ] {
        refused(&format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors={event}\n"
        ))?;
    }
    let longest = protocol::TOKEN_CHECKS
        .iter()
        .max_by_key(|stage| stage.len())
        .unwrap();
    let worst = format!(
        "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=FFFFFFFF errors={}\n",
        vec![format!("token:{longest}"); 8].join(",")
    );
    ensure!(worst.len() <= 512 && worst.is_ascii());
    accepted(&worst)?;
    let query_worst = format!(
        "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=FFFFFFFF errors=token:control-restrictions-query,{} restrictions=0:FFFFFFFF:FFFFFFFF\n",
        vec![format!("token:{longest}"); 7].join(",")
    );
    ensure!(query_worst.len() <= 512 && query_worst.is_ascii());
    accepted(&query_worst)?;
    accepted(
        "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=descendant:timeout\n",
    )?;
    for phase in [
        "ctypes",
        "ctypes-wintypes",
        "json",
        "os",
        "pathlib",
        "runpy",
        "subprocess",
        "time",
    ] {
        accepted(&format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=import-{phase}:import\n"
        ))?;
    }
    for prefix in ["import-", "missing-"] {
        for label in [
            "ctypes",
            "ctypes-native",
            "struct",
            "struct-native",
            "endian",
            "os",
            "types",
            "absent",
            "unrecognized",
        ] {
            accepted(&format!(
                "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000001 errors=descendant:transport,import-ctypes:{prefix}{label}\n"
            ))?;
        }
    }
    for label in ["denied", "module", "procedure", "init", "memory", "format"] {
        accepted(&format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000001 errors=descendant:transport,import-ctypes:import-ctypes-{label}\n"
        ))?;
        refused(&format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000001 errors=descendant:transport,import-ctypes:missing-ctypes-{label}\n"
        ))?;
    }
    let eight = format!(
        "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000001 errors={}\n",
        ["import-ctypes-wintypes:missing-unrecognized"; 8].join(",")
    );
    ensure!(eight.len() <= 512);
    accepted(&eight)?;
    for invalid in [
        eight.replace("errors=", "errors=root:control,"),
        format!("{eight}\n"),
        "x".repeat(513),
        wire.replace("root:control", "import-ctypes:import-private"),
        wire.replace("root:control", "import-ctypes:missing-private"),
        wire.replace("root:control", "root:private"),
    ] {
        refused(&invalid)?;
    }
    let native_worst = format!(
        "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=FFFFFFFF errors={} native_error=FFFFFFFF\n",
        ["descendant:control-output-pipe-inheritance"; 8].join(",")
    );
    ensure!(native_worst.len() <= 512);
    accepted(&native_worst)?;
    let python_worst = format!(
        "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=FFFFFFFF errors={}\n",
        ["tf-restrictions-length:control"; 8].join(",")
    );
    ensure!(python_worst.len() <= 512);
    accepted(&python_worst)?;

    let tail = "REGISTRY_LOADER_FOLLOWUP role=primary errors=loader:win32-00000005\n";
    ensure!(
        loader_detail(&format!("{ORIGINAL}{tail}")).as_deref()
            == Some(
                "child_exit=none errors=import-ctypes:import-ctypes-native followup=loader:win32-00000005"
            ),
        "original loader followup detail differs"
    );
    for invalid in [
        "loader:win32-00000000",
        "loader:win32-100000000",
        "loader:win32-abcdefab",
        "loader:loaded",
        "loader-release:released",
        "loader:loaded,loader-release:win32-00000000",
    ] {
        ensure!(
            !loader_tail(invalid)
                && loader_detail(&format!(
                    "{ORIGINAL}REGISTRY_LOADER_FOLLOWUP role=primary errors={invalid}\n"
                ))
                .unwrap()
                .ends_with("followup=unqualified"),
            "malformed loader followup accepted"
        );
    }
    let operation = anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "fixed timeout",
    ));
    let address = operation.downcast_ref::<std::io::Error>().unwrap() as *const _;
    let preserved = preserve(
        Some(operation),
        None,
        format!("{ORIGINAL}private-malformed").as_bytes(),
        false,
    )
    .unwrap();
    let group = preserved.downcast_ref::<Failures>().unwrap();
    ensure!(
        group.errors.len() == 2
            && group.errors[1]
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| std::ptr::eq(error, address))
            && group.errors[0].to_string().contains("primary_exit=none")
            && !format!("{preserved:?}").contains("private"),
        "loader receipt replaced operation or exposed followup"
    );
    ensure!(
        from_prefix(ORIGINAL.trim_end_matches('\n').as_bytes(), false).is_none()
            && from_prefix(ORIGINAL.as_bytes(), true)
                .unwrap()
                .ends_with("followup=unqualified"),
        "loader prefix completeness differs"
    );
    for middle in [
        "",
        ",loader:loaded,loader-release:win32-FFFFFFFF",
        ",loader:unqualified",
    ] {
        let child = format!(
            "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000000 errors=import-ctypes:import-ctypes-native{middle},descendant:transport\n"
        );
        let error = validate_wire(1, Some("private-stdout"), Some(&child)).unwrap_err();
        ensure!(
            error
                .to_string()
                .contains("child_exit=00000000 errors=import-ctypes:import-ctypes-native")
                && !format!("{error:?}").contains("private"),
            "bounded descendant loader receipt was discarded"
        );
    }
    for code in [0, 1, 125, 259, 0xc0000005, u32::MAX] {
        let receipt = preserve(
            None,
            Some(code),
            format!("{ORIGINAL}{tail}").as_bytes(),
            false,
        )
        .unwrap();
        ensure!(
            receipt
                .to_string()
                .contains(&format!("primary_exit=0x{code:08X}")),
            "loader receipt exit changed"
        );
        let cleanup = anyhow::anyhow!("fixed cleanup");
        let result = super::super::completion::finish_undebugged(
            Some(receipt),
            vec![cleanup],
            true,
            false,
            true,
        )
        .unwrap();
        ensure!(
            !result.is::<QualifiedFailure>()
                && result
                    .downcast_ref::<Failures>()
                    .is_some_and(|group| group.errors.len() == 2),
            "unqualified undebugged receipt became qualified"
        );
    }

    let trace = crate::windows_security::sxs::safe(
        anyhow::anyhow!(r"C:\private-sxs-sentinel\capture.etl"),
        "start-tool",
    )
    .downcast::<crate::windows_security::sxs::PrivateFailure>()
    .unwrap();
    let trace = Arc::new(trace);
    let group = sanitize(
        Failures {
            errors: vec![
                anyhow::Error::new(trace.clone()),
                super::super::checks::qualified(anyhow::Error::new(trace.clone())),
                anyhow::anyhow!("private-cause-sentinel"),
            ],
        }
        .into(),
    );
    let values = &group.downcast_ref::<Failures>().unwrap().errors;
    ensure!(
        Arc::ptr_eq(
            values[0]
                .downcast_ref::<Arc<crate::windows_security::sxs::PrivateFailure>>()
                .unwrap(),
            &trace
        ) && Arc::ptr_eq(
            values[1]
                .downcast_ref::<QualifiedFailure>()
                .unwrap()
                .original()
                .downcast_ref::<Arc<crate::windows_security::sxs::PrivateFailure>>()
                .unwrap(),
            &trace
        ) && values[2].is::<PrivateFailure>()
            && !format!("{group:?}").contains("sentinel"),
        "recursive registry privacy lost trusted private cause identity"
    );
    let mut bytes = format!("{ORIGINAL}private-sentinel").into_bytes();
    bytes.extend([0xed, 0xa0, 0x80]);
    let raw = anyhow::Error::new(String::from_utf8(bytes.clone()).unwrap_err());
    let address = raw.downcast_ref::<std::string::FromUtf8Error>().unwrap() as *const _;
    let preserved = preserve(Some(raw), None, &bytes, false).unwrap();
    let complete = sanitize(
        Failures {
            errors: vec![preserved, anyhow::anyhow!("private-cleanup-sentinel")],
        }
        .into(),
    );
    let group = complete.downcast_ref::<Failures>().unwrap();
    let ordered = group.errors[0].downcast_ref::<Failures>().unwrap();
    let raw = ordered.errors[1].downcast_ref::<PrivateFailure>().unwrap();
    ensure!(
        raw.original()
            .downcast_ref::<std::string::FromUtf8Error>()
            .is_some_and(|error| std::ptr::eq(error, address))
            && raw.to_string().contains("category=decode")
            && raw.source().is_none()
            && group.errors[1].is::<PrivateFailure>()
            && !format!("{complete:?}").contains("sentinel"),
        "malformed captured bytes lost private failure ownership"
    );
    Ok(())
}
