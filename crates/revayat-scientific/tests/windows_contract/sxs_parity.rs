//! Bounded SxS byte/session regressions. No test here starts or controls a host ETW session.
use revayat_scientific::windows_security::sxs::*;
use std::cell::RefCell;

const BEGIN: &str = "Begin Activation Context Generation.\n";
const END: &str = "End Activation Context Generation.\n";
const MANIFEST: &str = "F:\\private-consumer-sentinel\\consumer.dll";
fn utf8(text: &str) -> Vec<u8> {
    [b"\xef\xbb\xbf".as_slice(), text.as_bytes()].concat()
}
fn utf16(text: &str) -> Vec<u8> {
    let mut bytes = vec![255, 254];
    for unit in text.encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    bytes
}
fn block(path: &str, detail: &str) -> String {
    format!("{BEGIN}ManifestPath = {path}\n{detail}\n{END}")
}
fn session_bytes() -> Vec<u8> {
    let mut bytes = vec![0; SESSION_CAPACITY];
    for (offset, value) in [
        (0, SESSION_CAPACITY as u32),
        (48, 64),
        (56, 16),
        (64, 1),
        (112, 2168),
        (116, 120),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[8..16].copy_from_slice(&7u64.to_le_bytes());
    bytes[24..40].copy_from_slice(&[1; 16]);
    for (offset, text) in [
        (120, SESSION_NAME),
        (2168, "F:\\sxs-trace-fixed\\capture.etl"),
    ] {
        for (index, unit) in text.encode_utf16().enumerate() {
            bytes[offset + index * 2..offset + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    bytes
}

#[test]
fn strict_trace_codecs_reject_missing_bom_malformed_text_and_private_payloads() {
    check_evidence_validation().unwrap();
    check_reporting_validation().unwrap();
    check_capture_validation().unwrap();
    let text = block(
        MANIFEST,
        "ERROR: Cannot resolve reference Microsoft.Windows.Common-Controls,type=\"win32\",version=\"6.0.0.0\".\nERROR: Activation Context generation failed.",
    );
    let expected = failure_evidence(&utf16(&text), MANIFEST).unwrap();
    assert!(
        expected.contains("unresolved_reference=True") && expected.contains("common_controls=True")
    );
    assert!(!expected.contains("private-") && !expected.contains(MANIFEST));
    for value in [
        &text,
        &(text.clone() + "\n"),
        &text.replace("ERROR:", "INFO: Ω\nERROR:"),
    ] {
        assert_eq!(failure_evidence(&utf8(value), MANIFEST).unwrap(), expected);
        assert_eq!(failure_evidence(&utf16(value), MANIFEST).unwrap(), expected);
    }
    for malformed in [
        vec![],
        vec![239],
        vec![239, 187, 191],
        vec![255, 254],
        vec![255, 254, 0],
        vec![254, 255, 0, 65],
        vec![255, 254, 0, 0],
        vec![255, 254, 0, 216],
        utf8("\0"),
        utf8("\r"),
        utf8(&"x".repeat(2049)),
        utf8(&"\n".repeat(4096)),
        vec![0; 1048577],
        text.as_bytes().to_vec(),
    ] {
        let error = failure_evidence(&malformed, MANIFEST).unwrap_err();
        assert!(!format!("{error:?}").contains("sentinel"));
    }
    for body in [
        vec![194],
        vec![128],
        vec![192, 175],
        vec![237, 160, 128],
        vec![244, 144, 128, 128],
        vec![226, 130],
    ] {
        let bytes = [vec![239, 187, 191], body].concat();
        assert!(failure_evidence(&bytes, MANIFEST).is_err());
    }
    for text in [
        text.clone() + &text,
        text.replace(END, ""),
        text.replace(MANIFEST, "wrong.dll"),
        text.replace("Microsoft.Windows.Common-Controls", "private-unknown"),
        block(MANIFEST, "ERROR: private-error-sentinel"),
        block(MANIFEST, "INFO: benign"),
        block(
            MANIFEST,
            "INFO: Reference: private-reference-sentinel\nERROR: Access is denied.",
        ),
        format!("{BEGIN}{text}"),
        format!("private-outside\n{text}"),
        END.to_owned(),
        text.replace(
            "ManifestPath = ",
            &format!("ManifestPath = {MANIFEST}\nManifestPath = "),
        ),
    ] {
        assert!(failure_evidence(&utf8(&text), MANIFEST).is_err());
    }
    for identity in [
        "Microsoft.Windows.Common-Controls",
        "Microsoft.VC80.CRT",
        "Microsoft.VC140.CRT,version=\"14.*\".",
    ] {
        assert!(known_dependency(identity));
    }
    for identity in [
        "Microsoft.VC150.CRT",
        "Microsoft.Windows.Common-Controls,private=\"x/y\"",
        "private-reference",
        "Microsoft.VC90.CRT ",
    ] {
        assert!(!known_dependency(identity));
    }
}

#[test]
fn collector_positive_control_cannot_substitute_for_failed_consumer_evidence() {
    revayat_scientific::windows_security::activation::control::check_trace_control_validation()
        .unwrap();
    let control = "F:\\private-control-sentinel\\collector.manifest";
    let positive = block(
        control,
        "ERROR: invalid namespace\nERROR: Activation Context generation failed.",
    );
    let benign = block(MANIFEST, "INFO: Activation Context generation succeeded.");
    for count in 0..3 {
        let text = benign.repeat(count) + &positive;
        let result = success_evidence(&utf8(&text), MANIFEST, control).unwrap();
        assert_eq!(
            success_evidence(&utf16(&text), MANIFEST, control).unwrap(),
            result
        );
        assert!(
            result.contains(&format!("consumer_blocks={count}")) && !result.contains("private-")
        );
    }
    assert!(failure_evidence(&utf8(&positive), MANIFEST).is_err());
    assert!(success_evidence(&utf8(&positive), control, control).is_err());
    for invalid in [
        String::new(),
        benign.clone(),
        positive.clone() + &positive,
        positive.replace(control, "wrong.manifest"),
        positive.replace("ERROR: Activation Context generation failed.\n", ""),
        positive.replace(
            "ERROR: invalid namespace",
            "ERROR: Cannot resolve reference unknown",
        ),
        positive.replace("ERROR: invalid namespace", "INFO: Reference: unknown"),
        positive.replace(
            "ERROR: invalid namespace",
            "ERROR: Activation Context generation succeeded.",
        ),
        positive.clone()
            + &benign.replace(
                "INFO: Activation Context generation succeeded.",
                "ERROR: Access is denied.",
            ),
        positive.clone()
            + &benign.replace(
                "INFO: Activation Context generation succeeded.",
                "INFO: Reference: unknown",
            ),
        benign.repeat(64) + &positive,
    ] {
        assert!(success_evidence(&utf8(&invalid), MANIFEST, control).is_err());
    }
}

#[test]
fn session_decoder_and_capture_limits_require_exact_owned_identity() {
    let original = SessionSnapshot::decode(&session_bytes()).unwrap();
    original.require_capture().unwrap();
    for mode in [1, 0x00400000] {
        let mut candidate = original.clone();
        candidate.mode = mode;
        candidate.maximum_buffers = 256;
        candidate.require_capture().unwrap();
        candidate.maximum_buffers = 257;
        assert!(candidate.require_capture().is_err());
        for invalid in [
            0,
            2,
            4,
            8,
            0x100,
            0x400,
            0x800,
            0x00400001,
            0x00400002,
            0x00800000,
            u32::MAX,
        ] {
            let mut bad = original.clone();
            bad.mode = invalid;
            assert!(bad.require_capture().is_err());
        }
    }
    for field in [0, 112, 116] {
        let mut bad = session_bytes();
        bad[field..field + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(SessionSnapshot::decode(&bad).is_err());
    }
    for field in [48, 56, 88, 96, 100] {
        let mut bad = session_bytes();
        let value: u32 = if field <= 56 { 0 } else { 1 };
        bad[field..field + 4].copy_from_slice(&value.to_le_bytes());
        assert!(
            SessionSnapshot::decode(&bad)
                .unwrap()
                .require_capture()
                .is_err()
        );
    }
    for offset in [120, 2168] {
        let mut bad = session_bytes();
        for index in (offset..offset + 2048).step_by(2) {
            bad[index] = b'A';
        }
        assert!(SessionSnapshot::decode(&bad).is_err());
        let mut bad = session_bytes();
        bad[offset..offset + 4].copy_from_slice(&[0, 216, 0, 0]);
        assert!(SessionSnapshot::decode(&bad).is_err());
    }
    assert!(SessionSnapshot::decode(&[]).is_err());
    assert!(select_session(&[], &original.path).unwrap().is_none());
    assert_eq!(
        select_session(std::slice::from_ref(&original), &original.path)
            .unwrap()
            .unwrap()
            .handle,
        7
    );
    assert!(select_session(&[original.clone(), original.clone()], &original.path).is_err());
    let mut foreign = original.clone();
    foreign.name = "foreign".to_owned();
    assert!(select_session(&[foreign.clone()], &original.path).is_err());
    foreign = original.clone();
    foreign.guid[0] ^= 1;
    assert!(original.require_same(&foreign).is_err());
    assert!(require_enumeration(0, 256).is_ok());
    for (status, count) in [(234, 1), (5, 0), (0, 257)] {
        assert!(require_enumeration(status, count).is_err());
    }
}

#[test]
fn trace_storage_lifecycle_latches_attempts_before_failing_callbacks() {
    for failure in -1..3 {
        let mut state = StorageLifecycle::default();
        let order = RefCell::new(Vec::new());
        let step = |phase| {
            order.borrow_mut().push(phase);
            if phase == failure {
                anyhow::bail!("private");
            }
            Ok(())
        };
        let result = state
            .prepare(|| step(0))
            .and_then(|()| state.seal(|| step(1)))
            .and_then(|()| state.enter(|| step(2)));
        assert_eq!(result.is_err(), failure >= 0);
        assert_eq!(
            *order.borrow(),
            match failure {
                0 => vec![0],
                1 => vec![0, 1],
                _ => vec![0, 1, 2],
            }
        );
        assert!(state.prepare(|| panic!("retry prepare")).is_err());
        assert!(state.seal(|| panic!("retry seal")).is_err());
        assert!(state.enter(|| panic!("retry enter")).is_err());
    }
    let mut missing = StorageLifecycle::default();
    assert!(missing.enter(|| panic!("missing seal")).is_err());
    for mode in 0..4 {
        let order = RefCell::new(String::new());
        let result = execute_capture(
            || {
                order.borrow_mut().push('o');
                if mode > 0 {
                    anyhow::bail!("operation");
                }
                Ok(())
            },
            || {
                order.borrow_mut().push('c');
                Ok(())
            },
            || {
                order.borrow_mut().push('s');
                if mode == 2 {
                    anyhow::bail!("private-stop-sentinel");
                }
                Ok(())
            },
            |_| {
                order.borrow_mut().push('p');
                if mode == 3 {
                    anyhow::bail!("private-parse-sentinel");
                }
                Ok(())
            },
        );
        assert_eq!(
            *order.borrow(),
            if mode == 0 {
                "ocsp"
            } else if mode == 2 {
                "os"
            } else {
                "osp"
            }
        );
        assert_eq!(result.is_err(), mode != 0);
        if mode >= 2 {
            assert!(!format!("{:?}", result.unwrap_err()).contains("sentinel"));
        }
    }
}

#[test]
fn ordinal_paths_match_unicode_case_without_expansion_or_normalization() {
    assert!(ordinal_path_equal("C:\\Étage\\app.exe", "c:\\étage\\APP.EXE").unwrap());
    assert!(!ordinal_path_equal("C:\\straße", "C:\\STRASSE").unwrap());
    assert!(!ordinal_path_equal("C:\\é", "C:\\e\u{301}").unwrap());
    let text = block("F:\\Étage\\consumer.dll", "ERROR: Access is denied.");
    assert!(failure_evidence(&utf8(&text), "f:\\étage\\CONSUMER.DLL").is_ok());
    let control = block(
        "F:\\Étage\\consumer.dll",
        "ERROR: invalid namespace\nERROR: Activation Context generation failed.",
    );
    assert!(
        success_evidence(
            &utf8(&control),
            "f:\\étage\\CONSUMER.DLL",
            "F:\\Étage\\consumer.dll"
        )
        .is_err()
    );
    let mut original = SessionSnapshot::decode(&session_bytes()).unwrap();
    original.path = "F:\\Étage\\capture.etl".to_owned();
    let mut later = original.clone();
    later.path = "f:\\étage\\CAPTURE.ETL".to_owned();
    original.require_same(&later).unwrap();
    assert!(select_session(&[original], &later.path).unwrap().is_some());
}

#[test]
fn fixed_event_xml_bounds_namespaces_leaf_nodes_and_owned_image_selection() {
    check_startup_events_validation().unwrap();
    let image = "C:\\fixed owned\\authority.exe";
    let start = "2026-01-01T00:00:00Z";
    let end = "2026-01-01T00:00:01Z";
    let xml = format!(
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='SideBySide'/><EventID>33</EventID><TimeCreated SystemTime='2026-01-01T00:00:00.5000000Z'/><Channel>Application</Channel></System><EventData><Data>{image}</Data><Data>Dependent Assembly Microsoft.Windows.Common-Controls,processorArchitecture=amd64 could not be found.</Data></EventData></Event>"
    );
    let line = classify_event(&xml, image, start, end).unwrap().unwrap();
    assert!(
        line.contains("event_id=33 matched_owned_image=True")
            && line.contains("dependent_assembly_not_found=True")
    );
    assert!(
        line.contains("common_controls=True")
            && line.contains("amd64=True")
            && !line.contains(image)
    );
    assert!(
        classify_event(
            &xml.replace(image, &(image.to_owned() + ".other")),
            image,
            start,
            end
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        classify_event(
            &xml.replace(image, &image.to_uppercase()),
            image,
            start,
            end
        )
        .unwrap()
        .unwrap(),
        line
    );
    for invalid in [
        xml.replace("SideBySide", "Other"),
        xml.replace("Application", "System"),
        xml.replace(
            "http://schemas.microsoft.com/win/2004/08/events/event",
            "urn:other",
        ),
        xml.replace(">33</EventID>", ">65536</EventID>"),
        xml.replace(">33</EventID>", "><Nested>33</Nested></EventID>"),
        xml.replace(
            "<Provider Name='SideBySide'/>",
            "<Provider Name='SideBySide' Unknown='value'/>",
        ),
        xml.replace("<Channel>", "<Channel Unknown='value'>"),
        xml.replace("00:00:00.5000000Z", "00:00:02.5000000Z"),
        xml.replace("</EventData>", &format!("<Data>{image}</Data></EventData>")),
        xml.replace("</EventData>", "<Other/></EventData>"),
        format!("<!DOCTYPE Event>{xml}"),
        xml.replace("<Data>", "<Data><Nested/>"),
        "x".repeat(32769),
    ] {
        assert!(classify_event(&invalid, image, start, end).is_err());
    }
    let unknown = xml.replace("Dependent Assembly Microsoft.Windows.Common-Controls,processorArchitecture=amd64 could not be found.", "private unknown payload");
    let line = classify_event(&unknown, image, start, end)
        .unwrap()
        .unwrap();
    assert!(line.contains("dependent_assembly_not_found=False") && !line.contains("private"));
    assert!(classify_event(&xml, image, "2026-02-30T00:00:00Z", end).is_err());
    let comment_identity = xml.replace(
        &format!("<Data>{image}</Data>"),
        &format!("<Data><!--{image}--></Data>"),
    );
    assert!(
        classify_event(&comment_identity, image, start, end)
            .unwrap()
            .is_none()
    );
    let comment_payload = unknown.replace(
        "private unknown payload",
        "<!--access denied--><?private ignored?>",
    );
    let classified = classify_event(&comment_payload, image, start, end)
        .unwrap()
        .unwrap();
    assert!(classified.contains("access_denied=False"));
    let deep_text = xml.replace("</System>", "<A><B><C><D><E>x</E></D></C></B></A></System>");
    assert!(classify_event(&deep_text, image, start, end).is_err());
    let deep_empty = xml.replace("</System>", "<A><B><C><D><E/></D></C></B></A></System>");
    assert!(classify_event(&deep_empty, image, start, end).is_ok());
    let unicode_image = xml.replace(image, "C:\\Étage\\authority.exe");
    assert!(
        classify_event(&unicode_image, "c:\\étage\\AUTHORITY.EXE", start, end)
            .unwrap()
            .is_some()
    );
    let cdata = xml.replace(
        &format!("<Data>{image}</Data>"),
        &format!("<Data><![CDATA[{image}]]></Data>"),
    );
    assert_eq!(
        classify_event(&cdata, image, start, end).unwrap(),
        classify_event(&xml, image, start, end).unwrap()
    );
}
