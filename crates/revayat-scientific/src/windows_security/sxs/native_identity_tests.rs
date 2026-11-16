//! Returned-buffer identity contracts plus required hosted read-only token-query checks.
use super::*;
fn sid() -> Vec<u8> {
    vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
}
#[test]
fn bounded_token_sid_requires_header_alignment_revision_count_and_complete_span() {
    let mut data = Query {
        words: vec![0; 32],
        length: 28,
    };
    let base = data.words.as_ptr() as usize;
    let bytes = data.bytes_mut();
    bytes[..8].copy_from_slice(&(base + 16).to_le_bytes());
    bytes[16..28].copy_from_slice(&sid());
    assert_eq!(data.sid(0, 16).unwrap(), sid());
    for delta in [-4isize, 17, 24, 8] {
        let mut bad = data.clone();
        let pointer = (bad.words.as_ptr() as usize).wrapping_add_signed(delta);
        bad.bytes_mut()[..8].copy_from_slice(&pointer.to_le_bytes());
        assert!(bad.sid(0, 16).is_err());
    }
    for (at, value) in [(16, 2), (17, 16)] {
        let prior = data.bytes()[at];
        data.bytes_mut()[at] = value;
        assert!(data.sid(0, 16).is_err());
        data.bytes_mut()[at] = prior;
    }
    data.length = 27;
    assert!(data.sid(0, 16).is_err());
}
#[test]
fn lpac_named_attribute_requires_exact_name_type_value_and_returned_spans() {
    let name = "WIN://NOALLAPPPKG".encode_utf16().collect::<Vec<_>>();
    let fixture = || {
        let mut data = Query {
            words: vec![0; 64],
            length: 128,
        };
        let base = data.words.as_ptr() as u64;
        let bytes = data.bytes_mut();
        bytes[..4].copy_from_slice(&[1, 0, 0, 0]);
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&(base + 16).to_le_bytes());
        bytes[16..18].copy_from_slice(&((name.len() * 2) as u16).to_le_bytes());
        bytes[18..20].copy_from_slice(&((name.len() * 2) as u16).to_le_bytes());
        bytes[24..32].copy_from_slice(&(base + 64).to_le_bytes());
        bytes[32..36].copy_from_slice(&[2, 0, 0, 0]);
        bytes[40..44].copy_from_slice(&1u32.to_le_bytes());
        bytes[48..56].copy_from_slice(&(base + 112).to_le_bytes());
        for (index, unit) in name.iter().enumerate() {
            bytes[64 + index * 2..66 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes[112..120].copy_from_slice(&1u64.to_le_bytes());
        data
    };
    require_lpac(&fixture(), &name).unwrap();
    for (at, value) in [
        (0, 2),
        (2, 1),
        (4, 0),
        (4, 2),
        (8, 1),
        (16, 1),
        (18, 1),
        (24, 1),
        (32, 3),
        (34, 1),
        (36, 0x10),
        (40, 0),
        (40, 2),
        (48, 1),
        (64, b'X'),
        (112, 0),
        (112, 2),
    ] {
        let mut data = fixture();
        data.bytes_mut()[at] = value;
        assert!(require_lpac(&data, &name).is_err(), "mutation at {at}");
    }
    for length in [15, 119, 513] {
        let mut data = fixture();
        if length <= 512 {
            data.length = length;
        } else {
            data.words.resize(65, 0);
            data.length = length;
        }
        assert!(require_lpac(&data, &name).is_err());
    }
}
#[test]
fn exact_primary_duplicate_effective_context_keeps_restricted_multiset_multiplicity() {
    let expected = Snapshot {
        user: vec![1],
        package: vec![2],
        restricted: vec![(vec![3], 1), (vec![3], 1), (vec![4], 2)],
    };
    let same = Snapshot {
        user: vec![1],
        package: vec![2],
        restricted: expected.restricted.clone(),
    };
    expected.require_same(&same).unwrap();
    for bad in [
        Snapshot {
            user: vec![9],
            ..same.clone()
        },
        Snapshot {
            package: vec![9],
            ..same.clone()
        },
        Snapshot {
            restricted: vec![(vec![3], 1), (vec![4], 2), (vec![4], 2)],
            ..same.clone()
        },
    ] {
        assert!(expected.require_same(&bad).is_err());
    }
}
#[test]
fn startup_token_query_keeps_original_wire_and_refuses_inconsistent_native_outputs() {
    let valid = 1usize as Raw;
    assert_eq!(
        startup_outcome("host", true, valid, 0).unwrap(),
        "WINDOWS_STARTUP_TOKEN context=host desired_access=0x00000008 opened=True win32_error=0 cause_claimed=False child_equivalence_claimed=False"
    );
    assert_eq!(
        startup_outcome("lpac", false, null_mut(), 5).unwrap(),
        "WINDOWS_STARTUP_TOKEN context=lpac desired_access=0x00000008 opened=False win32_error=5 cause_claimed=False child_equivalence_claimed=False"
    );
    // LPAC success is diagnostic too, never forced-denial or admission evidence.
    assert!(
        startup_outcome("lpac", true, valid, 0)
            .unwrap()
            .contains("opened=True")
    );
    for (label, opened, handle, error) in [
        ("private-sentinel", true, valid, 0),
        ("host", true, null_mut(), 0),
        ("host", true, usize::MAX as Raw, 0),
        ("host", true, valid, 5),
        ("lpac", false, valid, 5),
        ("lpac", false, usize::MAX as Raw, 5),
        ("lpac", false, null_mut(), 0),
    ] {
        let failure = startup_outcome(label, opened, handle, error).unwrap_err();
        assert!(!failure.to_string().contains("private-sentinel"));
    }
}
#[test]
fn startup_query_cleanup_keeps_primary_and_both_independent_close_and_reporting_failures() {
    let primary = anyhow::anyhow!("fixed primary");
    finish::<()>(Ok(()), vec![]).unwrap();
    assert_eq!(
        finish::<()>(Err(anyhow::anyhow!("fixed primary")), vec![])
            .unwrap_err()
            .to_string(),
        "fixed primary"
    );
    let closed = finish::<()>(
        Err(primary),
        vec![
            anyhow::anyhow!("first close"),
            anyhow::anyhow!("second close"),
        ],
    )
    .unwrap_err();
    let failure = finish::<()>(Err(closed), vec![anyhow::anyhow!("report")]).unwrap_err();
    let outer = failure.downcast_ref::<Failures>().unwrap();
    let inner = outer.errors[0].downcast_ref::<Failures>().unwrap();
    assert_eq!(
        inner
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["fixed primary", "first close", "second close"]
    );
    assert_eq!(outer.errors[1].to_string(), "report");
    assert!(!failure.to_string().contains("fixed primary"));
    let source = include_str!("native_context.rs");
    let core = source.split_once("fn authority_context<").unwrap().1;
    assert!(core.contains("host()?;") && core.contains("scoped(copy.0"));
    assert!(core.find("host()?;").unwrap() < core.find("scoped(copy.0").unwrap());
    assert!(core.contains("[cleanup(), copy.close(), primary.close()]"));
    assert!(core.find("checkpoint()?;").unwrap() < core.find("require_host()?;").unwrap());
    assert!(core.contains("let checked = checkpoint();"));
    assert!(core.contains("finish(scoped_result, checked.err().into_iter().collect())"));
    let observe = source
        .split_once("pub(crate) fn observe_startup_token(")
        .unwrap()
        .1;
    assert!(observe.contains("Duration::from_secs(10)"));
    assert!(
        observe.find("require_host()?;").unwrap()
            < observe.find("let started = Instant::now()").unwrap()
    );
    assert!(
        observe
            .contains("let operation = finish(operation, deadline().err().into_iter().collect());")
    );
    assert!(
        observe.find("authority_context(").unwrap()
            < observe.find("emit(&lines.borrow())").unwrap()
    );
    assert!(!observe.contains("SetTokenInformation") && !observe.contains("CreateProcess"));
}
#[test]
fn authority_checkpoint_failure_precedes_native_access_and_runs_independent_cleanup_once() {
    let calls = std::cell::RefCell::new(Vec::new());
    let failure = authority_context::<()>(
        null_mut(),
        "not-consumed",
        || {
            calls.borrow_mut().push("deadline");
            Err(anyhow::anyhow!("fixed deadline"))
        },
        || {
            panic!("host operation after expired acquisition");
        },
        |_| {
            panic!("LPAC operation after expired acquisition");
        },
        || {
            calls.borrow_mut().push("query-close");
            Err(anyhow::anyhow!("fixed cleanup"))
        },
    )
    .unwrap_err();
    assert_eq!(*calls.borrow(), ["deadline", "query-close"]);
    let errors = &failure.downcast_ref::<Failures>().unwrap().errors;
    assert_eq!(
        errors.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["fixed deadline", "fixed cleanup"]
    );
}
#[test]
fn actual_host_startup_token_query_has_exact_query_rights_and_close_before_return() {
    let mut owner = Handle(null_mut());
    let mut lines = Vec::new();
    let observed = startup_query(
        unsafe { GetCurrentProcess() },
        "host",
        &mut owner,
        &mut lines,
    );
    let cleanup = owner.close();
    assert!(observed.unwrap());
    cleanup.unwrap();
    assert!(owner.0.is_null());
    assert_eq!(
        lines,
        [
            "WINDOWS_STARTUP_TOKEN context=host desired_access=0x00000008 opened=True win32_error=0 cause_claimed=False child_equivalence_claimed=False"
        ]
    );
    lines.clear();
    assert!(!startup_query(null_mut(), "lpac", &mut owner, &mut lines).unwrap());
    assert!(owner.0.is_null());
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("opened=False") && !lines[0].contains("win32_error=0 "));
    owner.close().unwrap();
}
#[test]
fn owner_identity_rejects_foreign_user_wrong_type_level_and_default_owner() {
    let user = sid();
    require_owner_identity(&user, &user, &[9], 1, 0, false, false).unwrap();
    require_owner_identity(&user, &user, &user, 2, 2, true, true).unwrap();
    for (actual, owner, kind, level, duplicate, strict) in [
        (&[9][..], &user[..], 2, 2, true, true),
        (&user[..], &[9][..], 2, 2, true, true),
        (&user[..], &user[..], 1, 2, true, true),
        (&user[..], &user[..], 2, 1, true, true),
        (&user[..], &user[..], 2, 0, false, false),
    ] {
        assert!(
            require_owner_identity(&user, actual, owner, kind, level, duplicate, strict).is_err()
        );
    }
}
