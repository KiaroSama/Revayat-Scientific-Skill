//! Source-derived session ownership and stop/reap ordering. Never touches a live trace.
use revayat_scientific::windows_security::sxs::*;
use std::cell::RefCell;
fn snapshot() -> SessionSnapshot {
    SessionSnapshot {
        handle: 7,
        guid: [1; 16],
        name: SESSION_NAME.to_owned(),
        path: "F:\\sxs-trace-fixed\\capture.etl".to_owned(),
        mode: 1,
        buffer_kib: 64,
        maximum_buffers: 16,
        events_lost: 0,
        log_lost: 0,
        realtime_lost: 0,
    }
}
#[test]
fn session_recovery_refuses_foreign_binding_and_requires_starter_reaped() {
    for mode in 0..12 {
        let original = snapshot();
        let mut foreign = snapshot();
        foreign.guid[0] ^= 1;
        let live = RefCell::new(mode != 3 && mode != 4);
        let stops = RefCell::new(0);
        let all_calls = RefCell::new(0);
        let query_calls = RefCell::new(0);
        let all = || {
            *all_calls.borrow_mut() += 1;
            Ok(if mode == 6 {
                vec![original.clone(), original.clone()]
            } else if *live.borrow() {
                vec![original.clone()]
            } else {
                vec![]
            })
        };
        let query = || {
            *query_calls.borrow_mut() += 1;
            Ok(if *live.borrow() {
                Some(if mode == 9 {
                    foreign.clone()
                } else {
                    original.clone()
                })
            } else if mode == 10 {
                Some(foreign.clone())
            } else {
                None
            })
        };
        let result = stop_owned(
            &original.path,
            mode != 2,
            mode == 4 || mode == 7,
            if mode == 1 {
                Some(&foreign)
            } else if mode == 5 {
                None
            } else {
                Some(&original)
            },
            all,
            query,
            |_| {
                *stops.borrow_mut() += 1;
                if mode == 8 {
                    anyhow::bail!("private stop");
                }
                *live.borrow_mut() = mode == 11;
                let mut stopped = original.clone();
                if mode == 7 {
                    stopped.events_lost = 1;
                }
                Ok(stopped)
            },
        );
        assert_eq!(
            result.is_ok(),
            mode == 0 || mode == 3 || mode == 5,
            "mode={mode}"
        );
        assert_eq!(
            *stops.borrow(),
            usize::from(matches!(mode, 0 | 5 | 7 | 8 | 10 | 11)),
            "mode={mode}"
        );
        if mode == 2 {
            assert_eq!((*all_calls.borrow(), *query_calls.borrow()), (0, 0));
        }
    }
}
#[test]
fn intent_and_bound_receipts_are_closed_exact_and_run_bound() {
    let run = "a".repeat(32);
    let original = snapshot();
    let intent = intent_text(&run, "F:\\").unwrap();
    assert_eq!(intent_volume(&intent, &run).unwrap(), "F:\\");
    let bound = bound_text(&run, &original).unwrap();
    original
        .require_same(&decode_bound(&bound, &run, &original.path).unwrap())
        .unwrap();
    for text in [
        String::new(),
        bound.clone() + "x",
        bound.replace(&run, &"b".repeat(32)),
        bound.replace("0000000000000007", "0000000000000000"),
        bound.replace("01010101-0101-0101-0101-010101010101", "bad-guid"),
    ] {
        assert!(decode_bound(&text, &run, &original.path).is_err());
    }
    for text in [
        String::new(),
        intent.clone() + "x",
        intent.replace(&run, "bad"),
        intent.replace("F:\\", "C:\\"),
    ] {
        assert!(intent_volume(&text, &run).is_err());
    }
    for volume in ["C:\\", "f:/", "F:\\extra", "F:", "\\\\host\\share\\"] {
        assert!(intent_text(&run, volume).is_err());
    }
}
