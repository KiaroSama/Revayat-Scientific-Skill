use super::contract::{self, Predicate, need};
use super::*;
use anyhow::ensure;
use std::cell::Cell;
fn fixture(value: &SessionSnapshot) -> Vec<u8> {
    let mut bytes = vec![0; SESSION_CAPACITY];
    for (at, field) in [
        (0, SESSION_CAPACITY as u32),
        (48, value.buffer_kib),
        (56, value.maximum_buffers),
        (64, value.mode),
        (88, value.events_lost),
        (96, value.log_lost),
        (100, value.realtime_lost),
        (112, 2168),
        (116, 120),
    ] {
        bytes[at..at + 4].copy_from_slice(&field.to_le_bytes());
    }
    bytes[8..16].copy_from_slice(&value.handle.to_le_bytes());
    bytes[24..40].copy_from_slice(&value.guid);
    for (at, text) in [(120, &value.name), (2168, &value.path)] {
        for (index, unit) in text.encode_utf16().enumerate() {
            bytes[at + index * 2..at + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    bytes
}
fn original() -> SessionSnapshot {
    SessionSnapshot {
        handle: 7,
        guid: [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc,
        ],
        name: SESSION_NAME.into(),
        path: r"F:\sxs-trace-fixed\capture.etl".into(),
        mode: 1,
        buffer_kib: 64,
        maximum_buffers: 16,
        events_lost: 0,
        log_lost: 0,
        realtime_lost: 0,
    }
}
fn empty() -> SessionSnapshot {
    SessionSnapshot {
        handle: 0,
        guid: [0; 16],
        name: String::new(),
        path: String::new(),
        mode: 0,
        buffer_kib: 0,
        maximum_buffers: 0,
        events_lost: 0,
        log_lost: 0,
        realtime_lost: 0,
    }
}
pub fn check_validation() -> anyhow::Result<()> {
    reporting()?;
    let mut rejected = empty();
    rejected.buffer_kib = 64;
    rejected.maximum_buffers = 16;
    ensure!(
        contract::capture_optional(Some(&rejected))
            .unwrap_err()
            .to_string()
            == "fixed SxS trace failed stage=session-capture mode=00000000 buffer_kib=64 maximum_buffers=16 events_lost=0 log_lost=0 realtime_lost=0 raw_error_withheld=True",
        "capture predicate projection differs"
    );
    let a = original();
    a.require_same(select_session(std::slice::from_ref(&a), &a.path)?.unwrap())?;
    a.require_capture()?;
    ensure!(
        select_session(&[], &a.path)?.is_none(),
        "empty session list selected value"
    );
    let mut tool = SessionSnapshot::decode(&fixture(&a))?;
    tool.mode = 0x00400000;
    tool.require_capture()?;
    ensure!(
        a.require_same(&tool).is_err(),
        "session mode drift accepted"
    );
    a.require_same(&SessionSnapshot::decode(&fixture(&a))?)?;
    recovery(&a)?;
    for mode in [1, 0x00400000] {
        let mut candidate = SessionSnapshot::decode(&fixture(&a))?;
        candidate.mode = mode;
        candidate.buffer_kib = 64;
        candidate.maximum_buffers = 256;
        candidate.require_capture()?;
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
            0x00400004,
            0x00400008,
            0x00400100,
            0x00400400,
            0x00400800,
            0x00800000,
            u32::MAX,
        ] {
            let mut bad = SessionSnapshot::decode(&fixture(&a))?;
            bad.mode = invalid;
            ensure!(
                bad.require_capture().is_err(),
                "unsupported capture mode accepted"
            );
        }
        for field in [48, 56, 88, 96, 100] {
            let mut bytes = fixture(&candidate);
            bytes[field..field + 4].copy_from_slice(
                &(if field == 48 || field == 56 { 0u32 } else { 1 }).to_le_bytes(),
            );
            ensure!(
                SessionSnapshot::decode(&bytes)?.require_capture().is_err(),
                "capture zero/lost field accepted"
            );
        }
        candidate.maximum_buffers = 257;
        ensure!(
            candidate.require_capture().is_err(),
            "capture buffer budget exceeded"
        );
        candidate.buffer_kib = u32::MAX;
        candidate.maximum_buffers = u32::MAX;
        ensure!(
            candidate.require_capture().is_err(),
            "capture product overflow accepted"
        );
    }
    let first = [
        contract::decode_optional(None).err().unwrap(),
        contract::decode_optional(Some(&vec![0; SESSION_CAPACITY]))
            .err()
            .unwrap(),
        contract::select_optional(None, &a.path).err().unwrap(),
        contract::same_optional(None, Some(&a)).unwrap_err(),
        contract::same_optional(Some(&a), Some(&empty())).unwrap_err(),
        contract::capture_optional(None).unwrap_err(),
    ];
    for (error, label) in first.into_iter().zip([
        "length",
        "header",
        "selection",
        "present",
        "handle",
        "present",
    ]) {
        ensure!(
            error.to_string()
                == format!(
                    "fixed SxS trace failed stage=session-predicate check={label} raw_error_withheld=True"
                ),
            "session first predicate differs"
        );
    }
    for offset in [0, 112, 116] {
        let mut bytes = fixture(&a);
        bytes[offset..offset + 4].copy_from_slice(&1u32.to_le_bytes());
        ensure!(
            SessionSnapshot::decode(&bytes).is_err(),
            "session header/offset drift accepted"
        );
    }
    for offset in [120, 2168] {
        let mut bytes = fixture(&a);
        for at in (offset..offset + 2048).step_by(2) {
            bytes[at..at + 2].copy_from_slice(&65u16.to_le_bytes());
        }
        ensure!(
            SessionSnapshot::decode(&bytes).is_err(),
            "unterminated session text accepted"
        );
        let mut bytes = fixture(&a);
        bytes[offset..offset + 4].copy_from_slice(&[0, 216, 0, 0]);
        ensure!(
            SessionSnapshot::decode(&bytes).is_err(),
            "invalid session UTF16 accepted"
        );
    }
    for field in [48, 56, 64, 88, 96, 100] {
        let mut bytes = fixture(&a);
        bytes[field..field + 4].copy_from_slice(
            &(if matches!(field, 48 | 56 | 64) {
                0u32
            } else {
                1
            })
            .to_le_bytes(),
        );
        ensure!(
            SessionSnapshot::decode(&bytes)?.require_capture().is_err(),
            "invalid capture field accepted"
        );
    }
    let mut foreign = a.clone();
    foreign.name = "foreign-session".into();
    ensure!(
        select_session(&[foreign], &a.path).is_err()
            && select_session(&vec![empty(); 257], &a.path).is_err(),
        "foreign/oversize session selection accepted"
    );
    require_enumeration(0, 256)?;
    for (status, count) in [(234, 1), (5, 0), (0, 257)] {
        ensure!(
            require_enumeration(status, count).is_err(),
            "inexact enumeration accepted"
        );
    }
    ensure!(
        select_session(&[a.clone(), a.clone()], &a.path).is_err()
            && select_session(std::slice::from_ref(&a), r"F:\other.etl").is_err()
            && a.require_same(&empty()).is_err()
            && empty().require_capture().is_err()
            && SessionSnapshot::decode(&vec![0; SESSION_CAPACITY]).is_err()
            && SessionSnapshot::decode(&vec![0; SESSION_CAPACITY + 1]).is_err(),
        "unqualified session identity accepted"
    );
    Ok(())
}
fn reporting() -> anyhow::Result<()> {
    for (stage, label) in [
        "initial",
        "intent",
        "start-tool",
        "post-tool",
        "bind",
        "post-bind",
        "bind-save",
    ]
    .into_iter()
    .enumerate()
    {
        let error = contract::at_start(stage as i32, || {
            Err::<(), _>(anyhow::anyhow!("C:\\private-session-sentinel\\capture.etl"))
        })
        .unwrap_err();
        ensure!(
            error.to_string()
                == format!("fixed SxS trace failed stage={label} raw_error_withheld=True")
                && !format!("{error:?}").contains("sentinel"),
            "session stage disclosure changed"
        );
        let pointer = error.as_ref() as *const (dyn std::error::Error + Send + Sync) as *const ();
        let retained = contract::at_start(stage as i32, || Err::<(), _>(error)).unwrap_err();
        ensure!(
            retained.as_ref() as *const (dyn std::error::Error + Send + Sync) as *const ()
                == pointer,
            "session safe carrier replaced"
        );
    }
    for invalid in [-1, 7, i32::MAX] {
        let calls = Cell::new(0);
        ensure!(
            contract::at_start(invalid, || {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .is_err()
                && calls.get() == 0,
            "invalid session start stage executed callback"
        );
    }
    for index in 0..12 {
        let predicate = Predicate::try_from(index)?;
        need(true, predicate)?;
        let error = need(false, predicate).unwrap_err();
        ensure!(
            error.is::<PrivateFailure>() && error.to_string().len() < 160,
            "session predicate error type/bound differs"
        );
    }
    Ok(())
}
fn recovery(value: &SessionSnapshot) -> anyhow::Result<()> {
    use super::super::recovery::*;
    for mode in 0..12 {
        let live = Cell::new(!matches!(mode, 3 | 4));
        let stops = Cell::new(0);
        let mut foreign = value.clone();
        foreign.guid[0] ^= 1;
        let result = stop_owned(
            &value.path,
            mode != 2,
            matches!(mode, 4 | 7),
            if mode == 1 {
                Some(&foreign)
            } else if mode == 5 {
                None
            } else {
                Some(value)
            },
            || {
                Ok(if mode == 6 {
                    vec![value.clone(), value.clone()]
                } else if live.get() {
                    vec![value.clone()]
                } else {
                    vec![]
                })
            },
            || {
                Ok(if live.get() {
                    Some(if mode == 9 {
                        foreign.clone()
                    } else {
                        value.clone()
                    })
                } else if mode == 10 {
                    Some(foreign.clone())
                } else {
                    None
                })
            },
            |_| {
                stops.set(stops.get() + 1);
                ensure!(mode != 8, "fixed stop failure");
                live.set(mode == 11);
                let mut stopped = value.clone();
                if mode == 7 {
                    stopped.events_lost = 1;
                }
                Ok(stopped)
            },
        );
        ensure!(
            result.is_ok() == matches!(mode, 0 | 3 | 5)
                && stops.get() == usize::from(matches!(mode, 0 | 5 | 7 | 8 | 10 | 11)),
            "owned session recovery matrix differs"
        );
    }
    let run = "a".repeat(32);
    ensure!(
        intent_volume(&intent_text(&run, "F:\\")?, &run)? == "F:\\",
        "session intent volume changed"
    );
    let bound = bound_text(&run, value)?;
    value.require_same(&decode_bound(&bound, &run, &value.path)?)?;
    for text in [
        String::new(),
        format!("{bound}x"),
        bound.replace(&run, &"b".repeat(32)),
        bound.replace("0000000000000007", "0000000000000000"),
        bound.replace("12345678-1234-1234-1234-123456789abc", "bad-guid"),
    ] {
        ensure!(
            decode_bound(&text, &run, &value.path).is_err(),
            "foreign bound receipt accepted"
        );
    }
    let intent = intent_text(&run, "F:\\")?;
    for text in [
        String::new(),
        format!("{intent}x"),
        intent.replace(&run, "bad"),
        intent.replace("F:\\", "C:\\"),
    ] {
        ensure!(
            intent_volume(&text, &run).is_err(),
            "foreign intent receipt accepted"
        );
    }
    Ok(())
}
