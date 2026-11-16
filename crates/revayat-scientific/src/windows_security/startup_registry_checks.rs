//! Frozen StartupRegistryAccess.CheckValidation, including every reachable finalization assertion.
use super::*;
use std::{
    cell::Cell,
    mem::{offset_of, size_of},
};
const DENIED: i32 = 0xC0000022u32 as i32;
fn fault(text: &'static str) -> (anyhow::Error, *const std::io::Error) {
    let error = anyhow::Error::new(std::io::Error::other(text));
    let pointer = error.downcast_ref::<std::io::Error>().unwrap() as *const _;
    (error, pointer)
}
fn same(error: &anyhow::Error, pointer: *const std::io::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|value| std::ptr::eq(value, pointer))
}
fn group(error: &anyhow::Error) -> &[anyhow::Error] {
    &error.downcast_ref::<Failures>().unwrap().errors
}
pub fn check_validation() -> Result<()> {
    ensure!(
        size_of::<usize>() == 8
            && size_of::<UnicodeString>() == 16
            && size_of::<ObjectAttributes>() == 48,
        "startup registry requires exact x64 ABI"
    );
    ensure!(
        [
            offset_of!(UnicodeString, length),
            offset_of!(UnicodeString, maximum),
            offset_of!(UnicodeString, buffer)
        ] == [0, 2, 8]
    );
    ensure!(
        [
            offset_of!(ObjectAttributes, length),
            offset_of!(ObjectAttributes, root),
            offset_of!(ObjectAttributes, name),
            offset_of!(ObjectAttributes, flags),
            offset_of!(ObjectAttributes, descriptor),
            offset_of!(ObjectAttributes, qos)
        ] == [0, 8, 16, 24, 32, 40]
    );
    let text = KEY_PATH
        .encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    ensure!(
        KEY_PATH == r"\Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide"
            && ACCESS == 0x20019
            && text.len() == 142
            && text[140..] == [0, 0]
    );
    let name = fixed_name(11usize as *const u16);
    let object = fixed_attributes(22usize as *const UnicodeString);
    ensure!(
        (name.length, name.maximum, name.buffer as usize) == (140, 142, 11)
            && (
                object.length,
                object.root as usize,
                object.name as usize,
                object.flags,
                object.descriptor as usize,
                object.qos as usize
            ) == (48, 0, 22, 0x40, 0, 0)
    );
    ensure!(
        outcome("host", 0, 1)?
            == "WINDOWS_STARTUP_REGISTRY context=host label=sxs-policy desired_access=0x00020019 status=0x00000000 opened=True child_equivalence_claimed=False cause_claimed=False"
    );
    ensure!(outcome("lpac", DENIED, 0)?.contains("status=0xC0000022 opened=False"));
    for status in [0, 1, 0x40000003, i32::MAX] {
        ensure!(outcome("lpac", status, 1)?.contains("opened=True"));
        closed(status)?;
    }
    for (status, key) in [(0, 0), (0, usize::MAX), (DENIED, 1), (-1, usize::MAX)] {
        ensure!(outcome("lpac", status, key).is_err());
    }
    ensure!(outcome("private-registry-sentinel", 0, 1).is_err());
    for status in [-1, 0xC0000008u32 as i32, 0xC0000235u32 as i32] {
        ensure!(closed(status).is_err());
    }
    for operation_fails in [false, true] {
        let attempts = Cell::new(0);
        let (operation, pointer) = fault("fixed open failure");
        let error = observe_one(
            "lpac",
            |_| Ok(()),
            &|| Ok(()),
            &|| Ok(()),
            |key| {
                *key = 1;
                if operation_fails {
                    Err(operation)
                } else {
                    Ok(0)
                }
            },
            |_| {
                attempts.set(attempts.get() + 1);
                closed(0xC0000008u32 as i32)
            },
        )
        .unwrap_err();
        let errors = group(&error);
        ensure!(attempts.get() == 1 && errors.len() == if operation_fails { 2 } else { 1 });
        ensure!(!operation_fails || same(&errors[0], pointer));
        ensure!(errors.last().unwrap().to_string() == "close fixed registry read handle failed");
    }
    for label in ["host", "lpac"] {
        let order = RefCell::new(Vec::new());
        let calls = Cell::new(0);
        let closes = Cell::new(0);
        observe_one(
            label,
            |_| {
                order.borrow_mut().push("record");
                Ok(())
            },
            &|| {
                order.borrow_mut().push("deadline");
                Ok(())
            },
            &|| {
                order.borrow_mut().push("qualify");
                Ok(())
            },
            |key| {
                calls.set(calls.get() + 1);
                order.borrow_mut().push("open");
                *key = 1;
                Ok(0)
            },
            |key| {
                ensure!(key == 1);
                closes.set(closes.get() + 1);
                order.borrow_mut().push("close");
                Ok(())
            },
        )?;
        ensure!(
            calls.get() == 1
                && closes.get() == 1
                && *order.borrow()
                    == [
                        "deadline", "qualify", "open", "qualify", "deadline", "record", "close"
                    ]
        );
    }
    let (calls, closes, records) = (Cell::new(0), Cell::new(0), Cell::new(0));
    observe_one(
        "lpac",
        |_| {
            records.set(records.get() + 1);
            Ok(())
        },
        &|| Ok(()),
        &|| Ok(()),
        |_| {
            calls.set(calls.get() + 1);
            Ok(DENIED)
        },
        |_| {
            closes.set(closes.get() + 1);
            Ok(())
        },
    )?;
    ensure!((calls.get(), closes.get(), records.get()) == (1, 0, 1));
    ensure!(
        observe_one(
            "host",
            |_| Ok(()),
            &|| Ok(()),
            &|| Ok(()),
            |_| Ok(DENIED),
            |_| Ok(())
        )
        .is_err()
    );
    let closes = Cell::new(0);
    ensure!(
        observe_one(
            "lpac",
            |_| Ok(()),
            &|| Ok(()),
            &|| Ok(()),
            |key| {
                *key = 1;
                Ok(-1)
            },
            |_| {
                closes.set(closes.get() + 1);
                Ok(())
            }
        )
        .is_err()
            && closes.get() == 1
    );
    for fail_at in 0..6 {
        let (qualifications, deadlines, calls, closes, records) = (
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
            Cell::new(0),
        );
        let (primary, pointer) = fault("fixed primary");
        let primary = RefCell::new(Some(primary));
        let error = observe_one(
            "lpac",
            |_| {
                records.set(records.get() + 1);
                if fail_at == 5 {
                    Err(primary.borrow_mut().take().unwrap())
                } else {
                    Ok(())
                }
            },
            &|| {
                deadlines.set(deadlines.get() + 1);
                if fail_at == 0 && deadlines.get() == 1 || fail_at == 4 && deadlines.get() == 2 {
                    Err(primary.borrow_mut().take().unwrap())
                } else {
                    Ok(())
                }
            },
            &|| {
                qualifications.set(qualifications.get() + 1);
                if fail_at == 1 && qualifications.get() == 1
                    || fail_at == 3 && qualifications.get() == 2
                {
                    Err(primary.borrow_mut().take().unwrap())
                } else {
                    Ok(())
                }
            },
            |key| {
                calls.set(calls.get() + 1);
                *key = 1;
                if fail_at == 2 {
                    Err(primary.borrow_mut().take().unwrap())
                } else {
                    Ok(0)
                }
            },
            |_| {
                closes.set(closes.get() + 1);
                Ok(())
            },
        )
        .unwrap_err();
        ensure!(
            same(&error, pointer)
                && calls.get() == i32::from(fail_at >= 2)
                && closes.get() == calls.get()
                && records.get() == i32::from(fail_at == 5)
        );
    }
    let (primary, primary_pointer) = fault("fixed primary");
    let (cleanup, cleanup_pointer) = fault("fixed cleanup");
    let attempts = Cell::new(0);
    let error = observe_one(
        "lpac",
        |_| Ok(()),
        &|| Ok(()),
        &|| Ok(()),
        |key| {
            *key = 1;
            Err(primary)
        },
        |_| {
            attempts.set(attempts.get() + 1);
            Err(cleanup)
        },
    )
    .unwrap_err();
    ensure!(
        attempts.get() == 1
            && group(&error).len() == 2
            && same(&group(&error)[0], primary_pointer)
            && same(&group(&error)[1], cleanup_pointer)
    );
    let (primary, primary_pointer) = fault("fixed primary");
    let (cleanup, cleanup_pointer) = fault("fixed cleanup");
    let cleanup = RefCell::new(Some(cleanup));
    let attempts = Cell::new(0);
    let error = super::cleanup(
        Some(primary),
        vec![
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                Err(cleanup.borrow_mut().take().unwrap())
            }),
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                Ok(())
            }),
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                Ok(())
            }),
        ],
    )
    .unwrap_err();
    ensure!(
        attempts.get() == 3
            && group(&error).len() == 2
            && same(&group(&error)[0], primary_pointer)
            && same(&group(&error)[1], cleanup_pointer)
    );
    child_finalization()
}
fn child_finalization() -> Result<()> {
    let order = RefCell::new(Vec::new());
    finalize_child(
        None,
        true,
        || {
            order.borrow_mut().push("revert");
            Ok(true)
        },
        || anyhow::bail!("unexpected fail-fast"),
        vec![
            Box::new(|| {
                order.borrow_mut().push("duplicate");
                Ok(())
            }),
            Box::new(|| {
                order.borrow_mut().push("primary");
                Ok(())
            }),
        ],
        || {
            order.borrow_mut().push("emit");
            Ok(())
        },
    )?;
    ensure!(*order.borrow() == ["revert", "duplicate", "primary", "emit"]);
    for throws in [false, true] {
        let order = RefCell::new(Vec::new());
        let (fatal, pointer) = fault("fixed fail-fast");
        let error = finalize_child(
            None,
            true,
            || {
                order.borrow_mut().push("revert");
                if throws {
                    Err(fault("fixed revert").0)
                } else {
                    Ok(false)
                }
            },
            || {
                order.borrow_mut().push("fail-fast");
                Err(fatal)
            },
            vec![Box::new(|| {
                order.borrow_mut().push("close");
                Ok(())
            })],
            || {
                order.borrow_mut().push("emit");
                Ok(())
            },
        )
        .unwrap_err();
        ensure!(same(&error, pointer) && *order.borrow() == ["revert", "fail-fast"]);
    }
    let order = RefCell::new(Vec::new());
    ensure!(
        finalize_child(
            None,
            true,
            || Ok(false),
            || {
                order.borrow_mut().push("fail-fast");
                Ok(())
            },
            vec![Box::new(|| {
                order.borrow_mut().push("close");
                Ok(())
            })],
            || {
                order.borrow_mut().push("emit");
                Ok(())
            }
        )
        .is_err()
            && *order.borrow() == ["fail-fast"]
    );
    for impersonating in [false, true] {
        let order = RefCell::new(Vec::new());
        let (primary, primary_pointer) = fault("fixed operation");
        let (close, close_pointer) = fault("fixed close");
        let close = RefCell::new(Some(close));
        let (report, report_pointer) = fault("fixed report");
        let error = finalize_child(
            Some(primary),
            impersonating,
            || {
                order.borrow_mut().push("revert");
                Ok(true)
            },
            || anyhow::bail!("unexpected fail-fast"),
            vec![
                Box::new(|| {
                    order.borrow_mut().push("duplicate");
                    Err(close.borrow_mut().take().unwrap())
                }),
                Box::new(|| {
                    order.borrow_mut().push("primary");
                    Ok(())
                }),
            ],
            || {
                order.borrow_mut().push("emit");
                Err(report)
            },
        )
        .unwrap_err();
        ensure!(
            group(&error).len() == 3
                && same(&group(&error)[0], primary_pointer)
                && same(&group(&error)[1], close_pointer)
                && same(&group(&error)[2], report_pointer)
        );
        ensure!(
            *order.borrow()
                == if impersonating {
                    vec!["revert", "duplicate", "primary", "emit"]
                } else {
                    vec!["duplicate", "primary", "emit"]
                }
        );
    }
    Ok(())
}
