//! Fixed read-only SideBySide observations, never child attempted-object or admission evidence.
use super::*;
use crate::windows_security::{
    activation::{Failures, native::require_host},
    sxs::with_authority,
};
use registry_authority::native::{Attributes, Unicode};
use std::cell::RefCell;
const KEY_PATH: &str = r"\Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide";
const ACCESS: u32 = 0x20019;
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenKey(key: *mut Handle, access: u32, attributes: *const Attributes) -> i32;
}
fn fixed_name(text: *const u16) -> Unicode {
    Unicode {
        length: 140,
        maximum: 142,
        buffer: text,
    }
}
fn fixed_attributes(name: *const Unicode) -> Attributes {
    Attributes {
        length: 48,
        root: null_mut(),
        name,
        flags: 0x40,
        descriptor: null_mut(),
        qos: null_mut(),
    }
}
fn valid(handle: Handle) -> bool {
    !handle.is_null() && handle as usize != usize::MAX
}
fn outcome(label: &str, status: i32, key: Handle) -> Result<String> {
    ensure!(
        matches!(label, "host" | "lpac")
            && if status >= 0 {
                valid(key)
            } else {
                key.is_null()
            },
        "fixed registry-access contract is invalid"
    );
    Ok(format!(
        "WINDOWS_STARTUP_REGISTRY context={label} label=sxs-policy desired_access=0x00020019 status=0x{:08X} opened={} child_equivalence_claimed=False cause_claimed=False",
        status as u32,
        if status >= 0 { "True" } else { "False" }
    ))
}
fn closed(status: i32) -> Result<()> {
    ensure!(status >= 0, "close fixed registry read handle failed");
    Ok(())
}
fn finish<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(cleanup)) => Err(Failures {
            errors: vec![cleanup],
        }
        .into()),
        (Err(primary), Err(cleanup)) => Err(Failures {
            errors: vec![primary, cleanup],
        }
        .into()),
    }
}
fn observe_one(
    label: &str,
    record: impl FnOnce(String) -> Result<()>,
    deadline: &dyn Fn() -> Result<()>,
    qualify: &dyn Fn() -> Result<()>,
    open: impl FnOnce(&mut Handle) -> Result<i32>,
    close: impl FnOnce(Handle) -> Result<()>,
) -> Result<i32> {
    let mut key = null_mut();
    let result = (|| {
        deadline()?;
        qualify()?;
        let status = open(&mut key)?;
        qualify()?;
        deadline()?;
        record(outcome(label, status, key)?)?;
        ensure!(
            label != "host" || status >= 0,
            "host fixed registry positive control failed"
        );
        Ok(status)
    })();
    let owned = std::mem::replace(&mut key, null_mut());
    let cleanup = if valid(owned) { close(owned) } else { Ok(()) };
    finish(result, cleanup)
}
fn observe_fixed(
    label: &str,
    lines: &mut Vec<String>,
    deadline: &dyn Fn() -> Result<()>,
    qualify: &dyn Fn() -> Result<()>,
) -> Result<i32> {
    observe_one(
        label,
        |line| {
            lines.push(line);
            Ok(())
        },
        deadline,
        qualify,
        |key| {
            let text = KEY_PATH.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let name = fixed_name(text.as_ptr());
            let attributes = fixed_attributes(&name);
            // All borrowed name/object storage outlives the exact synchronous read-open.
            Ok(unsafe { NtOpenKey(key, ACCESS, &attributes) })
        },
        |key| closed(unsafe { registry_authority::native::NtClose(key) }),
    )
}
pub(super) fn observe_child(
    process: Handle,
    package: &str,
    emit: impl FnOnce(&[String]) -> Result<()>,
) -> Result<i32> {
    require_host()?;
    let started = Instant::now();
    let deadline = || {
        ensure!(
            started.elapsed() <= Duration::from_secs(10),
            "fixed child registry comparison exceeded 10 seconds"
        );
        Ok(())
    };
    let lines = RefCell::new(Vec::with_capacity(2));
    let operation = (|| {
        // This original host positive control must precede all child-token acquisition.
        observe_fixed("host", &mut lines.borrow_mut(), &deadline, &|| Ok(()))?;
        with_authority(process, package, &deadline, |require_same| {
            require_same()?;
            let status = observe_fixed("lpac", &mut lines.borrow_mut(), &deadline, require_same)?;
            require_same()?;
            deadline()?;
            Ok(status)
        })
    })();
    let reporting = emit(&lines.borrow());
    finish(operation, reporting)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        mem::{offset_of, size_of},
    };
    fn fake() -> Handle {
        1usize as Handle
    }
    fn refused<T>(result: Result<T>) {
        let error = result
            .err()
            .expect("inconsistent original contract must fail");
        assert!(!error.to_string().contains("private-registry-sentinel"));
    }
    #[test]
    fn fixed_registry_abi_name_access_and_all_original_status_vectors_are_exact() {
        assert_eq!((size_of::<Unicode>(), size_of::<Attributes>()), (16, 48));
        assert_eq!(
            [
                offset_of!(Unicode, length),
                offset_of!(Unicode, maximum),
                offset_of!(Unicode, buffer)
            ],
            [0, 2, 8]
        );
        assert_eq!(
            [
                offset_of!(Attributes, length),
                offset_of!(Attributes, root),
                offset_of!(Attributes, name),
                offset_of!(Attributes, flags),
                offset_of!(Attributes, descriptor),
                offset_of!(Attributes, qos)
            ],
            [0, 8, 16, 24, 32, 40]
        );
        assert_eq!(
            KEY_PATH,
            r"\Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide"
        );
        assert_eq!(ACCESS, 0x20019);
        let text = KEY_PATH.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        assert_eq!((text.len() * 2, text[70]), (142, 0));
        let name = fixed_name(11usize as *const u16);
        let object = fixed_attributes(22usize as *const Unicode);
        assert_eq!(
            (name.length, name.maximum, name.buffer as usize),
            (140, 142, 11)
        );
        assert_eq!(
            (
                object.length,
                object.root as usize,
                object.name as usize,
                object.flags,
                object.descriptor as usize,
                object.qos as usize
            ),
            (48, 0, 22, 0x40, 0, 0)
        );
        assert_eq!(
            outcome("host", 0, fake()).unwrap(),
            "WINDOWS_STARTUP_REGISTRY context=host label=sxs-policy desired_access=0x00020019 status=0x00000000 opened=True child_equivalence_claimed=False cause_claimed=False"
        );
        assert!(
            outcome("lpac", 0xc0000022u32 as i32, null_mut())
                .unwrap()
                .contains("status=0xC0000022 opened=False")
        );
        for status in [0, 1, 0x40000003, i32::MAX] {
            assert!(
                outcome("lpac", status, fake())
                    .unwrap()
                    .contains("opened=True")
            );
            closed(status).unwrap();
        }
        for (status, key) in [
            (0, null_mut()),
            (0, usize::MAX as Handle),
            (0xc0000022u32 as i32, fake()),
            (-1, usize::MAX as Handle),
        ] {
            refused(outcome("lpac", status, key));
        }
        refused(outcome("private-registry-sentinel", 0, fake()));
        for status in [-1, 0xc0000008u32 as i32, 0xc0000235u32 as i32] {
            refused(closed(status));
        }
    }
    #[test]
    fn original_observe_one_orders_checks_records_and_owned_close_for_both_roles() {
        for label in ["host", "lpac"] {
            let order = RefCell::new(Vec::new());
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
                    order.borrow_mut().push("open");
                    *key = fake();
                    Ok(0)
                },
                |key| {
                    assert_eq!(key, fake());
                    order.borrow_mut().push("close");
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                *order.borrow(),
                [
                    "deadline", "qualify", "open", "qualify", "deadline", "record", "close"
                ]
            );
        }
        let counts = Cell::new((0, 0));
        let denied = observe_one(
            "lpac",
            |_| {
                let (r, c) = counts.get();
                counts.set((r + 1, c));
                Ok(())
            },
            &|| Ok(()),
            &|| Ok(()),
            |_| Ok(0xc0000022u32 as i32),
            |_| {
                let (r, c) = counts.get();
                counts.set((r, c + 1));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!((denied, counts.get()), (0xc0000022u32 as i32, (1, 0)));
        refused(observe_one(
            "host",
            |_| Ok(()),
            &|| Ok(()),
            &|| Ok(()),
            |_| Ok(0xc0000022u32 as i32),
            |_| Ok(()),
        ));
        let closes = Cell::new(0);
        refused(observe_one(
            "lpac",
            |_| Ok(()),
            &|| Ok(()),
            &|| Ok(()),
            |key| {
                *key = fake();
                Ok(-1)
            },
            |_| {
                closes.set(closes.get() + 1);
                Ok(())
            },
        ));
        assert_eq!(closes.get(), 1);
    }
    #[test]
    fn all_six_original_failure_boundaries_close_only_acquired_handles_and_keep_primary() {
        for fail_at in 0..6 {
            let (deadlines, qualifications, opens, closes, records) = (
                Cell::new(0),
                Cell::new(0),
                Cell::new(0),
                Cell::new(0),
                Cell::new(0),
            );
            let result = observe_one(
                "lpac",
                |_| {
                    records.set(records.get() + 1);
                    if fail_at == 5 {
                        anyhow::bail!("fixed primary");
                    }
                    Ok(())
                },
                &|| {
                    deadlines.set(deadlines.get() + 1);
                    if fail_at == 0 && deadlines.get() == 1 || fail_at == 4 && deadlines.get() == 2
                    {
                        anyhow::bail!("fixed primary");
                    }
                    Ok(())
                },
                &|| {
                    qualifications.set(qualifications.get() + 1);
                    if fail_at == 1 && qualifications.get() == 1
                        || fail_at == 3 && qualifications.get() == 2
                    {
                        anyhow::bail!("fixed primary");
                    }
                    Ok(())
                },
                |key| {
                    opens.set(opens.get() + 1);
                    *key = fake();
                    if fail_at == 2 {
                        anyhow::bail!("fixed primary");
                    }
                    Ok(0)
                },
                |_| {
                    closes.set(closes.get() + 1);
                    Ok(())
                },
            );
            assert_eq!(result.unwrap_err().to_string(), "fixed primary");
            assert_eq!(
                (opens.get(), closes.get(), records.get()),
                (
                    i32::from(fail_at >= 2),
                    i32::from(fail_at >= 2),
                    i32::from(fail_at == 5)
                )
            );
        }
        for primary_fails in [false, true] {
            let closes = Cell::new(0);
            let error = observe_one(
                "lpac",
                |_| Ok(()),
                &|| Ok(()),
                &|| Ok(()),
                |key| {
                    *key = fake();
                    if primary_fails {
                        anyhow::bail!("fixed primary");
                    }
                    Ok(0)
                },
                |_| {
                    closes.set(closes.get() + 1);
                    anyhow::bail!("fixed close");
                },
            )
            .unwrap_err();
            let errors = &error
                .downcast_ref::<crate::windows_security::activation::Failures>()
                .unwrap()
                .errors;
            assert_eq!(
                (closes.get(), errors.len()),
                (1, if primary_fails { 2 } else { 1 })
            );
            assert_eq!(errors.last().unwrap().to_string(), "fixed close");
            if primary_fails {
                assert_eq!(errors[0].to_string(), "fixed primary");
            }
        }
    }
    #[test]
    fn existing_qualified_child_is_the_only_context_and_host_read_precedes_acquisition() {
        let source = include_str!("startup_access.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(
            source.find("observe_fixed(\"host\"").unwrap()
                < source.find("with_authority(").unwrap()
        );
        assert!(source.contains("NtOpenKey(key, ACCESS, &attributes)"));
        assert!(
            !source.contains("NtSet")
                && !source.contains("NtCreate")
                && !source.contains("CreateProcess")
        );
        assert!(
            source.find("with_authority(").unwrap() < source.find("emit(&lines.borrow())").unwrap()
        );
        assert!(
            source.find("require_host()?;").unwrap()
                < source.find("observe_fixed(\"host\"").unwrap()
        );
        let context = include_str!("../sxs/native_context.rs");
        assert!(
            context.contains("scoped(copy.0")
                && context.contains("[cleanup(), copy.close(), primary.close()]")
        );
        let errors = finish::<()>(
            Err(anyhow::anyhow!("fixed primary")),
            Err(anyhow::anyhow!("fixed report")),
        )
        .unwrap_err();
        let errors = &errors.downcast_ref::<Failures>().unwrap().errors;
        assert_eq!(
            errors.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["fixed primary", "fixed report"]
        );
    }
    #[test]
    fn shared_scoped_owner_and_finalizer_keep_original_restore_close_emit_failure_order() {
        use crate::windows_security::activation::finalize_comparison;
        for impersonating in [false, true] {
            let order = RefCell::new(Vec::new());
            let error = finalize_comparison(
                Some(anyhow::anyhow!("fixed primary")),
                impersonating,
                || {
                    order.borrow_mut().push("revert");
                    Ok(())
                },
                || panic!("unexpected fatal"),
                vec![
                    Box::new(|| {
                        order.borrow_mut().push("duplicate");
                        anyhow::bail!("fixed close");
                    }),
                    Box::new(|| {
                        order.borrow_mut().push("primary");
                        Ok(())
                    }),
                ],
                || {
                    order.borrow_mut().push("emit");
                    anyhow::bail!("fixed report");
                },
            )
            .unwrap_err();
            let expected = if impersonating {
                vec!["revert", "duplicate", "primary", "emit"]
            } else {
                vec!["duplicate", "primary", "emit"]
            };
            assert_eq!(*order.borrow(), expected);
            let errors = &error.downcast_ref::<Failures>().unwrap().errors;
            assert_eq!(
                errors.iter().map(ToString::to_string).collect::<Vec<_>>(),
                ["fixed primary", "fixed close", "fixed report"]
            );
        }
        let order = RefCell::new(Vec::new());
        let error = finalize_comparison(
            None,
            true,
            || {
                order.borrow_mut().push("revert");
                anyhow::bail!("fixed revert");
            },
            || order.borrow_mut().push("fatal"),
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
        assert_eq!(*order.borrow(), ["revert", "fatal"]);
        assert!(error.downcast_ref::<Failures>().is_some());
        // This models only finalization. The real shared scoped owner must abort on failed restore.
        let identity = include_str!("../sxs/native_identity.rs");
        let restoration = identity
            .split_once("fn restore(&mut self)")
            .unwrap()
            .1
            .split_once("impl Drop for Impersonation")
            .unwrap()
            .0;
        assert!(
            restoration.contains("RevertToSelf()") && restoration.contains("std::process::abort()")
        );
    }
    #[test]
    fn actual_host_fixed_read_open_closes_the_key_without_mutating_machine_policy() {
        let mut rows = Vec::new();
        let status = observe_fixed("host", &mut rows, &|| Ok(()), &|| Ok(())).unwrap();
        assert!(status >= 0);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].starts_with("WINDOWS_STARTUP_REGISTRY context=host label=sxs-policy "));
        assert!(rows[0].ends_with("child_equivalence_claimed=False cause_claimed=False"));
    }
}
