//! Original ScratchAccess and supported-volume fixture matrices; no native API is invoked.
use super::{Failures, FileIdentity, access::*, failure, same_identity, sid};
use anyhow::{Result, ensure};
use std::{
    cell::Cell,
    mem::{offset_of, size_of},
    sync::Arc,
};

fn privileges(entries: &[(u64, u32)]) -> Vec<u8> {
    let mut bytes = (entries.len() as u32).to_le_bytes().to_vec();
    for (luid, attributes) in entries {
        bytes.extend(luid.to_le_bytes());
        bytes.extend(attributes.to_le_bytes());
    }
    bytes
}
fn privilege_checks() -> Result<()> {
    ensure!(
        Privileges::parse(&[0; 4])?
            .frame("primary")?
            .contains("count=0 traversal_present=False traversal_enabled=False"),
        "scratch empty privilege frame differs"
    );
    for attributes in [0, 1, 2, 3, 0x80000002] {
        let mut bytes = privileges(&[(23, attributes)]);
        let value = Privileges::parse(&bytes)?;
        value.same(&Privileges::parse(&bytes)?)?;
        let frame = value.frame("duplicate")?;
        ensure!(
            frame.contains(&format!(
                "count=1 traversal_present=True traversal_enabled={}",
                super::truth(attributes & 2 != 0)
            )) && frame.contains(&format!("attributes=0x{attributes:08X}"))
                && frame.len() < 256,
            "scratch privilege frame differs"
        );
        let mut changed = bytes.clone();
        changed[12] ^= 2;
        ensure!(
            value.same(&Privileges::parse(&changed)?).is_err(),
            "scratch privilege attribute mutation accepted"
        );
        bytes[8] = 1;
        let other = Privileges::parse(&bytes)?;
        ensure!(
            !other.present && value.same(&other).is_err(),
            "scratch privilege accepted partial LUID equality"
        );
    }
    for bytes in [
        vec![0; 3],
        vec![0; 65537],
        vec![1, 0, 0, 0],
        vec![129, 0, 0, 0],
        privileges(&[(23, 0), (23, 0)]),
    ] {
        ensure!(
            Privileges::parse(&bytes).is_err(),
            "scratch privilege accepted malformed or duplicate inventory"
        );
    }
    Ok(())
}
fn native_observation_checks() -> Result<()> {
    ensure!(
        size_of::<usize>() == 8
            && size_of::<UnicodeString>() == 16
            && size_of::<ObjectAttributes>() == 48
            && size_of::<IoStatus>() == 16
            && offset_of!(ObjectAttributes, name) == 16
            && offset_of!(IoStatus, information) == 8,
        "scratch native observation ABI differs"
    );
    let names = native_names("E:\\", |drive, output| {
        ensure!(
            drive == "E:" && output.len() == 512,
            "scratch device query request differs"
        );
        let text = "\\Device\\HarddiskVolume12\0\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        output[..text.len()].copy_from_slice(&text);
        Ok(text.len() as u32)
    })?;
    ensure!(
        names == ["\\??\\E:\\", "\\Device\\HarddiskVolume12\\"],
        "scratch native name families differ"
    );
    for bad in ["E:", "E:\\temp", "e:\\", "C:\\", "\\\\server\\share\\"] {
        let calls = Cell::new(0);
        let result = native_names(bad, |_, _| {
            calls.set(calls.get() + 1);
            Ok(0)
        });
        ensure!(
            result.is_err() && calls.get() == 0,
            "invalid scratch drive reached device lookup"
        );
    }
    for bad in [
        "",
        "\\Device\\HarddiskVolume12\0",
        "\\Device\\HarddiskVolume12\0old\0\0",
        "\\Device\\HarddiskVolume\0\0",
        "\\Device\\HarddiskVolume1\\extra\0\0",
        "\\??\\E:\0\0",
    ] {
        ensure!(
            native_names("E:\\", |_, output| {
                let text = bad.encode_utf16().collect::<Vec<_>>();
                output[..text.len()].copy_from_slice(&text);
                Ok(text.len() as u32)
            })
            .is_err(),
            "scratch device mapping accepted malformed termination or family"
        );
    }
    for length in [0, 1, 513, u32::MAX] {
        ensure!(
            native_names("E:\\", |_, _| Ok(length)).is_err(),
            "scratch device mapping accepted out-of-bound span"
        );
    }
    let absolute_temp = format!("{}temp", names[1]);
    for path in [
        names[0].as_str(),
        names[1].as_str(),
        absolute_temp.as_str(),
        "temp",
    ] {
        let relative = path == "temp";
        let mut request =
            NativeRequest::new(path, "host", if relative { "temp-relative" } else { "dos" });
        request.root = if relative { 23 } else { 0 };
        if relative {
            request.target = "temp".into();
        }
        let (calls, binds, closes) = (Cell::new(0), Cell::new(0), Cell::new(0));
        let result = request.open(
            |call, output| {
                calls.set(calls.get() + 1);
                super::need(
                    call.access == DESIRED
                        && call.share == 7
                        && call.options == 0x200021
                        && call.object.length == 48
                        && call.object.root == if relative { 23 } else { 0 }
                        && call.object.attributes == 0x40
                        && call.object.descriptor == 0
                        && call.object.qos == 0
                        && call.object.name == call.unicode as *const _ as usize
                        && output.handle == 0
                        && output.io.status == -1,
                )?;
                super::need(
                    usize::from(call.unicode.length) == path.encode_utf16().count() * 2
                        && call.unicode.maximum == call.unicode.length + 2
                        && call.unicode.buffer == call.text.as_ptr() as usize
                        && call.text.last() == Some(&0)
                        && String::from_utf16(&call.text[..call.text.len() - 1])
                            .is_ok_and(|value| value == path),
                )?;
                output.handle = 17;
                output.io.status = 0;
                output.io.information = 1;
                Ok(0)
            },
            || Err(failure("unexpected scratch pending fixture")),
        );
        let opened = request.opened;
        let released = request.release(
            |_| {
                binds.set(binds.get() + 1);
                Ok(())
            },
            |handle| {
                super::need(handle == 17)?;
                closes.set(closes.get() + 1);
                Ok(())
            },
        );
        ensure!(
            result.is_ok()
                && opened
                && released.is_ok()
                && calls.get() == 1
                && binds.get() == 1
                && closes.get() == 1
                && !request.has_storage(),
            "scratch native request did not bind/close/release exactly once"
        );
        let frame = request.frame()?;
        ensure!(
            frame.len() < 512
                && (relative || !frame.contains(path))
                && frame.contains(&format!("role=host name={}", request.name))
                && frame.contains("opened=True"),
            "scratch native frame escaped fixed metadata"
        );
    }
    for status in [0, super::volume::DENIED] {
        let mut request = NativeRequest::new("", "lpac", "device");
        request.returned = status;
        request.opened = status == 0;
        ensure!(
            request
                .frame()?
                .contains(&format!("ntstatus=0x{:08X}", status as u32)),
            "scratch native frame status differs"
        );
    }
    for returned in [PENDING, 0, super::volume::DENIED] {
        let fatal = Cell::new(false);
        let result = require_synchronous(
            returned,
            IoStatus {
                status: if returned == 0 { PENDING } else { 0 },
                information: 0,
            },
            || {
                fatal.set(true);
                Ok(())
            },
        );
        ensure!(
            fatal.get() == matches!(returned, PENDING | 0) && result.is_err() == fatal.get(),
            "scratch pending return/completion was not fatal"
        );
    }
    for bytes in [0, 7, 8, 9, usize::MAX] {
        ensure!(
            require_volume(
                0,
                IoStatus {
                    status: 0,
                    information: bytes
                }
            )
            .is_err()
                == (bytes != 8),
            "scratch device information size differs"
        );
    }
    let original = failure("private-close");
    let attempts = Cell::new(0);
    let mut failed = NativeRequest::new("", "host", "device");
    failed.output = Some(Box::new(OpenOutput {
        handle: 17,
        io: IoStatus {
            status: 0,
            information: 0,
        },
    }));
    let result = failed
        .release(
            |_| {
                attempts.set(attempts.get() + 1);
                Err(original.clone())
            },
            |_| {
                attempts.set(attempts.get() + 1);
                Ok(())
            },
        )
        .unwrap_err();
    let group = result.downcast_ref::<Failures>().unwrap();
    ensure!(
        attempts.get() == 2
            && !failed.has_storage()
            && group.errors.len() == 1
            && Arc::ptr_eq(&group.errors[0], &original),
        "scratch native release lost all attempts or original error"
    );
    Ok(())
}
pub fn check_access_validation() -> Result<()> {
    native_observation_checks()?;
    privilege_checks()?;
    ensure!(
        size_of::<FileIdentity>() == 24 && size_of::<AttributeInformation>() == 8,
        "scratch file identity/attribute ABI differs"
    );
    let expected = FileIdentity {
        volume: 1,
        high: 2,
        low: 3,
    };
    same_identity(expected, expected)?;
    for actual in [
        FileIdentity {
            volume: 4,
            ..expected
        },
        FileIdentity {
            high: 4,
            ..expected
        },
        FileIdentity { low: 4, ..expected },
    ] {
        ensure!(
            same_identity(expected, actual).is_err(),
            "scratch object identity mutation accepted"
        );
    }
    let user = sid("S-1-5-21-1-2-3-1000")?;
    let package = sid("S-1-15-2-1")?;
    let system = sid("S-1-5-18")?;
    let dacl = super::acl(&[
        super::ace(1, 0, 0xc0000, &sid("S-1-3-4")?),
        super::ace(0, 0, 0x1301bf, &package),
    ]);
    let sacl = super::acl(&[super::ace(17, 0, 1, &sid("S-1-16-4096")?)]);
    let bytes = super::descriptor(0x1014, &user, &system, &dacl, Some(&sacl));
    let policy = policy_summary(&bytes, &user, &package)?;
    ensure!(
        policy
            == "owner_user=True dacl_present=True dacl_null=False package_allow=0x001301BF package_deny=0x00000000 owner_deny=0x000C0000 label_present=True label_rid=0x00001000 label_policy=0x00000001",
        "scratch descriptor model differs"
    );
    for allowed in [false, true] {
        for opened in [false, true] {
            let result = AccessResult {
                checked: true,
                allowed,
                granted: if allowed { DESIRED } else { 0 },
                opened,
                open_error: if opened { 0 } else { 5 },
                policy: policy.clone(),
                ..AccessResult::default()
            };
            let frame = result.frame("root")?;
            ensure!(
                frame.contains(&format!("allowed={}", super::truth(allowed)))
                    && frame.contains(&format!("opened={}", super::truth(opened)))
                    && frame.len() <= 1024
                    && !frame.contains("S-1-")
                    && frame.ends_with("child_equivalence_claimed=False"),
                "scratch descriptor/open observations were conflated or leaked principals"
            );
        }
    }
    ensure!(
        AccessResult {
            query: 5,
            open_error: 5,
            ..AccessResult::default()
        }
        .frame("temp")?
        .contains(
            "descriptor_error=0x00000005 check_completed=False allowed=False granted=0x00000000"
        ),
        "scratch unknown descriptor invented access proof"
    );
    for invalid in [
        AccessResult::default().frame("private-path"),
        AccessResult {
            allowed: true,
            ..AccessResult::default()
        }
        .frame("root"),
        AccessResult {
            granted: DESIRED,
            ..AccessResult::default()
        }
        .frame("root"),
        AccessResult {
            opened: true,
            open_error: 5,
            ..AccessResult::default()
        }
        .frame("root"),
        policy_summary(&[0; 19], &user, &package),
        policy_summary(&vec![0; 65537], &user, &package),
    ] {
        ensure!(
            invalid.is_err(),
            "scratch observation accepted malformed frame or descriptor"
        );
    }
    let primary = failure("private-primary");
    let cleanup = failure("private-cleanup");
    for fail in [false, true] {
        let mut errors = Vec::new();
        let attempts = Cell::new(0);
        super::attempt(&mut errors, || {
            attempts.set(attempts.get() + 1);
            if fail { Err(cleanup.clone()) } else { Ok(()) }
        });
        super::attempt(&mut errors, || {
            attempts.set(attempts.get() + 1);
            Ok(())
        });
        let error = super::finish::<()>(Err(primary.clone()), errors).unwrap_err();
        ensure!(
            attempts.get() == 2,
            "scratch cleanup skipped an independent attempt"
        );
        if fail {
            let group = error.downcast_ref::<Failures>().unwrap();
            ensure!(
                group.errors.len() == 2
                    && Arc::ptr_eq(&group.errors[0], &primary)
                    && Arc::ptr_eq(&group.errors[1], &cleanup),
                "scratch cleanup replaced ordered error identities"
            );
        } else {
            ensure!(
                Arc::ptr_eq(&error, &primary),
                "clean scratch cleanup replaced original failure"
            );
        }
    }
    Ok(())
}
pub fn check_supported_validation() -> Result<()> {
    for errors in [
        vec![0, 0],
        vec![0, 5],
        vec![5, 0],
        vec![0, 2],
        vec![],
        vec![0],
        vec![0, 0, 0],
    ] {
        ensure!(
            super::file::require_supported_creation(&errors).is_err()
                == (errors.as_slice() != [0, 0]),
            "supported scratch creation result differs"
        );
    }
    let count = super::volume::MASKS.len();
    let mut result = vec![0; 2 + count * 5];
    for (index, mask) in super::volume::MASKS.iter().enumerate() {
        let readable = matches!(index, 2 | 6);
        result[2 + index] = if readable { 0 } else { super::volume::DENIED };
        result[2 + count + index] = if readable { *mask as i32 } else { 0 };
    }
    crate::windows_security::policy::require_supported_results(&result)?;
    for index in 0..2 + count * 2 {
        let mut changed = result.clone();
        changed[index] ^= 1;
        ensure!(
            crate::windows_security::policy::require_supported_results(&changed).is_err(),
            "supported scratch vector authority mutation accepted"
        );
    }
    for length in [0, result.len() - 1, result.len() + 1] {
        ensure!(
            crate::windows_security::policy::require_supported_results(&vec![0; length]).is_err(),
            "supported scratch result length mutation accepted"
        );
    }
    for attributes in [0, 1, 2, 3, 4, 0x80000002] {
        ensure!(
            Privileges::parse(&privileges(&[(23, attributes)]))?
                .supported()
                .is_err()
                == !matches!(attributes, 2 | 3),
            "supported scratch privilege enablement differs"
        );
    }
    for bytes in [vec![0; 4], vec![0; 28]] {
        ensure!(
            Privileges::parse(&bytes)?.supported().is_err(),
            "supported scratch accepted absent traversal inventory"
        );
    }
    Ok(())
}
