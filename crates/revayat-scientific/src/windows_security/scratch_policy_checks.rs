//! Original ScratchAttachment and ScratchVolumePolicy callback/policy fixture matrices.
use super::{Failures, FileIdentity, failure, policy as scratch};
use crate::windows_security::policy::{self, Acl, Descriptor};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    sync::Arc,
};

fn fixture(mask: u32, medium: bool, users: bool) -> Result<Vec<u8>> {
    let system = super::sid("S-1-5-18")?;
    let mut entries = vec![super::ace(0, 0, mask, &system)];
    if users {
        entries.push(super::ace(0, 0, 0x80000000, &super::sid("S-1-5-32-545")?));
    }
    let label = super::sid(if medium { "S-1-16-8192" } else { "S-1-16-4096" })?;
    let sacl = super::acl(&[super::ace(17, 0, 1, &label)]);
    Ok(super::descriptor(
        0x1014,
        &system,
        &system,
        &super::acl(&entries),
        Some(&sacl),
    ))
}
pub fn check_attachment_validation() -> Result<()> {
    let mut number = vec![7, 0, 0, 0];
    number.extend(2u32.to_le_bytes());
    number.extend(1u32.to_le_bytes());
    scratch::attachment_number(&number, 2, 1)?;
    for rejected in [
        scratch::attachment_number(&[0; 11], 2, 1),
        scratch::attachment_number(&number, 3, 1),
        scratch::attachment_number(&number, 2, 2),
        scratch::attachment_number(&[0; 12], 0, 0),
        scratch::attachment_descriptor(&[0; 19]).map(|_| ()),
        scratch::attachment_descriptor(&vec![0; 65537]).map(|_| ()),
    ] {
        ensure!(
            rejected.is_err(),
            "scratch attachment accepted malformed identity or descriptor"
        );
    }
    let before = fixture(0x100020, false, false)?;
    ensure!(
        scratch::same_attachment_policy(&before, &fixture(0x100020, false, false)?)?,
        "scratch attachment equal policies differ"
    );
    let system = super::sid("S-1-5-18")?;
    let admin = super::sid("S-1-5-32-544")?;
    let sd = Descriptor::parse(&before)?;
    for changed in [
        super::descriptor(0x1014, &admin, &system, sd.dacl.unwrap(), sd.sacl),
        super::descriptor(0x1014, &system, &admin, sd.dacl.unwrap(), sd.sacl),
        fixture(0x100021, false, false)?,
        fixture(0x100020, true, false)?,
    ] {
        ensure!(
            !scratch::same_attachment_policy(&before, &changed)?,
            "scratch attachment conflated policy mutation"
        );
    }
    ensure!(
        scratch::attachment_pair("image-stable", Some(&before), Some(&before))?
            .contains("known=True equal=True"),
        "scratch attachment known pair differs"
    );
    let unknown = scratch::attachment_pair("image-volume", Some(&before), None)?;
    ensure!(
        unknown.contains("known=False equal=False")
            && unknown.len() < 256
            && !unknown.contains("S-1-"),
        "scratch attachment leaked unknown pair"
    );
    let original = failure("private-original");
    let identity = failure("private-identity");
    let cleanup = failure("private-cleanup");
    let closed = Cell::new(0);
    let error = scratch::release_attachment(
        Some(original.clone()),
        || Err(identity.clone()),
        || {
            closed.set(closed.get() + 1);
            Err(cleanup.clone())
        },
    )
    .unwrap_err();
    let group = error.downcast_ref::<Failures>().unwrap();
    ensure!(
        closed.get() == 1
            && group.errors.len() == 3
            && Arc::ptr_eq(&group.errors[0], &original)
            && Arc::ptr_eq(&group.errors[1], &identity)
            && Arc::ptr_eq(&group.errors[2], &cleanup),
        "scratch attachment lost cleanup order or failure identity"
    );
    Ok(())
}
pub fn check_volume_policy_validation() -> Result<()> {
    for legacy in [false, true] {
        for diagnostic in [false, true] {
            for supported in [false, true] {
                let mode = scratch::receipt_mode(legacy, diagnostic, supported);
                ensure!(
                    mode.is_err() == (legacy || diagnostic && supported),
                    "scratch receipt selection differs"
                );
                if let Ok(mode) = mode {
                    ensure!(
                        mode == if supported {
                            1
                        } else if diagnostic {
                            0
                        } else {
                            -1
                        },
                        "scratch receipt mode differs"
                    );
                }
            }
        }
    }
    ensure!(
        scratch::receipt_name(false) != scratch::receipt_name(true)
            && scratch::receipt_name(false) != scratch::LEGACY_RECEIPT
            && scratch::receipt_name(true) != scratch::LEGACY_RECEIPT,
        "scratch receipt names overlap"
    );
    for phase in [
        "preflight",
        "wall",
        "regressions",
        "registry-authority",
        "module-id2",
        "python-loader-trace",
    ] {
        for observe in [false, true] {
            for qualified in [false, true] {
                for registry in [None, Some(0), Some(scratch::DENIED)] {
                    ensure!(
                        scratch::supports(phase, observe, registry, qualified)
                            == (matches!(phase, "preflight" | "wall" | "regressions")
                                && registry == Some(0)
                                && (qualified || observe && phase == "preflight")),
                        "supported scratch phase differs"
                    );
                }
            }
        }
    }
    for supported in [false, true] {
        for running in [false, true] {
            for deferred in [false, true] {
                for clean in [false, true] {
                    ensure!(
                        policy::can_restore(supported, running, deferred, clean)
                            == (!deferred && (!supported || !running && clean)),
                        "scratch restoration gate differs"
                    );
                }
            }
        }
    }
    for mode in 0..4 {
        let order = RefCell::new(Vec::new());
        let failure = failure("fixed restoration");
        let result = scratch::complete_supported(
            mode != 1 && mode != 3,
            || {
                order.borrow_mut().push("restore");
                if mode == 2 {
                    Err(failure.clone())
                } else {
                    Ok(())
                }
            },
            || {
                order.borrow_mut().push("defer");
                if mode == 3 {
                    Err(failure.clone())
                } else {
                    Ok(())
                }
            },
        );
        ensure!(
            result.is_err() == (mode != 0)
                && order.into_inner()
                    == [if mode == 1 || mode == 3 {
                        "defer"
                    } else {
                        "restore"
                    }],
            "supported scratch completion ordering differs"
        );
        if mode == 2 {
            ensure!(
                Arc::ptr_eq(&result.unwrap_err(), &failure),
                "scratch restoration replaced original failure"
            );
        } else if mode == 3 {
            let error = result.unwrap_err();
            let group = error.downcast_ref::<Failures>().unwrap();
            ensure!(
                group.errors.len() == 2
                    && group.errors[0].to_string()
                        == "supported scratch process cleanup remains uncertain"
                    && Arc::ptr_eq(&group.errors[1], &failure),
                "scratch deferral lost uncertainty or failure identity"
            );
        }
    }
    let package = "S-1-15-2-1-2-3-4-5-6-7";
    let original = fixture(0x10000000, true, true)?;
    let trial = scratch::volume_trial(&original, package)?;
    let sd = Descriptor::parse(&trial)?;
    let acl = Acl::parse(sd.dacl.unwrap())?;
    let added = &acl.aces[2];
    ensure!(
        added.mask()? == 0x1301bf
            && added.mask()? == (0x301bf | 0x100000)
            && added.flags == 0
            && added.sid()? == super::sid(package)?
            && !policy::descriptor_equal(&original, &trial)?,
        "scratch trial ACE differs"
    );
    ensure!(
        scratch::volume_trial(&trial, package).is_err(),
        "scratch trial accepted duplicate package ACE"
    );
    let actual = RefCell::new(trial.clone());
    let writes = Cell::new(0);
    ensure!(
        scratch::restore_policy(
            &original,
            &trial,
            || Ok(actual.borrow().clone()),
            |bytes| {
                writes.set(writes.get() + 1);
                *actual.borrow_mut() = bytes.to_vec();
                Ok(())
            }
        )
        .is_ok(),
        "scratch restore failed"
    );
    ensure!(
        writes.get() == 1 && policy::descriptor_equal(&actual.borrow(), &original)?,
        "scratch restore did not persist original"
    );
    ensure!(
        scratch::restore_policy(
            &original,
            &trial,
            || Ok(original.clone()),
            |_| {
                writes.set(writes.get() + 1);
                Ok(())
            }
        )
        .is_ok()
            && writes.get() == 1,
        "scratch original restore was not idempotent"
    );
    let foreign = fixture(0x80000000, true, false)?;
    ensure!(
        scratch::restore_policy(
            &original,
            &trial,
            || Ok(foreign.clone()),
            |_| {
                writes.set(writes.get() + 1);
                Ok(())
            }
        )
        .is_err()
            && writes.get() == 1,
        "scratch restore overwrote foreign policy"
    );
    let operation = failure("private-operation");
    let cleanup = failure("private-cleanup");
    let attempts = Cell::new(0);
    let mut errors = Vec::new();
    super::attempt(&mut errors, || {
        attempts.set(attempts.get() + 1);
        Err(cleanup.clone())
    });
    super::attempt(&mut errors, || {
        attempts.set(attempts.get() + 1);
        Ok(())
    });
    let error = super::finish::<()>(Err(operation.clone()), errors).unwrap_err();
    let group = error.downcast_ref::<Failures>().unwrap();
    ensure!(
        attempts.get() == 2 && group.errors.len() == 2 && Arc::ptr_eq(&group.errors[0], &operation),
        "scratch cleanup lost original or close attempt"
    );
    differential_checks()?;
    for outer in [false, true] {
        for clean in [false, true] {
            for count in [0, 1] {
                for chosen in [false, true] {
                    ensure!(
                        policy::recovery_available(outer, clean, count, chosen)
                            == (outer || clean && count == 0 && !chosen),
                        "scratch recovery gate differs"
                    );
                }
            }
        }
    }
    ensure!(
        !policy::recovery_available(false, false, 0, false),
        "uncertain scratch recovery was admitted"
    );
    receipt_checks(package, original, trial)
}
fn differential_checks() -> Result<()> {
    let operation = failure("private-operation");
    let cleanup = failure("private-cleanup");
    for mode in 0..6 {
        let phase = Cell::new(0);
        let installs = Cell::new(0);
        let restores = Cell::new(0);
        let result = scratch::differential(
            || {
                let step = phase.get();
                phase.set(step + 1);
                if mode == 1 && step == 1 {
                    return Err(operation.clone());
                }
                if mode == 2 && step == 2 || mode == 3 && step == 0 {
                    return Ok(vec![0, 0]);
                }
                if mode == 4 && step == 1 {
                    return Ok(vec![1, 1]);
                }
                Ok(if step == 1 {
                    vec![0, 0]
                } else {
                    vec![scratch::DENIED, scratch::DENIED]
                })
            },
            || Ok(()),
            || {
                installs.set(installs.get() + 1);
                if mode == 5 {
                    Err(operation.clone())
                } else {
                    Ok(())
                }
            },
            || {
                restores.set(restores.get() + 1);
                Ok(())
            },
        );
        ensure!(
            result.is_err() == (mode != 0)
                && restores.get() == 1
                && installs.get() == if mode == 3 { 0 } else { 1 },
            "scratch differential fault ordering differs mode={mode}"
        );
        if let Ok(values) = result {
            ensure!(
                values.len() == 3 && mode == 0,
                "scratch differential result count differs"
            );
        }
    }
    for mode in 0..5 {
        let phase = Cell::new(0);
        let order = RefCell::new(Vec::new());
        let result = scratch::differential(
            || {
                let step = phase.get();
                phase.set(step + 1);
                order.borrow_mut().push(format!("probe{step}"));
                if (mode == 1 || mode == 4) && step == 1 {
                    return Err(operation.clone());
                }
                Ok(vec![
                    if step == 1 { 0 } else { scratch::DENIED },
                    if step == 1 { 0 } else { scratch::DENIED },
                    if mode == 3 && step == 2 { 0 } else { 5 },
                ])
            },
            || Ok(()),
            || {
                order.borrow_mut().push("install".into());
                Ok(())
            },
            || {
                order.borrow_mut().push("restore".into());
                if mode == 2 || mode == 4 {
                    Err(cleanup.clone())
                } else {
                    Ok(())
                }
            },
        );
        ensure!(
            result.is_err() == (mode != 0),
            "scratch differential error differs mode={mode}"
        );
        let expected = if mode == 0 || mode == 3 {
            "probe0,install,probe1,restore,probe2"
        } else {
            "probe0,install,probe1,restore"
        };
        ensure!(
            order.into_inner().join(",") == expected,
            "scratch differential cleanup sequence differs"
        );
        if mode == 0 {
            let values = result.unwrap();
            ensure!(
                values.len() == 3 && values[0][2] == 5 && values[2][2] == 5,
                "scratch differential lost complete restored vector"
            );
        } else if mode == 1 {
            ensure!(
                Arc::ptr_eq(&result.unwrap_err(), &operation),
                "scratch differential replaced original error"
            );
        } else if mode == 4 {
            let error = result.unwrap_err();
            let group = error.downcast_ref::<Failures>().unwrap();
            ensure!(
                group.errors.len() == 2
                    && Arc::ptr_eq(&group.errors[0], &operation)
                    && Arc::ptr_eq(&group.errors[1], &cleanup),
                "scratch differential lost independent errors"
            );
        }
    }
    Ok(())
}
fn receipt_checks(package: &str, original: Vec<u8>, trial: Vec<u8>) -> Result<()> {
    let mut receipt = scratch::VolumeReceipt {
        run: "a".repeat(32),
        package: package.into(),
        supported: false,
        root: "E:\\".into(),
        disk: 2,
        partition: 1,
        image: FileIdentity {
            volume: 1,
            high: 2,
            low: 3,
        },
        before: original.clone(),
        after: trial,
    };
    for supported in [false, true] {
        receipt.supported = supported;
        receipt.after = scratch::volume_trial(&original, package)?;
        let sd = Descriptor::parse(&receipt.after)?;
        let acl = Acl::parse(sd.dacl.unwrap())?;
        let mode_ace = &acl.aces[2];
        ensure!(
            mode_ace.mask()? == 0x1301bf
                && mode_ace.flags == 0
                && mode_ace.sid()? == super::sid(package)?,
            "scratch receipt mode trial differs"
        );
        let text = receipt.encode()?;
        let fields = text.split('\n').map(String::from).collect::<Vec<_>>();
        ensure!(
            fields.len() == 12
                && fields[10]
                    == format!(
                        "{:x}",
                        Sha256::digest(format!("{}\n", fields[..10].join("\n")).as_bytes())
                    )
                && !text.contains("private"),
            "scratch receipt shape or digest differs"
        );
        let decoded =
            scratch::VolumeReceipt::decode(text.as_bytes(), &receipt.run, package, supported)?;
        ensure!(
            policy::descriptor_equal(&decoded.before, &original)?
                && policy::descriptor_equal(&decoded.after, &receipt.after)?
                && decoded.supported == supported
                && decoded.disk == 2
                && decoded.partition == 1,
            "scratch receipt roundtrip differs"
        );
        for mode in 0..7 {
            let mut changed = fields.clone();
            match mode {
                0 => changed[0] = "scratch-volume-v2".into(),
                1 => changed[0] = "scratch-volume-v1".into(),
                2 => changed[3] = if supported { "diagnostic" } else { "supported" }.into(),
                3 => changed[0] = "scratch-volume-v4".into(),
                4 => changed[0] = "scratch-volume-v3".into(),
                5 => {
                    let mut old = receipt.after.clone();
                    let start = u32::from_le_bytes(old[16..20].try_into()?) as usize;
                    let offset = start + 8 + acl.aces[0].bytes.len() + acl.aces[1].bytes.len() + 4;
                    old[offset..offset + 4].copy_from_slice(
                        &(if supported { 0x100020u32 } else { 0x20u32 }).to_le_bytes(),
                    );
                    changed[9] = STANDARD.encode(old);
                }
                _ => changed[3] = "foreign".into(),
            }
            changed[10] = format!(
                "{:x}",
                Sha256::digest(format!("{}\n", changed[..10].join("\n")).as_bytes())
            );
            ensure!(
                scratch::VolumeReceipt::decode(
                    changed.join("\n").as_bytes(),
                    &receipt.run,
                    package,
                    supported
                )
                .is_err(),
                "scratch receipt accepted binding mutation mode={mode}"
            );
        }
        for invalid in [
            format!("{text}extra"),
            text.replace("scratch-volume-v5", "foreign"),
            text[..text.len() - 2].into(),
            text.replace(&fields[10], &"0".repeat(64)),
        ] {
            ensure!(
                scratch::VolumeReceipt::decode(
                    invalid.as_bytes(),
                    &receipt.run,
                    package,
                    supported
                )
                .is_err(),
                "scratch receipt accepted malformed text"
            );
        }
    }
    Ok(())
}
