//! Source-equivalent inert checks for PrivateCreatorFixture.CheckValidation.
use super::{FileIdentity, OperationResult, failure, private, same_identity, sid};
use anyhow::{Result, ensure};
use std::{
    cell::{Cell, RefCell},
    sync::Arc,
};

fn offset(bytes: &[u8], field: usize) -> usize {
    u32::from_le_bytes(bytes[field..field + 4].try_into().unwrap()) as usize
}
pub fn check_private_creator_validation() -> Result<()> {
    let user = sid("S-1-5-21-101-202-303-1001")?;
    let package = sid("S-1-15-2-101-202-303-404-505-606-707")?;
    for line in [-1, 0, 1, 9999, 10000, i32::MAX] {
        let caught = private::policy_need(false, line, 0, 0, 0, 0).unwrap_err();
        let expected = format!(
            "fixed private creator fixture rejected line={} field=0 first=0x00000000 second=0x00000000 third=0x00000000",
            if (1..=9999).contains(&line) { line } else { 0 }
        );
        ensure!(
            caught.to_string() == expected,
            "private creator line diagnostics differ"
        );
    }
    ensure!(
        private::policy_need(false, 123, 1, u32::MAX, 0, 0x80000000)
            .unwrap_err()
            .to_string()
            == "fixed private creator fixture rejected line=123 field=1 first=0xFFFFFFFF second=0x00000000 third=0x80000000",
        "private policy diagnostics differ"
    );
    private::policy_need(true, 0, 0, 0, 0, 0)?;
    private::policy_need(true, 0, 1, 0, 0, 0)?;
    let bytes = private::policy(&user, &package);
    private::require_policy(&bytes, &user, &package)?;
    for bookkeeping in [0, 0x400, 0x800, 0xc00] {
        let mut exact = bytes.clone();
        exact[2..4].copy_from_slice(&(0x9014u16 | bookkeeping).to_le_bytes());
        private::require_policy(&exact, &user, &package)?;
        for flags in [(0x9014 | bookkeeping) | 8, (0x9014 | bookkeeping) & !0x1000] {
            let mut changed = exact.clone();
            changed[2..4].copy_from_slice(&flags.to_le_bytes());
            ensure!(
                private::require_policy(&changed, &user, &package).is_err(),
                "private policy accepted control mutation"
            );
        }
        let first = offset(&exact, 16) + 8;
        exact[first + 1] |= 16;
        ensure!(
            private::require_policy(&exact, &user, &package).is_err(),
            "private policy accepted inherited ACE"
        );
    }
    let dacl = offset(&bytes, 16);
    let sacl = offset(&bytes, 12);
    let mut samples = Vec::new();
    let mut changed = bytes.clone();
    changed[3] &= !0x10;
    samples.push((changed, 1));
    let only_user = super::acl(&[super::ace(0, 0, 0x1f01ff, &user)]);
    samples.push((
        super::descriptor(
            0x1014,
            &user,
            &user,
            &only_user,
            Some(&bytes[sacl..sacl + 28]),
        ),
        2,
    ));
    let mut changed = bytes.clone();
    changed[dacl + 12..dacl + 16].copy_from_slice(&0x120089u32.to_le_bytes());
    samples.push((changed, 3));
    let mut changed = bytes.clone();
    changed[sacl + 9] = 1;
    samples.push((changed, 4));
    let mut changed = bytes.clone();
    changed[sacl + 12..sacl + 16].copy_from_slice(&2u32.to_le_bytes());
    samples.push((changed, 5));
    for (sample, field) in &samples {
        let error = private::require_policy(sample, &user, &package)
            .unwrap_err()
            .to_string();
        ensure!(
            error.contains(&format!(" field={field} first=0x")) && !error.contains("S-1-"),
            "private policy field diagnostics differ"
        );
    }
    let mut mutations = samples.into_iter().map(|v| v.0).collect::<Vec<_>>();
    for (at, value) in [(dacl + 9, 1), (dacl + 8, 1), (sacl + 25, 32)] {
        let mut changed = bytes.clone();
        changed[at] = value;
        mutations.push(changed);
    }
    let system = sid("S-1-5-18")?;
    let dacl_bytes = &bytes[dacl..];
    let sacl_bytes = &bytes[sacl..sacl + 28];
    mutations.push(super::descriptor(
        0x1014,
        &user,
        &system,
        dacl_bytes,
        Some(sacl_bytes),
    ));
    mutations.push(super::descriptor(
        0x1014,
        &system,
        &user,
        dacl_bytes,
        Some(sacl_bytes),
    ));
    let double_label = super::acl(&[
        bytes[sacl + 8..sacl + 28].to_vec(),
        bytes[sacl + 8..sacl + 28].to_vec(),
    ]);
    mutations.push(super::descriptor(
        0x1014,
        &user,
        &user,
        dacl_bytes,
        Some(&double_label),
    ));
    let extra = super::acl(&[
        super::ace(0, 0, 0x1f01ff, &user),
        super::ace(0, 0, 0x1f01ff, &package),
        super::ace(0, 0, 0x1f01ff, &system),
    ]);
    mutations.push(super::descriptor(
        0x1014,
        &user,
        &user,
        &extra,
        Some(sacl_bytes),
    ));
    for changed in mutations {
        ensure!(
            private::require_policy(&changed, &user, &package).is_err(),
            "private policy accepted mutation"
        );
    }
    ensure!(
        private::require_policy(&bytes, &system, &package).is_err(),
        "private policy accepted foreign user"
    );
    ensure!(
        private::require_policy(&bytes, &user, &sid("S-1-15-2-1")?).is_err(),
        "private policy accepted foreign package"
    );
    for root in ["D:\\", "Z:\\"] {
        ensure!(
            private::folder(root)? == format!("{root}private-creator"),
            "private folder differs"
        );
    }
    for root in ["", "C:\\", "e:\\", "E:\\temp", "E:/", "\\\\server\\share\\"] {
        ensure!(
            private::folder(root).is_err(),
            "private folder accepted foreign root"
        );
    }
    for digits in ["0", "12", "99999999999999999999"] {
        ensure!(
            private::native_root(&format!("\\Device\\HarddiskVolume{digits}\\")),
            "private native root rejected"
        );
    }
    for name in [
        "\\\\?\\E:\\",
        "\\Device\\HarddiskVolume\\",
        "\\Device\\HarddiskVolume1",
        "\\Device\\HarddiskVolume١\\",
        "\\Device\\harddiskvolume1\\",
        "\\Device\\HarddiskVolume1\\temp\\",
    ] {
        ensure!(
            !private::native_root(name),
            "private native root accepted alias"
        );
    }
    let identity = FileIdentity {
        volume: 7,
        high: 11,
        low: 13,
    };
    same_identity(identity, identity)?;
    for actual in [
        FileIdentity {
            volume: 8,
            ..identity
        },
        FileIdentity {
            high: 12,
            ..identity
        },
        FileIdentity {
            low: 14,
            ..identity
        },
    ] {
        ensure!(
            same_identity(identity, actual).is_err(),
            "private identity mutation accepted"
        );
    }
    lifecycle_checks()?;
    removal_checks()
}

fn lifecycle_checks() -> Result<()> {
    let mut state = private::Lifecycle::default();
    ensure!(
        state.use_control(|| Ok(())).is_err() && state.seal(|| Ok(())).is_err(),
        "private lifecycle admitted unprepared state"
    );
    ensure!(
        state.prepare(|| Ok(())).is_ok() && state.prepare(|| Ok(())).is_err(),
        "private prepare was not one-shot"
    );
    ensure!(
        state.seal(|| Ok(())).is_ok() && state.seal(|| Ok(())).is_err(),
        "private seal was not one-shot"
    );
    ensure!(
        state.remove(|| Ok(())).is_err(),
        "private unused fixture removed"
    );
    ensure!(
        state.use_control(|| Ok(())).is_ok()
            && state.use_control(|| Ok(())).is_err()
            && state.remove(|| Ok(())).is_err(),
        "private running fixture admitted transition"
    );
    state.end(true);
    ensure!(
        state.use_control(|| Ok(())).is_ok(),
        "private clean reuse refused"
    );
    state.end(true);
    ensure!(
        state.remove(|| Ok(())).is_ok()
            && state.removed
            && state.use_control(|| Ok(())).is_err()
            && state.remove(|| Ok(())).is_err(),
        "private removed lifecycle differs"
    );
    let mut poisoned = private::Lifecycle::default();
    ensure!(
        poisoned.prepare(|| Ok(())).is_ok()
            && poisoned.seal(|| Ok(())).is_ok()
            && poisoned.use_control(|| Ok(())).is_ok(),
        "private poison preparation differs"
    );
    let releases = Cell::new(0);
    ensure!(
        poisoned
            .release(|| {
                releases.set(releases.get() + 1);
                Ok(())
            })
            .is_err(),
        "private running release accepted"
    );
    poisoned.end(false);
    ensure!(
        poisoned
            .release(|| {
                releases.set(releases.get() + 1);
                Ok(())
            })
            .is_err()
            && releases.get() == 0
            && poisoned.use_control(|| Ok(())).is_err()
            && poisoned.remove(|| Ok(())).is_err(),
        "private uncertain release accepted"
    );
    let mut clean = private::Lifecycle::default();
    ensure!(
        clean.prepare(|| Ok(())).is_ok()
            && clean
                .release(|| {
                    releases.set(releases.get() + 1);
                    Ok(())
                })
                .is_ok()
            && releases.get() == 1,
        "private clean release differs"
    );
    let mut failed = private::Lifecycle::default();
    ensure!(
        failed.prepare(|| Err(failure("fixed prepare"))).is_err()
            && failed.prepare(|| Ok(())).is_err()
            && failed.seal(|| Ok(())).is_err(),
        "private failed prepare was retried"
    );
    let mut failed_use = private::Lifecycle::default();
    ensure!(
        failed_use.prepare(|| Ok(())).is_ok()
            && failed_use.seal(|| Ok(())).is_ok()
            && failed_use
                .use_control(|| Err(failure("fixed use")))
                .is_err(),
        "private failed use differs"
    );
    failed_use.end(true);
    ensure!(
        failed_use.remove(|| Ok(())).is_err(),
        "private failed use permitted removal"
    );
    Ok(())
}
fn removal_checks() -> Result<()> {
    for fault in 0..8 {
        let events = RefCell::new(Vec::new());
        let primary = failure("fixed removal");
        let cleanup = failure("fixed close");
        let step = |name, selected| -> OperationResult<()> {
            events.borrow_mut().push(name);
            if fault == selected {
                Err(primary.clone())
            } else {
                Ok(())
            }
        };
        let caught = private::remove_bound(private::Removal {
            check: &mut || step("check", 1),
            close_pin: &mut || step("pin-close", 2),
            open: &mut || {
                step("open", 3)?;
                Ok(17)
            },
            bind: &mut |handle| {
                ensure_handle(handle)?;
                step("bind", 4)
            },
            dispose: &mut |handle| {
                ensure_handle(handle)?;
                step("dispose", 5)
            },
            close: &mut |handle| {
                ensure_handle(handle)?;
                events.borrow_mut().push("close");
                if fault == 6 || fault == 4 {
                    Err(cleanup.clone())
                } else {
                    Ok(())
                }
            },
            absent: &mut || step("absent", 7),
        })
        .err();
        let events = events.into_inner();
        ensure!(
            caught.is_none() == (fault == 0)
                && events.contains(&"open") == (fault != 1 && fault != 2)
                && events.contains(&"dispose") == (fault == 0 || fault >= 5)
                && events.contains(&"close") == (fault == 0 || fault >= 4)
                && events.contains(&"absent") == (fault == 0 || fault == 7),
            "private bound removal ordering differs fault={fault}"
        );
        if fault == 4 {
            let caught = caught.unwrap();
            let group = caught.downcast_ref::<super::Failures>().unwrap();
            ensure!(
                group.errors.len() == 2
                    && Arc::ptr_eq(&group.errors[0], &primary)
                    && Arc::ptr_eq(&group.errors[1], &cleanup),
                "private removal lost independent error identity"
            );
        }
    }
    Ok(())
}
fn ensure_handle(handle: usize) -> OperationResult<()> {
    super::need(handle == 17)
}
