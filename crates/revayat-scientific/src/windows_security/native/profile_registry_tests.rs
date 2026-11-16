//! Original profile-registry contracts, structural seams plus a hosted owned-key support case.
use super::*;
use crate::windows_security::policy::{Acl, Descriptor as Relative, REGISTRY_READ};
#[test]
fn exact_six_rules_preserve_legacy_denial_and_corrected_read_only_masks() {
    let user = "S-1-5-21-1-2-3-500";
    let package = "S-1-15-2-1-2-3-4-5-6-7";
    for read_only in [false, true] {
        let text = policy::sddl(user, package, read_only).unwrap();
        assert_eq!(
            text,
            format!(
                "D:P(D;CI;0x000C0000;;;S-1-3-4)(D;CI;0x{:08X};;;{package})(A;CI;0x000F003F;;;S-1-5-18)(A;CI;0x000F003F;;;S-1-5-32-544)(A;CI;0x000F003F;;;{user})(A;CI;0x{:08X};;;{package})",
                if read_only { 0xd0006 } else { 0xe0006 },
                if read_only { REGISTRY_READ } else { 0x19 }
            )
        );
        let mut descriptor = Descriptor::new(&text).unwrap();
        let bytes = policy::bytes(&descriptor).unwrap();
        crate::windows_security::policy::validate_registry_seal(&bytes).unwrap();
        let parsed = Relative::parse(&bytes).unwrap();
        let entries = Acl::parse(parsed.dacl.unwrap()).unwrap();
        assert_eq!(entries.aces.len(), 6);
        assert_eq!(
            entries
                .aces
                .iter()
                .map(|ace| (ace.kind, ace.flags))
                .collect::<Vec<_>>(),
            [(1, 2), (1, 2), (0, 2), (0, 2), (0, 2), (0, 2)]
        );
        assert_eq!(entries.aces[0].mask().unwrap(), 0xc0000);
        assert_eq!(
            entries.aces[1].mask().unwrap(),
            if read_only { 0xd0006 } else { 0xe0006 }
        );
        assert_eq!(
            entries.aces[5].mask().unwrap(),
            if read_only { 0x20019 } else { 0x19 }
        );
        descriptor.close().unwrap();
    }
    let base = Descriptor::new(&policy::sddl(user, package, true).unwrap()).unwrap();
    let mut base = base;
    let bytes = policy::bytes(&base).unwrap();
    base.close().unwrap();
    let offset = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let length = u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap()) as usize;
    let mut padded = bytes.clone();
    padded.extend([0; 4]);
    padded[offset + 2..offset + 4].copy_from_slice(&((length + 4) as u16).to_le_bytes());
    assert!(policy::matches_access(&bytes, &padded).unwrap());
    let mut bookkeeping = bytes.clone();
    bookkeeping[3] ^= 4;
    assert!(policy::matches_access(&bytes, &bookkeeping).unwrap());
    for flag in [4u16, 0x100, 0x800, 0x1000] {
        let mut changed = bytes.clone();
        let control = u16::from_le_bytes(changed[2..4].try_into().unwrap()) ^ flag;
        changed[2..4].copy_from_slice(&control.to_le_bytes());
        assert!(!policy::matches_access(&bytes, &changed).unwrap_or(false));
    }
    let first = offset + 8;
    let first_length = u16::from_le_bytes(bytes[first + 2..first + 4].try_into().unwrap()) as usize;
    for (at, change) in [(first + 1, 1u8), (first + 4, 1), (first + 8 + 8, 1)] {
        let mut changed = bytes.clone();
        changed[at] ^= change;
        assert!(!policy::matches_access(&bytes, &changed).unwrap_or(false));
    }
    let mut changed = bytes.clone();
    changed[first..first + first_length].fill(0);
    assert!(!policy::matches_access(&bytes, &changed).unwrap_or(false));
    for user in ["S-1-5-18", "S-1-5-32-544", package, "private-sentinel"] {
        assert!(policy::sddl(user, package, true).is_err());
    }
}
#[test]
fn bounded_names_and_tree_cannot_escape_or_exceed_original_limits() {
    let name = r"\REGISTRY\USER\S-1-5-21-1\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\owned";
    let encoded = name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let mut data = (encoded.len() as u32).to_le_bytes().to_vec();
    data.extend(&encoded);
    assert_eq!(decode_name(&data, data.len()).unwrap(), name);
    for returned in [0, 3, 4097] {
        assert!(decode_name(&data, returned).is_err());
    }
    for length in [0u32, 1, 4096] {
        let mut bad = data.clone();
        bad[..4].copy_from_slice(&length.to_le_bytes());
        assert!(decode_name(&bad, bad.len()).is_err());
    }
    let mut invalid = data.clone();
    invalid[4..6].fill(0);
    assert!(decode_name(&invalid, invalid.len()).is_err());
    for (count, depth, okay) in [
        (0, 0, true),
        (255, 32, true),
        (256, 32, false),
        (1, 33, false),
    ] {
        assert_eq!(tree_budget(count, depth).is_ok(), okay);
    }
    for value in ["", r"bad\child", ".", "..", "bad\0child"] {
        assert!(child_name(&value.encode_utf16().collect::<Vec<_>>()).is_err());
    }
}
#[test]
fn profile_and_fresh_open_require_explicit_denial_or_exact_read_only_authority() {
    for api in [false, true] {
        let live = 1usize as Handle;
        validate_open(api, 0, live, true, 0x20019, 0x20019, true).unwrap();
        validate_open(
            api,
            if api { 0x80070005 } else { 5 },
            null_mut(),
            false,
            0,
            0x20019,
            false,
        )
        .unwrap();
        // Neither API may substitute invalid NON-NULL output for an actual denied open.
        for raw in [
            usize::MAX,
            0x80000000,
            0x80000001,
            0x800000ff,
            usize::MAX - 1,
            1,
        ] {
            assert!(
                validate_open(
                    api,
                    if api { 0x80070005 } else { 5 },
                    raw as Handle,
                    false,
                    0,
                    0x20019,
                    false
                )
                .is_err(),
                "api={api} raw_is_null={}",
                raw == 0
            );
            assert!(
                validate_open(api, 0, raw as Handle, true, 0x20019, 0x20019, true).is_ok()
                    == valid(raw as Handle)
            );
        }
        for (status, valid, same, grant, allowed) in [
            (0, false, true, 0x20019, true),
            (0, true, false, 0x20019, true),
            (0, true, true, 0xf003f, true),
            (0, true, true, 0x19, true),
            (0, true, true, 0x20019, false),
            (1, false, false, 0, false),
            (if api { 0x80070005 } else { 5 }, true, true, 0, false),
        ] {
            assert!(
                validate_open(
                    api,
                    status,
                    if valid { live } else { null_mut() },
                    same,
                    grant,
                    0x20019,
                    allowed
                )
                .is_err()
            );
        }
    }
    for mask in [2, 4, 0x10000, 0x40000, 0x80000] {
        assert_eq!(crate::windows_security::policy::REGISTRY_DENY & mask, mask);
    }
}
#[test]
fn actual_profile_owner_is_installed_before_observers_and_closed_before_profile_deletion() {
    let run = include_str!("authority_run.rs");
    let prepare = run
        .find("profile_registry.prepare(process.0, &sid,")
        .unwrap();
    assert!(run.find("Lifecycle::Qualified").unwrap() < prepare);
    assert!(
        prepare
            < run
                .find("let metadata = default_metadata(process.0)?;")
                .unwrap()
    );
    assert!(run.find("profile_registry.close()").unwrap() < run.rfind("profile.close()").unwrap());
    assert!(run.contains("profile.retain()"));
    assert!(run.contains("observer.token_metadata(record)"));
    let source = include_str!("profile_registry.rs");
    assert!(source.contains("WINDOWS_PROFILE_REGISTRY sealed=true keys="));
    assert!(source.contains("WINDOWS_PROFILE_REGISTRY_READ_PAIR old_denied=true new_read=true individual_mutations_denied=true keys="));
    assert!(run.contains("!profile_keys_closed || !process_reaped || !job_reaped"));
    let owner = include_str!("profile_registry.rs");
    assert!(owner.contains("GetAppContainerRegistryLocation(0x60019"));
    assert!(
        owner.contains("self.controls(process, package, false)?;")
            && owner.contains("self.controls(process, package, true)?;")
    );
    assert!(
        !owner.contains("RegCreateKey")
            && !owner.contains("HKCU")
            && !owner.contains("NtDeleteKey")
    );
}
#[test]
fn close_failures_stay_uncertain_and_all_owned_keys_are_attempted_in_reverse_order() {
    let calls = std::cell::RefCell::new(Vec::new());
    let mut owner = ProfileRegistry::default();
    for value in 1..=3 {
        owner.entries.push(Entry {
            key: Key(value as Handle),
            name: format!("fixed-{value}"),
        });
    }
    let error = owner
        .close_with(|handle| {
            calls.borrow_mut().push(handle as usize);
            if handle as usize == 2 {
                anyhow::bail!("fixed close");
            }
            Ok(())
        })
        .unwrap_err();
    assert_eq!(*calls.borrow(), [3, 2, 1]);
    assert!(owner.entries.is_empty() && owner.uncertain.get());
    assert!(error.downcast_ref::<Failures>().is_some());
    assert!(
        owner
            .close_with(|_| panic!("invalidated handle retried"))
            .is_err()
    );
}
#[test]
fn profile_registry_seal_keeps_every_original_rejected_descriptor_shape() {
    let package = "S-1-15-2-1-2-3-4-5-6-7";
    let mut native =
        Descriptor::new(&policy::sddl("S-1-5-21-1-2-3-500", package, true).unwrap()).unwrap();
    let bytes = policy::bytes(&native).unwrap();
    native.close().unwrap();
    let dacl = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    for mutation in 0..10 {
        let mut bad = bytes.clone();
        match mutation {
            0 => bad[3] &= !0x10,
            1 => bad[2] &= !4,
            2 => bad[16..20].fill(0),
            3 => bad[dacl + 4..dacl + 6].fill(0),
            4 | 5 => {
                let at = bad.len() as u32;
                bad[if mutation == 4 { 4..8 } else { 8..12 }].copy_from_slice(&at.to_le_bytes());
                bad.extend([1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
            }
            6 => {
                bad[2] |= 0x10;
                bad[12..16].copy_from_slice(&(dacl as u32).to_le_bytes());
            }
            7 => bad[dacl + 9] |= 16,
            8 => bad[dacl + 9] |= 8,
            _ => bad[dacl + 8] = 9,
        }
        assert!(
            crate::windows_security::policy::validate_registry_seal(&bad).is_err(),
            "mutation={mutation}"
        );
    }
}
#[test]
fn actual_owned_registry_key_supports_exact_seal_and_identity_preservation() {
    // Support only: the existing authority integration, not this synthetic fixture, owns profile proof.
    let package = "S-1-15-2-1-2-3-4-5-6-7";
    let mut fixture =
        crate::windows_security::native::fixture::RegistryFixture::new(package).unwrap();
    let user = crate::windows_security::sxs::current_user_sid().unwrap();
    let key = fixture.retained_root();
    let result = policy::apply(key, &user, package, true);
    let cleanup = fixture.close();
    result.unwrap();
    cleanup.unwrap();
}
