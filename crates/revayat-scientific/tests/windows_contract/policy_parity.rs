//! Binary-policy regressions are structural evidence, never effective native access proof.
use revayat_scientific::windows_security::policy::*;

fn sid(authority: u8, parts: &[u32]) -> Vec<u8> {
    let mut bytes = vec![1, parts.len() as u8, 0, 0, 0, 0, 0, authority];
    for part in parts {
        bytes.extend(part.to_le_bytes());
    }
    bytes
}
fn ace(kind: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind, flags];
    bytes.extend(((8 + sid.len()) as u16).to_le_bytes());
    bytes.extend(mask.to_le_bytes());
    bytes.extend(sid);
    bytes
}
fn acl(entries: &[Vec<u8>], padding: usize) -> Vec<u8> {
    let size = 8 + entries.iter().map(Vec::len).sum::<usize>() + padding;
    let mut bytes = vec![2, 0];
    bytes.extend((size as u16).to_le_bytes());
    bytes.extend((entries.len() as u16).to_le_bytes());
    bytes.extend([0, 0]);
    for entry in entries {
        bytes.extend(entry);
    }
    bytes.resize(size, 0);
    bytes
}
fn descriptor(dacl: &[u8]) -> Vec<u8> {
    let system = sid(5, &[18]);
    let label = acl(&[ace(17, 0, 1, &sid(16, &[4096]))], 0);
    let mut bytes = vec![1, 0, 0x14, 0x90];
    for offset in [20u32, 32, 44, (44 + label.len()) as u32] {
        bytes.extend(offset.to_le_bytes());
    }
    bytes.extend(&system);
    bytes.extend(&system);
    bytes.extend(label);
    bytes.extend(dacl);
    bytes
}
fn package() -> Vec<u8> {
    sid(15, &[2, 1, 2, 3, 4, 5, 6, 7])
}

#[test]
fn profile_comparison_ignores_only_observed_dacl_bookkeeping() {
    profile_validation::check_seal_comparison().unwrap();
    let owner = sid(3, &[4]);
    let dacl = acl(
        &[
            ace(1, 0, 0xc0000, &owner),
            ace(0, 0, 0x120089, &sid(1, &[0])),
        ],
        0,
    );
    let before = descriptor(&dacl);
    let mut actual = before.clone();
    actual[3] ^= 4; // SE_DACL_AUTO_INHERITED only.
    assert!(access_matches(&before, &actual).unwrap());
    for control in [0x1000u16, 4, 0x100, 0x800] {
        let mut changed = before.clone();
        let flags = u16::from_le_bytes(changed[2..4].try_into().unwrap()) ^ control;
        changed[2..4].copy_from_slice(&flags.to_le_bytes());
        assert!(!access_matches(&before, &changed).unwrap_or(false));
    }
    for changed in [
        acl(
            &[
                ace(0, 0, 0x120089, &sid(1, &[0])),
                ace(1, 0, 0xc0000, &owner),
            ],
            0,
        ),
        acl(
            &[
                ace(1, 1, 0xc0000, &owner),
                ace(0, 0, 0x120089, &sid(1, &[0])),
            ],
            0,
        ),
        acl(
            &[
                ace(1, 0, 0x40000, &owner),
                ace(0, 0, 0x120089, &sid(1, &[0])),
            ],
            0,
        ),
    ] {
        assert!(!access_matches(&before, &descriptor(&changed)).unwrap());
    }
}

#[test]
fn default_acl_summary_distinguishes_null_empty_padding_and_conditional_aces() {
    token_validation::check_default_metadata_validation().unwrap();
    let user = sid(5, &[21, 1, 2, 3, 500]);
    let package = package();
    let entries = [
        ace(1, 0, 2, &user),
        ace(0, 0, 8, &user),
        ace(0, 0, 0x20019, &package),
        ace(0, 10, 0x10000000, &user),
    ];
    let summary = default_acl_summary(Some(&acl(&entries, 0)), &user, &package).unwrap();
    assert_eq!(
        (summary.user_allow, summary.user_deny, summary.package_allow),
        (8, 2, 0x20019)
    );
    assert_eq!(summary.inherit_only, 1);
    assert!(summary.canonical && summary.recognized_all && !summary.is_null);
    let record = summary.record(acl(&entries, 0).len());
    assert_eq!(
        record,
        format!(
            "WINDOWS_DEFAULT_DACL status=summary default_dacl_null=False acl_bytes={} ace_count=4 canonical_order=True recognized_all=True unknown_ace_count=0 other_ace_count=0 inherit_only_count=1 user_allow_mask=0x00000008 user_deny_mask=0x00000002 package_allow_mask=0x00020019 package_deny_mask=0x00000000 effective_access_proved=False",
            acl(&entries, 0).len()
        )
    );
    assert!(!record.contains("S-1-") && !record.contains("effective_access_proved=True"));
    let null = default_acl_summary(None, &user, &package).unwrap();
    assert!(null.is_null);
    assert_eq!(
        null.record(0),
        "WINDOWS_DEFAULT_DACL status=summary default_dacl_null=True effective_access_proved=False"
    );
    assert_eq!(
        default_acl_summary(Some(&acl(&[], 0)), &user, &package)
            .unwrap()
            .record(8),
        "WINDOWS_DEFAULT_DACL status=summary default_dacl_null=False acl_bytes=8 ace_count=0 canonical_order=True recognized_all=True unknown_ace_count=0 other_ace_count=0 inherit_only_count=0 user_allow_mask=0x00000000 user_deny_mask=0x00000000 package_allow_mask=0x00000000 package_deny_mask=0x00000000 effective_access_proved=False"
    );
    assert_eq!(
        default_acl_summary(Some(&acl(&[], 0)), &user, &package)
            .unwrap()
            .ace_count,
        0
    );
    assert_eq!(
        default_acl_summary(Some(&acl(&entries, 4)), &user, &package)
            .unwrap()
            .user_allow,
        8
    );
    let reversed = acl(&[entries[1].clone(), entries[0].clone()], 0);
    assert!(
        !default_acl_summary(Some(&reversed), &user, &package)
            .unwrap()
            .canonical
    );
    let callback = acl(&[ace(9, 0, 8, &user)], 0);
    let summary = default_acl_summary(Some(&callback), &user, &package).unwrap();
    assert!(!summary.recognized_all && !summary.canonical);
    assert_eq!(summary.unknown, 1);
    assert!(
        summary
            .record(callback.len())
            .contains("unknown_ace_count=1")
    );
    assert_eq!(summary.user_allow, 0);
    let valid = acl(&entries, 0);
    for (offset, value) in [(0, 1), (1, 1), (2, 0), (4, 65), (10, 3), (16, 2), (17, 16)] {
        let mut bad = valid.clone();
        bad[offset] = value;
        assert!(
            default_acl_summary(Some(&bad), &user, &package).is_err(),
            "offset={offset}"
        );
    }
    assert!(within(100, 16, 100, 16, 4));
    assert!(!within(100, 16, 101, 4, 4));
    assert!(!within(100, 16, 108, 9, 4));
    assert!(!within(100, 16, 99, 1, 1));
    assert!(!within(u64::MAX - 8, 8, 1, 1, 4));
    let mut oversized = valid.clone();
    oversized[10..12].copy_from_slice(&65532u16.to_le_bytes());
    assert!(default_acl_summary(Some(&oversized), &user, &package).is_err());
}

#[test]
fn token_metadata_returned_pointers_are_bounded_before_any_acl_or_sid_decode() {
    token_validation::check_startup_token_validation().unwrap();
    let start = 0x1000u64;
    let dacl = acl(&[ace(0, 0, 8, &sid(5, &[21, 1, 2, 3, 500]))], 4);
    let mut buffer = vec![0; 8];
    assert!(token_default_acl(&buffer, start).unwrap().is_none());
    buffer[..8].copy_from_slice(&(start + 8).to_le_bytes());
    buffer.extend(&dacl);
    assert_eq!(
        token_default_acl(&buffer, start).unwrap(),
        Some(dacl.as_slice())
    );
    for pointer in [
        start - 4,
        start + 9,
        start + buffer.len() as u64 - 4,
        u64::MAX,
    ] {
        let mut changed = buffer.clone();
        changed[..8].copy_from_slice(&pointer.to_le_bytes());
        assert!(token_default_acl(&changed, start).is_err());
    }
    for length in [0u16, 7, 9, 65532] {
        let mut changed = buffer.clone();
        changed[10..12].copy_from_slice(&length.to_le_bytes());
        assert!(token_default_acl(&changed, start).is_err());
    }
    assert!(token_default_acl(&buffer[..7], start).is_err());
    assert!(token_default_acl(&vec![0; 65537], start).is_err());
    assert!(token_default_acl(&buffer[..buffer.len() - 1], start).is_err());
    let user = sid(5, &[21, 1, 2, 3, 500]);
    let mut identity = (start + 16).to_le_bytes().to_vec();
    identity.resize(16, 0);
    identity.extend(&user);
    assert_eq!(token_metadata_sid(&identity, start, true).unwrap(), user);
    assert_eq!(token_metadata_sid(&identity, start, false).unwrap(), user);
    for pointer in [0, start - 4, start + 17, start + identity.len() as u64 - 4] {
        let mut changed = identity.clone();
        changed[..8].copy_from_slice(&pointer.to_le_bytes());
        assert!(token_metadata_sid(&changed, start, true).is_err());
    }
    for (offset, byte) in [(16, 2), (17, 16)] {
        let mut changed = identity.clone();
        changed[offset] = byte;
        assert!(token_metadata_sid(&changed, start, true).is_err());
    }
    assert!(token_metadata_sid(&identity[..identity.len() - 1], start, true).is_err());
    assert!(token_metadata_sid(&[0; 15], start, true).is_err());
    assert!(token_metadata_sid(&[0; 7], start, false).is_err());
    assert!(token_metadata_sid(&vec![0; 65537], start, true).is_err());
    let mut bad_acl = buffer.clone();
    bad_acl[8] = 1;
    assert_eq!(token_default_acl(&bad_acl, start).unwrap_err(), "ace-spans");
    let mut wrapped = vec![0; 16];
    wrapped[..8].copy_from_slice(&1u64.to_le_bytes());
    assert!(token_default_acl(&wrapped, u64::MAX - 8).is_err());
}

#[test]
fn default_metadata_counts_other_unknown_inherited_and_full_masks_without_access_claims() {
    let user = sid(5, &[21, 1, 2, 3, 500]);
    let package = package();
    let other = sid(5, &[32, 544]);
    let bytes = acl(
        &[
            ace(1, 0, u32::MAX, &user),
            ace(0, 0, u32::MAX, &user),
            ace(1, 0, 0x80000000, &package),
            ace(0, 0, 0x20019, &package),
            ace(0, 0, 8, &other),
            ace(0, 16, 16, &user),
            ace(1, 16, 4, &user),
            ace(0, 8, u32::MAX, &package),
            ace(10, 0, 8, &user),
        ],
        4,
    );
    let summary = default_acl_summary(Some(&bytes), &user, &package).unwrap();
    assert_eq!(
        (summary.user_allow, summary.user_deny),
        (u32::MAX, u32::MAX)
    );
    assert_eq!(
        (summary.package_allow, summary.package_deny),
        (0x20019, 0x80000000)
    );
    assert_eq!(
        (summary.other, summary.inherit_only, summary.unknown),
        (1, 1, 1)
    );
    assert!(!summary.canonical && !summary.recognized_all);
    let record = summary.record(bytes.len());
    assert!(
        record.contains("user_allow_mask=0xFFFFFFFF") && record.contains("unknown_ace_count=1")
    );
    assert!(record.ends_with("effective_access_proved=False") && !record.contains("S-1-"));
    let inherited = acl(
        &[
            ace(0, 0, 8, &user),
            ace(0, 16, 16, &user),
            ace(1, 16, 4, &user),
        ],
        0,
    );
    assert!(
        default_acl_summary(Some(&inherited), &user, &package)
            .unwrap()
            .canonical
    );
}

#[test]
fn diagnostic_common_aces_keep_opaque_tails_without_relaxing_strict_grant_parsers() {
    let user = sid(5, &[21, 1, 2, 3, 500]);
    let package = package();
    for kind in [0, 1, 2, 3, 9, 10, 13, 14] {
        let mut entry = ace(kind, 0, 0x20019, &user);
        entry.extend([0xde, 0xad, 0xbe, 0xef]);
        let length = entry.len() as u16;
        entry[2..4].copy_from_slice(&length.to_le_bytes());
        let bytes = acl(&[entry], 4);
        let summary = default_acl_summary(Some(&bytes), &user, &package).unwrap();
        if kind <= 1 {
            assert_eq!(
                (summary.user_allow, summary.user_deny),
                if kind == 0 {
                    (0x20019, 0)
                } else {
                    (0, 0x20019)
                }
            );
            assert!(summary.canonical && summary.recognized_all);
            assert!(Acl::parse(&bytes).is_err());
            assert!(child_event_policy(&bytes).is_err());
            assert!(descriptor_trial(&descriptor(&bytes), &package, REGISTRY_READ).is_err());
        } else {
            assert_eq!(
                (summary.unknown, summary.user_allow, summary.user_deny),
                (1, 0, 0)
            );
            assert!(!summary.canonical && !summary.recognized_all);
        }
        let start = 0x1000u64;
        let mut returned = (start + 8).to_le_bytes().to_vec();
        returned.extend(&bytes);
        assert_eq!(
            token_default_acl(&returned, start).unwrap(),
            Some(bytes.as_slice())
        );
        assert!(
            summary
                .record(bytes.len())
                .ends_with("effective_access_proved=False")
        );
    }
}
#[test]
fn diagnostic_other_ace_kinds_require_their_actual_layout_and_never_supply_grants() {
    let user = sid(5, &[21, 1, 2, 3, 500]);
    let package = package();
    let object = |kind: u8, flags: u32| {
        let mut bytes = vec![kind, 0, 0, 0];
        bytes.extend(0x1f0003u32.to_le_bytes());
        bytes.extend(flags.to_le_bytes());
        for bit in [1, 2] {
            if flags & bit != 0 {
                bytes.extend([0x42; 16]);
            }
        }
        bytes.extend(&user);
        bytes.extend([1, 2, 3, 4]);
        let length = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&length.to_le_bytes());
        bytes
    };
    let mut variants = Vec::new();
    for kind in [5, 6, 7, 8, 11, 12, 15, 16] {
        for flags in [0, 1, 2, 3, 0x80000003] {
            variants.push(object(kind, flags));
        }
    }
    let mut compound = vec![4, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0];
    compound.extend(&user);
    let length = compound.len() as u16;
    compound[2..4].copy_from_slice(&length.to_le_bytes());
    variants.push(compound.clone());
    variants.extend([
        vec![17, 0, 4, 0],
        vec![255, 0, 8, 0, 0xde, 0xad, 0xbe, 0xef],
    ]);
    for entry in variants {
        let bytes = acl(std::slice::from_ref(&entry), 0);
        let summary = default_acl_summary(Some(&bytes), &user, &package).unwrap();
        assert_eq!(
            (
                summary.unknown,
                summary.other,
                summary.user_allow,
                summary.package_allow
            ),
            (1, 0, 0, 0)
        );
        assert!(!summary.canonical && !summary.recognized_all);
        if entry[0] <= 16 {
            let mut short = entry[..entry.len() - 4].to_vec();
            if entry[0] != 4 {
                short.truncate(12);
            }
            let length = short.len() as u16;
            short[2..4].copy_from_slice(&length.to_le_bytes());
            assert!(default_acl_summary(Some(&acl(&[short], 0)), &user, &package).is_err());
        }
    }
    for at in [12, 13] {
        let mut invalid = compound.clone();
        invalid[at] = if at == 12 { 2 } else { 16 };
        assert!(default_acl_summary(Some(&acl(&[invalid], 0)), &user, &package).is_err());
    }
    compound.extend([0; 4]);
    let length = compound.len() as u16;
    compound[2..4].copy_from_slice(&length.to_le_bytes());
    assert!(default_acl_summary(Some(&acl(&[compound], 0)), &user, &package).is_err());
    for entry in [
        vec![2, 0, 4, 0],
        vec![9, 0, 8, 0, 0, 0, 0, 0],
        vec![5, 0, 12, 0, 0, 0, 0, 0, 3, 0, 0, 0],
    ] {
        let bytes = acl(&[entry], 0);
        assert!(default_acl_summary(Some(&bytes), &user, &package).is_err());
        // Original NativeSpans/ValidSpans checks only plain allow/deny SIDs.
        // RawAcl rejects other malformed layouts later as managed-structure, not ace-spans.
        let mut returned = 0x1008u64.to_le_bytes().to_vec();
        returned.extend(&bytes);
        assert_eq!(
            token_default_acl(&returned, 0x1000).unwrap(),
            Some(bytes.as_slice())
        );
    }
    for kind in [0, 1, 2, 3, 9, 10, 13, 14] {
        for (offset, value) in [(8, 2), (9, 16)] {
            let mut malformed = ace(kind, 0, 8, &user);
            malformed[offset] = value;
            assert!(default_acl_summary(Some(&acl(&[malformed], 0)), &user, &package).is_err());
        }
    }
    let custom = vec![17, 0, 4, 0];
    let sixty_four = acl(&vec![custom.clone(); 64], 4);
    let summary = default_acl_summary(Some(&sixty_four), &user, &package).unwrap();
    assert_eq!((summary.ace_count, summary.unknown), (64, 64));
    assert!(default_acl_summary(Some(&acl(&vec![custom; 65], 0)), &user, &package).is_err());
    let mut ds = acl(&[object(5, 3)], 0);
    ds[0] = 4;
    assert_eq!(
        default_acl_summary(Some(&ds), &user, &package)
            .unwrap()
            .unknown,
        1
    );
    for (kind, maximum) in [(0, 65456usize), (5, 65420)] {
        let mut entry = if kind == 0 {
            ace(0, 0, 8, &sid(5, &[18]))
        } else {
            let mut bytes = vec![5, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0];
            bytes.extend(sid(5, &[18]));
            bytes
        };
        let header = entry.len();
        entry.resize(header + maximum, 0);
        let length = entry.len() as u16;
        entry[2..4].copy_from_slice(&length.to_le_bytes());
        default_acl_summary(Some(&acl(&[entry.clone()], 0)), &user, &package).unwrap();
        entry.extend([0; 4]);
        let length = entry.len() as u16;
        entry[2..4].copy_from_slice(&length.to_le_bytes());
        assert!(default_acl_summary(Some(&acl(&[entry], 0)), &user, &package).is_err());
    }
}

#[test]
fn child_acl_insertion_preserves_aces_and_event_mapping_matches_original_vectors() {
    default_control::check_child_validation().unwrap();
    default_control::check_control_validation().unwrap();
    default_control::comparison::check_validation().unwrap();
    let baseline = acl(&[], 0);
    let mut records = Vec::new();
    default_control::comparison::execute(
        |condition| {
            let changed = condition == default_control::comparison::Condition::UserAllow;
            Ok(default_control::comparison::Observation {
                condition,
                baseline: Some(baseline.clone()),
                opened: changed,
                exit: if changed { 0 } else { 0xc0150002 },
            })
        },
        || {
            Ok(default_control::comparison::Lease {
                restore: Box::new(|| Ok(())),
                defer: Box::new(|| anyhow::bail!("clean comparison unexpectedly deferred")),
            })
        },
        |record| {
            records.push(record.to_owned());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(records.len(), 4);
    assert_eq!(
        records.last().unwrap(),
        "WINDOWS_DEFAULT_DACL_DIFFERENTIAL startup_changed=True event_access_changed=True baseline_restored=True key_restored=True target_admitted=False production_grant=False cause_claimed=False"
    );
    let user = sid(5, &[21, 1, 2, 3, 500]);
    let package = package();
    for (input, expected) in [
        (0x80000000, 0x20001),
        (0x20000000, 0x120000),
        (0xa0000000, 0x120001),
        (0xa0000002, 0x120003),
        (0xb0000000, 0x1f0003),
    ] {
        let deny = ace(1, 0, input, &package);
        let allow = ace(0, 0, input, &package);
        let original = acl(&[deny.clone(), allow.clone()], 0);
        let inserted = child_with_user(&original, &user).unwrap();
        let parsed = Acl::parse(&inserted).unwrap();
        assert_eq!(parsed.aces[0].bytes, deny);
        assert_eq!(parsed.aces[2].bytes, allow);
        assert_eq!(parsed.aces[1].mask().unwrap(), 0x10000000);
        assert_eq!(parsed.aces[1].sid().unwrap(), user);
        assert!(child_with_user(&inserted, &user).is_err());
        let event = child_event_policy(&original).unwrap();
        assert!(
            Acl::parse(&event)
                .unwrap()
                .aces
                .iter()
                .all(|item| item.mask().unwrap() == expected)
        );
        assert!(child_acl_equal(&original, &acl(&[deny, allow], 4)).unwrap());
        assert!(!child_acl_equal(&original, &inserted).unwrap());
    }
    for invalid in [
        ace(0, 0, 0x40000000, &user),
        ace(0, 16, 8, &user),
        ace(9, 0, 8, &user),
    ] {
        assert!(child_event_policy(&acl(&[invalid], 0)).is_err());
    }
}

#[test]
fn registry_seal_requires_six_canonical_access_only_aces() {
    profile_validation::check_registry_masks().unwrap();
    let entries = (0..6)
        .map(|id| ace(0, 2, 0x20019, &sid(5, &[id])))
        .collect::<Vec<_>>();
    let dacl = acl(&entries, 0);
    let mut sd = vec![1, 0, 4, 0x90];
    sd.extend([0; 12]);
    sd.extend(20u32.to_le_bytes());
    sd.extend(&dacl);
    validate_registry_seal(&sd).unwrap();
    for (offset, value) in [(3, 0x80), (2, 0), (20 + 8 + 1, 16), (20 + 8, 9)] {
        let mut bad = sd.clone();
        bad[offset] = value;
        assert!(validate_registry_seal(&bad).is_err());
    }
    let with_identity = descriptor(&dacl);
    assert!(validate_registry_seal(&with_identity).is_err());
    assert_eq!(REGISTRY_READ, 0x20019);
    assert_eq!(REGISTRY_DENY & REGISTRY_READ, 0);
    for denied in [2, 4, 0x10000, 0x40000, 0x80000] {
        assert_eq!(REGISTRY_DENY & denied, denied);
    }
}

#[test]
fn registry_dacl_persistence_preserves_owner_group_integrity_and_unrelated_control() {
    let before = descriptor(&acl(&[ace(0, 0, 0x20019, &sid(5, &[18]))], 0));
    require_registry_preserved(&before, &before).unwrap();
    // A DACL-only write may change these flags and access bytes, not identity/MIC.
    for flag in [4u16, 8, 0x100, 0x400, 0x1000] {
        let mut changed = before.clone();
        let control = u16::from_le_bytes(changed[2..4].try_into().unwrap()) ^ flag;
        changed[2..4].copy_from_slice(&control.to_le_bytes());
        require_registry_preserved(&before, &changed).unwrap();
    }
    let changed_dacl = descriptor(&acl(&[ace(0, 0, 0xf003f, &sid(5, &[32, 544]))], 0));
    require_registry_preserved(&before, &changed_dacl).unwrap();
    for offset in [28, 40, 44 + 8 + 4, 44 + 8 + 8 + 8] {
        let mut changed = before.clone();
        changed[offset] ^= 1;
        assert!(
            require_registry_preserved(&before, &changed).is_err(),
            "offset={offset}"
        );
    }
    for flag in [1u16, 2, 0x10, 0x20, 0x200, 0x800, 0x2000, 0x4000] {
        let mut changed = before.clone();
        let control = u16::from_le_bytes(changed[2..4].try_into().unwrap()) ^ flag;
        changed[2..4].copy_from_slice(&control.to_le_bytes());
        assert!(
            require_registry_preserved(&before, &changed).is_err(),
            "flag={flag:x}"
        );
    }
    let mut missing = before.clone();
    missing[12..16].fill(0);
    assert!(require_registry_preserved(&before, &missing).is_err());
    missing = before.clone();
    missing[4..8].fill(0);
    assert!(require_registry_preserved(&before, &missing).is_err());
}

#[test]
fn exact_trial_receipt_binding_and_foreign_restore_are_fail_closed() {
    registry_lease::check_validation().unwrap();
    let before = descriptor(&acl(&[ace(0, 0, 0x20019, &sid(5, &[18]))], 0));
    let package = package();
    let trial = descriptor_trial(&before, &package, REGISTRY_READ).unwrap();
    assert!(!descriptor_equal(&before, &trial).unwrap());
    assert!(descriptor_trial(&trial, &package, REGISTRY_READ).is_err());
    let run = "a".repeat(32);
    let nonce = "b".repeat(32);
    let receipt = encode_registry_receipt(&run, &package, &nonce, &before, &trial).unwrap();
    let (original, expected) = decode_registry_receipt(&receipt, &run, &package).unwrap();
    assert_eq!(original, before);
    assert_eq!(expected, trial);
    for bad in [
        receipt.replace("sxs-policy", "other"),
        format!("{receipt}extra"),
        receipt.trim_end().to_owned(),
        receipt.replace(&nonce, &run),
    ] {
        assert!(decode_registry_receipt(&bad, &run, &package).is_err());
    }
    assert!(decode_registry_receipt(&receipt, &nonce, &package).is_err());
    let foreign = descriptor(&acl(&[ace(0, 0, 0xf003f, &sid(5, &[18]))], 0));
    assert_eq!(
        restore_decision(&before, &trial, &before, false).unwrap(),
        RestoreDecision::AlreadyOriginal
    );
    assert_eq!(
        restore_decision(&before, &trial, &trial, true).unwrap(),
        RestoreDecision::RestoreOriginal
    );
    assert!(restore_decision(&before, &trial, &trial, false).is_err());
    assert!(restore_decision(&before, &trial, &foreign, true).is_err());
}

#[test]
fn scratch_supported_masks_privileges_quota_and_recovery_keep_original_bounds() {
    assert_eq!(
        SCRATCH_MASKS,
        [0, 0x20, 0x100000, 0x100020, 1, 2, 0x20000, 0x40000, 0x80000]
    );
    let mut results = vec![0i32; 2 + SCRATCH_MASKS.len() * 5];
    for (index, mask) in SCRATCH_MASKS.iter().enumerate() {
        let readable = matches!(*mask, 0x100000 | 0x20000);
        results[2 + index] = if readable { 0 } else { 0xc0000022u32 as i32 };
        results[2 + SCRATCH_MASKS.len() + index] = if readable { *mask as i32 } else { 0 };
    }
    require_supported_results(&results).unwrap();
    for index in 0..2 + SCRATCH_MASKS.len() * 2 {
        let mut bad = results.clone();
        bad[index] ^= 1;
        assert!(require_supported_results(&bad).is_err());
    }
    for attrs in [0, 1, 2, 3, 4, 0x80000002] {
        assert_eq!(
            supported_privileges(&[(23, attrs)]).is_ok(),
            attrs == 2 || attrs == 3
        );
    }
    assert!(supported_privileges(&[]).is_err());
    assert!(supported_privileges(&[(23, 2), (24, 2)]).is_err());
    for supported in [false, true] {
        for running in [false, true] {
            for deferred in [false, true] {
                for clean in [false, true] {
                    assert_eq!(
                        can_restore(supported, running, deferred, clean),
                        !deferred && (!supported || !running && clean)
                    );
                }
            }
        }
    }
    assert!(recovery_available(true, false, 1, true));
    assert!(!recovery_available(false, false, 0, false));
    assert!(recovery_available(false, true, 0, false));
    let package = package();
    require_quota(&package, &package, 16777216, 16777216).unwrap();
    assert!(require_quota(&package, &sid(5, &[18]), 16777216, 16777216).is_err());
    assert!(require_quota(&package, &package, 16777215, 16777216).is_err());
}
