//! Source-grounded fixed storage policy and synchronous creation contracts, not kernel access.
use revayat_scientific::windows_security::{policy::Descriptor, sxs::storage::*};

fn sid(authority: u8, parts: &[u32]) -> Vec<u8> {
    let mut value = vec![1, parts.len() as u8, 0, 0, 0, 0, 0, authority];
    for part in parts {
        value.extend(part.to_le_bytes());
    }
    value
}
fn fixture(directory: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let owner = sid(5, &[21, 1, 2, 3, 1001]);
    let package = sid(15, &[2, 1, 2, 3, 4, 5, 6, 7]);
    let entries: [(u8, u32, Vec<u8>); 4] = [
        (1, 0x1f01ff, package.clone()),
        (1, 0xc0000, sid(3, &[4])),
        (0, 0x1f01ff, owner.clone()),
        (0, 0x1f01ff, sid(5, &[18])),
    ];
    let mut acl = vec![2, 0, 0, 0, 4, 0, 0, 0];
    for (kind, mask, identity) in entries {
        acl.extend([kind, if directory { 3 } else { 16 }]);
        acl.extend(((8 + identity.len()) as u16).to_le_bytes());
        acl.extend(mask.to_le_bytes());
        acl.extend(identity);
    }
    let length = acl.len() as u16;
    acl[2..4].copy_from_slice(&length.to_le_bytes());
    let mut sd = vec![1, 0, 4, if directory { 0x90 } else { 0x80 }];
    for offset in [20, 20 + owner.len(), 0, 20 + 2 * owner.len()] {
        sd.extend((offset as u32).to_le_bytes());
    }
    sd.extend(&owner);
    sd.extend(&owner);
    sd.extend(acl);
    (sd, owner, package)
}
#[test]
fn sealed_storage_requires_actual_owner_four_exact_canonical_inherited_rules() {
    for directory in [false, true] {
        let (sd, owner, package) = fixture(directory);
        require_policy(&sd, directory, &owner, &package).unwrap();
        let parsed = Descriptor::parse(&sd).unwrap();
        let dacl = parsed.dacl.unwrap();
        let at = sd.len() - dacl.len();
        for (offset, mask) in [
            (2, 4),
            (at + 4, 1),
            (at + 8, 1),
            (at + 9, 8),
            (at + 12, 1),
            (20, 1),
        ] {
            let mut bad = sd.clone();
            bad[offset] ^= mask;
            assert!(require_policy(&bad, directory, &owner, &package).is_err());
        }
        let mut foreign = owner.clone();
        *foreign.last_mut().unwrap() ^= 1;
        assert!(require_policy(&sd, directory, &foreign, &package).is_err());
        let mut foreign = package.clone();
        *foreign.last_mut().unwrap() ^= 1;
        assert!(require_policy(&sd, directory, &owner, &foreign).is_err());
        if directory {
            let mut bad = sd.clone();
            bad[3] &= !0x10;
            assert!(require_policy(&bad, true, &owner, &package).is_err());
        }
    }
}
#[test]
fn native_storage_path_accepts_one_exact_non_system_drive_and_one_device_mapping() {
    let folder = r"D:\sxs-trace-0123456789abcdef0123456789abcdef";
    let mapping = "\\Device\\HarddiskVolume12\0\0"
        .encode_utf16()
        .collect::<Vec<_>>();
    assert_eq!(
        native_path(folder, &mapping).unwrap(),
        r"\Device\HarddiskVolume12\sxs-trace-0123456789abcdef0123456789abcdef"
    );
    for bad in [
        folder.to_lowercase(),
        folder.replace("D:", "C:"),
        format!("{folder}\\extra"),
        folder.replace('f', "G"),
    ] {
        assert!(native_path(&bad, &mapping).is_err());
    }
    for bad in [
        "",
        "\\Device\\HarddiskVolume12\0",
        "\\Device\\HarddiskVolume12\0prior\0\0",
        "\\Device\\HarddiskVolume\0\0",
        "\\??\\D:\0\0",
        "\\Device\\HarddiskVolume1\\bad\0\0",
    ] {
        assert!(native_path(folder, &bad.encode_utf16().collect::<Vec<_>>()).is_err());
    }
}
#[test]
fn pending_native_storage_must_not_finalize_live_kernel_output_or_accept_warning() {
    assert_eq!(
        creation_completion(0, 0, 2, 17).unwrap(),
        Completion::Created
    );
    assert_eq!(
        creation_completion(0x103, 0, 2, 17).unwrap(),
        Completion::Pending
    );
    assert_eq!(
        creation_completion(0, 0x103, 2, 17).unwrap(),
        Completion::Pending
    );
    for (returned, completed, information, handle) in [
        (0, 0, 2, 0),
        (0, 0, 2, usize::MAX),
        (0, -1, 2, 17),
        (0, 0, 1, 17),
        (0x80000005u32 as i32, 0, 2, 17),
        (0xc0000035u32 as i32, 0, 2, 17),
    ] {
        assert!(creation_completion(returned, completed, information, handle).is_err());
    }
}
