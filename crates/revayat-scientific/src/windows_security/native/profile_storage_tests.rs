//! Original profile filesystem contracts. Hosted native cases are not local execution evidence.
use super::*;
use crate::windows_security::policy::{Acl, Descriptor as Relative};
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemAlloc(bytes: usize) -> Handle;
}

#[test]
fn original_moniker_and_exact_package_ac_path_cannot_select_another_tree() {
    let name = "Scientific.Security.0123456789abcdef0123456789abcdef";
    validate_name(name).unwrap();
    for bad in [
        "",
        "revayat-profile-123",
        "Scientific.Security.0123456789ABCDEF0123456789ABCDEF",
        "Scientific.Security.0123456789abcdef0123456789abcde",
        "Scientific.Security.0123456789abcdef0123456789abcdefx",
    ] {
        assert!(validate_name(bad).is_err());
    }
    let local = Path::new(r"C:\Users\owned user\AppData\Local");
    let (root, ac) = profile_paths(local, name).unwrap();
    assert_eq!(root, local.join("Packages").join(name));
    assert_eq!(ac, root.join("AC"));
    require_folder(&ac, &ac).unwrap();
    require_folder(
        &ac,
        &PathBuf::from(ac.to_string_lossy().to_ascii_lowercase()),
    )
    .unwrap();
    for wrong in [
        root.clone(),
        root.join("AC-other"),
        local.join("AC"),
        ac.join("child"),
        ac.join(".."),
    ] {
        assert!(require_folder(&ac, &wrong).is_err());
    }
    for bad in [
        Path::new("relative"),
        Path::new(r"C:\owned\..\other"),
        Path::new("C:\\bad\0path"),
    ] {
        assert!(profile_paths(bad, name).is_err());
    }
    let guid = Guid {
        a: 0x01234567,
        b: 0x89ab,
        c: 0xcdef,
        d: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    assert_eq!(
        moniker(&guid),
        "Scientific.Security.0123456789abcdef0102030405060708"
    );
    assert_eq!(size_of::<Guid>(), 16);
    assert_eq!(std::mem::offset_of!(Guid, d), 8);
}

#[test]
fn filesystem_six_rules_match_framework_masks_flags_order_and_access_readback() {
    let user = "S-1-5-21-1-2-3-500";
    let package = "S-1-15-2-1-2-3-4-5-6-7";
    for directory in [false, true] {
        let text = policy::sddl(user, package, directory).unwrap();
        let flags = if directory { "OICI" } else { "" };
        assert_eq!(
            text,
            format!(
                "D:P(D;{flags};0x000C0000;;;S-1-3-4)(D;{flags};0x000D0116;;;{package})(A;{flags};0x001F01FF;;;S-1-5-18)(A;{flags};0x001F01FF;;;S-1-5-32-544)(A;{flags};0x001F01FF;;;{user})(A;{flags};0x001200A9;;;{package})"
            )
        );
        let mut native = Descriptor::new(&text).unwrap();
        let bytes = policy::bytes(&native).unwrap();
        let parsed = Relative::parse(&bytes).unwrap();
        assert_eq!(parsed.control & 0x9004, 0x9004);
        assert!(parsed.owner.is_none() && parsed.group.is_none() && parsed.sacl.is_none());
        let acl = Acl::parse(parsed.dacl.unwrap()).unwrap();
        assert_eq!(acl.aces.len(), 6);
        assert_eq!(
            acl.aces
                .iter()
                .map(|ace| (ace.kind, ace.flags, ace.mask().unwrap()))
                .collect::<Vec<_>>(),
            [
                (1, if directory { 3 } else { 0 }, 0xc0000),
                (1, if directory { 3 } else { 0 }, 0xd0116),
                (0, if directory { 3 } else { 0 }, 0x1f01ff),
                (0, if directory { 3 } else { 0 }, 0x1f01ff),
                (0, if directory { 3 } else { 0 }, 0x1f01ff),
                (0, if directory { 3 } else { 0 }, 0x1200a9)
            ]
        );
        assert!(policy::matches_access(&bytes, &bytes).unwrap());
        let mut bookkeeping = bytes.clone();
        bookkeeping[3] ^= 4;
        assert!(policy::matches_access(&bytes, &bookkeeping).unwrap());
        let offset = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let mut padding = bytes.clone();
        let length = u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap());
        padding.extend([0; 4]);
        padding[offset + 2..offset + 4].copy_from_slice(&(length + 4).to_le_bytes());
        assert!(policy::matches_access(&bytes, &padding).unwrap());
        for (at, bit) in [
            (3, 0x10),
            (2, 4),
            (3, 1),
            (3, 8),
            (offset + 9, 1),
            (offset + 12, 1),
            (offset + 24, 1),
        ] {
            let mut bad = bytes.clone();
            bad[at] ^= bit;
            assert!(
                !policy::matches_access(&bytes, &bad).unwrap_or(false),
                "at={at}"
            );
        }
        let mut reversed = bytes.clone();
        reversed[offset + 8] = 0;
        assert!(!policy::matches_access(&bytes, &reversed).unwrap_or(false));
        native.close().unwrap();
    }
    for user in [
        "S-1-3-4",
        "S-1-5-18",
        "S-1-5-32-544",
        package,
        "S-1-05-21",
        "private-sentinel",
    ] {
        assert!(policy::sddl(user, package, true).is_err());
    }
}

#[test]
fn failed_open_cleanup_uncertainty_prevents_profile_deletion_authority() {
    let mut uncertain = false;
    let primary: Result<()> = Err(anyhow::anyhow!("fixed primary"));
    let error =
        retain_close(primary, Err(anyhow::anyhow!("fixed close")), &mut uncertain).unwrap_err();
    assert!(uncertain);
    assert_eq!(error.downcast_ref::<Failures>().unwrap().errors.len(), 2);
    let mut uncertain = true;
    retain_close(Ok(()), Ok(()), &mut uncertain).unwrap();
    assert!(uncertain);
}

#[test]
fn original_descendant_and_depth_budgets_include_exact_boundary_without_root_off_by_one() {
    for (count, depth, okay) in [
        (0, 1, true),
        (255, 32, true),
        (256, 1, false),
        (0, 33, false),
        (0, 0, false),
    ] {
        assert_eq!(tree_budget(count, depth).is_ok(), okay);
    }
}

#[test]
fn retained_tree_refuses_existing_storage_substitution_and_seals_children_before_parents() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("fresh-profile");
    require_absent(&root).unwrap();
    std::fs::create_dir(&root).unwrap();
    assert!(require_absent(&root).is_err());
    std::fs::create_dir(root.join("AC")).unwrap();
    std::fs::create_dir(root.join("AC").join("child")).unwrap();
    std::fs::write(root.join("AC").join("child").join("fixed.txt"), b"owned").unwrap();
    let mut storage = Storage::for_root(root.clone());
    storage.collect().unwrap();
    assert_eq!(storage.entries.len(), 4);
    let order = storage.seal_order();
    assert_eq!(storage.entries[*order.last().unwrap()].path, root);
    for (at, index) in order.iter().enumerate() {
        for (child_at, child) in order.iter().enumerate() {
            if storage.entries[*child].path.parent() == Some(storage.entries[*index].path.as_path())
            {
                assert!(child_at < at);
            }
        }
    }
    // Same bytes at another path never satisfy the retained object/path identity.
    let other = temp.path().join("other");
    std::fs::create_dir(&other).unwrap();
    let original = storage.entries[0].path.clone();
    storage.entries[0].path = other;
    assert!(storage.entries[0].require().is_err());
    storage.entries[0].path = original;
    storage.entries[0].require().unwrap();
    assert!(std::fs::rename(&root, temp.path().join("renamed")).is_err());
    storage.close().unwrap();
    storage.close().unwrap();
    assert!(storage.entries.is_empty());
}

#[test]
fn actual_hardlink_alias_is_rejected_without_sealing_an_unowned_object() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("outside");
    std::fs::write(&original, b"owned control").unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::hard_link(&original, root.join("alias")).unwrap();
    let mut storage = Storage::for_root(root);
    assert!(storage.collect().is_err());
    storage.close().unwrap();
    assert_eq!(std::fs::read(&original).unwrap(), b"owned control");
    let fresh_root = temp.path().join("fresh");
    std::fs::create_dir(&fresh_root).unwrap();
    let fresh = fresh_root.join("fixed");
    std::fs::write(&fresh, b"owned control").unwrap();
    let mut retained = Storage::for_root(fresh_root);
    retained.collect().unwrap();
    std::fs::hard_link(&fresh, temp.path().join("late-alias")).unwrap();
    assert!(
        retained
            .entries
            .iter()
            .find(|entry| !entry.directory)
            .unwrap()
            .require()
            .is_err()
    );
    retained.close().unwrap();
}

#[test]
fn native_path_allocations_are_released_and_invalid_outputs_are_not_paths() {
    for (status, units) in [
        (0i32, Some("C:\\owned profile")),
        (0, Some("relative")),
        (0x80070005u32 as i32, Some("C:\\owned profile")),
        (0, None),
    ] {
        let mut raw = null_mut();
        if let Some(text) = units {
            let encoded = wide(text);
            raw = unsafe { CoTaskMemAlloc(encoded.len() * 2) }.cast::<u16>();
            assert!(!raw.is_null());
            unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), raw, encoded.len()) };
        }
        assert_eq!(
            task_path(status, raw).is_ok(),
            status == 0 && units == Some("C:\\owned profile")
        );
    }
}

#[test]
fn every_owned_tree_handle_is_closed_once_in_reverse_even_after_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("fixed"), b"owned").unwrap();
    let mut storage = Storage::for_root(root);
    storage.collect().unwrap();
    let handles = storage
        .entries
        .iter()
        .map(|entry| entry.file.as_ref().unwrap().as_raw_handle() as usize)
        .collect::<Vec<_>>();
    let calls = std::cell::RefCell::new(Vec::new());
    let error = storage
        .close_with(|file| {
            let handle = file.as_raw_handle() as usize;
            calls.borrow_mut().push(handle);
            close_file(file)?;
            if handle == handles[1] {
                anyhow::bail!("fixed close uncertainty");
            }
            Ok(())
        })
        .unwrap_err();
    assert_eq!(
        *calls.borrow(),
        handles.into_iter().rev().collect::<Vec<_>>()
    );
    assert!(
        error
            .downcast_ref::<crate::windows_security::activation::Failures>()
            .is_some()
    );
    assert!(
        storage
            .close_with(|_| panic!("invalidated handle retried"))
            .is_err()
    );
}

#[test]
fn actual_owned_file_and_directory_support_exact_final_seal_without_scratch_mic_setter() {
    // Supporting native I/O, not a substitute for Profile::new's actual package-path binding.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("fixed"), b"owned").unwrap();
    let mut storage = Storage::for_root(root);
    storage.collect().unwrap();
    let user = crate::windows_security::sxs::current_user_sid().unwrap();
    let package = "S-1-15-2-1-2-3-4-5-6-7";
    let result = storage.seal(&user, package);
    let cleanup = storage.close();
    result.unwrap();
    cleanup.unwrap();
}

#[test]
fn actual_profile_new_requires_storage_before_success_and_keeps_existing_child_authority() {
    let source = include_str!("authority.rs");
    let body = source
        .split_once("impl Profile {")
        .unwrap()
        .1
        .split_once("fn sid_text")
        .unwrap()
        .0;
    assert!(
        body.find("Storage::before_create").unwrap()
            < body.find("CreateAppContainerProfile(").unwrap()
    );
    assert!(body.contains("profile.created = status == 0"));
    assert!(body.find("storage.prepare(").unwrap() < body.find("Ok(profile)").unwrap());
    assert!(body.find("storage.close()").unwrap() < body.find("profile.close()").unwrap());
    assert!(body.contains("profile.retain()"));
    let owner = include_str!("profile_storage.rs");
    assert!(owner.contains("GetAppContainerFolderPath(text.as_ptr()"));
    assert!(owner.contains("WINDOWS_PROFILE sealed=true capabilities=0 entries="));
    assert!(owner.contains("CoTaskMemFree"));
    assert!(!owner.contains("SetFileSecurityW") && !owner.contains("protect_scratch("));
    assert!(!owner.contains("CreateProcessW(") && !owner.contains("CreateProcessAsUserW("));
}
