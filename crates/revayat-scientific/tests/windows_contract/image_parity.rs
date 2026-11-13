//! Fixed byte mutations exercise the real bounded PE decoder, never execute an image.
use revayat_scientific::windows_security::image::*;

fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn short(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    short(&mut bytes, 0, 0x5a4d);
    put(&mut bytes, 0x3c, 0x80);
    put(&mut bytes, 0x80, 0x4550);
    short(&mut bytes, 0x84, 0x8664);
    short(&mut bytes, 0x86, 1);
    short(&mut bytes, 0x94, 240);
    short(&mut bytes, 0x96, 0x2002);
    short(&mut bytes, 0x98, 0x20b);
    put(&mut bytes, 0xa8, 0x1000);
    bytes[0xb0..0xb8].copy_from_slice(&0x180000000u64.to_le_bytes());
    put(&mut bytes, 0xd0, 0x3000);
    put(&mut bytes, 0xd4, 0x200);
    put(&mut bytes, 0x104, 16);
    for (offset, value) in [
        (8, 0xe00),
        (12, 0x1000),
        (16, 0xe00),
        (20, 0x200),
        (36, 0x60000020),
    ] {
        put(&mut bytes, 0x188 + offset, value);
    }
    bytes[0x200..0x206].copy_from_slice(&[0xb8, 0, 0, 0, 0, 0xc3]);
    bytes
}
fn imports(names: &[&str]) -> Vec<u8> {
    let mut bytes = fixture();
    put(&mut bytes, 0x110, 0x1200);
    put(&mut bytes, 0x114, ((names.len() + 1) * 20) as u32);
    let mut offset = 0x600;
    for (index, name) in names.iter().enumerate() {
        let row = 0x400 + index * 20;
        put(&mut bytes, row, 0x1700);
        put(&mut bytes, row + 12, (offset + 0xe00) as u32);
        put(&mut bytes, row + 16, 0x1700);
        bytes[offset..offset + name.len()].copy_from_slice(name.as_bytes());
        offset += name.len() + 1;
    }
    bytes
}
fn manifest(id: u32) -> Vec<u8> {
    let mut bytes = fixture();
    put(&mut bytes, 0x118, 0x1400);
    put(&mut bytes, 0x11c, 0x200);
    for offset in [0x60e, 0x62e, 0x64e] {
        short(&mut bytes, offset, 1);
    }
    for (offset, value) in [
        (0x610, 24),
        (0x614, 0x80000020),
        (0x630, id),
        (0x634, 0x80000040),
        (0x650, 1033),
        (0x654, 0x60),
        (0x660, 0x1480),
        (0x664, 4),
    ] {
        put(&mut bytes, offset, value);
    }
    bytes[0x680..0x684].copy_from_slice(&[1, 2, 3, 4]);
    bytes
}
fn worker() -> Vec<u8> {
    let mut bytes = fixture();
    put(&mut bytes, 0x108, 0x1200);
    put(&mut bytes, 0x10c, 0x200);
    for (offset, value) in [
        (16, 7),
        (20, 2),
        (24, 1),
        (28, 0x1240),
        (32, 0x1250),
        (36, 0x1258),
    ] {
        put(&mut bytes, 0x400 + offset, value);
    }
    put(&mut bytes, 0x440, 0x1020);
    put(&mut bytes, 0x450, 0x1280);
    let name = b"CreateActCtxWWorker\0";
    bytes[0x480..0x480 + name.len()].copy_from_slice(name);
    bytes[0x220..0x22a].copy_from_slice(&[0xb8, 1, 0, 0, 0, 0xe9, 0xd6, 0xff, 0xff, 0xff]);
    bytes
}

#[test]
fn malformed_x64_headers_sections_and_unbacked_rvas_are_refused() {
    let bytes = fixture();
    let image = PeImage::parse(&bytes, 0x10000000).unwrap();
    assert_eq!(image.entry, 0x1000);
    assert_eq!(image.map(0x1000, 6).unwrap(), 0x200);
    assert!(image.executable(0x1000, 1));
    for (offset, value) in [
        (0x3c, u32::MAX),
        (0xa8, 0x3000),
        (0x19c, u32::MAX),
        (0x194, u32::MAX),
        (0x1ac, 0x40000040),
    ] {
        let mut bad = bytes.clone();
        put(&mut bad, offset, value);
        assert!(
            PeImage::parse(&bad, 0x10000000).is_err(),
            "offset={offset:x}"
        );
    }
    for (offset, value) in [(0x84, 0x14c), (0x86, 65), (0x94, 239), (0x98, 0x10b)] {
        let mut bad = bytes.clone();
        short(&mut bad, offset, value);
        assert!(PeImage::parse(&bad, 1).is_err());
    }
    let mut overlap = bytes.clone();
    short(&mut overlap, 0x86, 2);
    overlap.copy_within(0x188..0x1b0, 0x1b0);
    assert!(PeImage::parse(&overlap, 1).is_err());
    let mut zero_fill = bytes.clone();
    put(&mut zero_fill, 0x190, 0x1000);
    let image = PeImage::parse(&zero_fill, 1).unwrap();
    assert!(image.map(0x1e00, 1).is_err());
}

#[test]
fn imports_reject_duplicates_delay_directories_private_names_and_profile_drift() {
    check_import_validation().unwrap();
    let bytes = imports(&["KERNEL32.dll", "ntdll.dll", "advapi32.dll"]);
    let image = PeImage::parse(&bytes, 1).unwrap();
    assert_eq!(
        image.direct_imports().unwrap(),
        ["advapi32.dll", "kernel32.dll", "ntdll.dll"]
    );
    image.qualify_registry_authority().unwrap_err(); // DLL is not the native executable role.
    let mut executable = bytes.clone();
    short(&mut executable, 0x96, 2);
    short(&mut executable, 0xdc, 3);
    PeImage::parse(&executable, 1)
        .unwrap()
        .qualify_registry_authority()
        .unwrap();
    for names in [
        vec!["kernel32.dll", "KERNEL32.dll"],
        vec!["C:\\private\\secret.dll"],
        vec!["kernel32.dll", "unexpected.dll"],
    ] {
        let mut bad = imports(&names);
        short(&mut bad, 0x96, 2);
        short(&mut bad, 0xdc, 3);
        assert!(
            PeImage::parse(&bad, 1)
                .unwrap()
                .qualify_registry_authority()
                .is_err()
        );
    }
    for (offset, value) in [
        (0x114, 39),
        (0x114, 2600),
        (0x410, 0),
        (0x110, u32::MAX),
        (0x420, 1),
        (0x170, 0x1000),
    ] {
        let mut bad = executable.clone();
        put(&mut bad, offset, value);
        assert!(PeImage::parse(&bad, 1).unwrap().direct_imports().is_err());
    }
}

#[test]
fn rust_authority_console_role_checks_real_import_structure_without_legacy_dll_allowlist() {
    let mut bytes = imports(&[
        "KERNEL32.dll",
        "VCRUNTIME140.dll",
        "api-ms-win-crt-runtime-l1-1-0.dll",
    ]);
    short(&mut bytes, 0x96, 2);
    short(&mut bytes, 0xdc, 3);
    let image = PeImage::parse(&bytes, 1).unwrap();
    image.qualify_rust_authority().unwrap();
    assert!(image.qualify_registry_authority().is_err()); // Different toolchain subject, not a broadened legacy rule.
    for (offset, value) in [(0xa8, 0), (0x178, 0x1000), (0x110, u32::MAX), (0x410, 0)] {
        let mut bad = bytes.clone();
        put(&mut bad, offset, value);
        assert!(
            PeImage::parse(&bad, 1)
                .unwrap()
                .qualify_rust_authority()
                .is_err()
        );
    }
    for (offset, value) in [(0x96, 0x2002), (0xdc, 2)] {
        let mut bad = bytes.clone();
        short(&mut bad, offset, value);
        assert!(
            PeImage::parse(&bad, 1)
                .unwrap()
                .qualify_rust_authority()
                .is_err()
        );
    }
}

#[cfg(windows)]
#[test]
fn actual_current_profile_authority_headers_satisfy_bounded_rust_admission() {
    let executable = std::env::current_exe().unwrap();
    let path = executable
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("registry-authority.exe");
    let bytes =
        std::fs::read(&path).expect("workspace must build the same-profile native authority");
    assert!((256..=8 * 1024 * 1024).contains(&bytes.len()));
    let image = PeImage::parse(&bytes, 1).unwrap();
    image.qualify_rust_authority().unwrap();
    assert!(image.image_size <= 64 * 1024 * 1024);
    assert!(image.entry != 0 && image.executable(image.entry, 1));
    assert!(!image.direct_imports().unwrap().is_empty());
    println!(
        "AUTHORITY_IMAGE_ADMISSION profile={} file_bytes={} mapped_bytes={} x64=True console=True imports_bounded=True native_execution_claimed=False",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        bytes.len(),
        image.image_size
    );
}

#[test]
fn export_selection_uses_unbiased_ordinals_and_rejects_forwarders() {
    let bytes = worker();
    let image = PeImage::parse(&bytes, 1).unwrap();
    let slice = image.activation_worker_slice().unwrap();
    assert_eq!(
        (slice.start, slice.rva, slice.raw, slice.length),
        (0x180001020, 0x1020, 0x220, 0xde0)
    );
    for (offset, value) in [
        (0x108, 0),
        (0x10c, 39),
        (0x414, 4097),
        (0x418, 0),
        (0x41c, u32::MAX),
        (0x440, 0x1200),
        (0x440, 0x1300),
        (0x440, 0),
        (0x440, u32::MAX),
    ] {
        let mut bad = bytes.clone();
        put(&mut bad, offset, value);
        assert!(
            PeImage::parse(&bad, 1)
                .unwrap()
                .activation_worker_slice()
                .is_err()
        );
    }
    let mut ordinal = bytes.clone();
    short(&mut ordinal, 0x458, 1);
    put(&mut ordinal, 0x440, 0);
    put(&mut ordinal, 0x444, 0x1020);
    assert_eq!(
        PeImage::parse(&ordinal, 1)
            .unwrap()
            .activation_worker_slice()
            .unwrap()
            .rva,
        0x1020
    );
    let mut bad = bytes.clone();
    short(&mut bad, 0x458, 2);
    assert!(
        PeImage::parse(&bad, 1)
            .unwrap()
            .activation_worker_slice()
            .is_err()
    );
}

#[test]
fn manifest_ids_languages_payloads_and_disjoint_resource_spans_remain_bound() {
    check_manifest_validation().unwrap();
    check_default_activation_validation().unwrap();
    check_module_activation_validation().unwrap();
    for id in [1, 2, 101] {
        let bytes = manifest(id);
        let image = PeImage::parse(&bytes, 1).unwrap();
        let value = image.manifest(id, true).unwrap();
        assert_eq!(value.language, 1033);
        assert_eq!(value.bytes, [1, 2, 3, 4]);
        assert!(image.manifest(if id == 1 { 2 } else { 1 }, true).is_err());
        for (offset, value) in [
            (0x118, 0),
            (0x11c, 15),
            (0x610, 23),
            (0x614, 0x80000000),
            (0x634, 0x80000020),
            (0x654, 0x80000060),
            (0x650, 65536),
            (0x66c, 1),
            (0x660, 0x1440),
            (0x664, 0),
            (0x664, 65537),
        ] {
            let mut bad = bytes.clone();
            put(&mut bad, offset, value);
            assert!(PeImage::parse(&bad, 1).unwrap().manifest(id, true).is_err());
        }
        let mut drift = bytes.clone();
        drift[0x680] ^= 1;
        assert!(
            PeImage::parse(&drift, 1)
                .unwrap()
                .require_manifest(id, 1033, &[1, 2, 3, 4])
                .is_err()
        );
    }
    let mut extra = manifest(1);
    short(&mut extra, 0x60e, 2);
    put(&mut extra, 0x618, 25);
    put(&mut extra, 0x61c, 0x80000020);
    let image = PeImage::parse(&extra, 1).unwrap();
    assert_eq!(image.manifest(1, false).unwrap().bytes, [1, 2, 3, 4]);
    assert!(image.manifest(1, true).is_err());
}

#[test]
fn static_records_bind_bytes_and_window_without_exposing_operands() {
    check_static_validation().unwrap();
    let bytes = fixture();
    let image = PeImage::parse(&bytes, 1).unwrap();
    let slice = image.static_slice(0x1000).unwrap();
    let text = "Dump of file C:\\private\\KernelBase.dll\n  0000000180001000: B8 00 00 00 00     mov eax,0\n  0000000180001005: C3     ret\n";
    let view = image.qualify_static(text, slice).unwrap();
    assert_eq!(view.records, 2);
    assert_eq!(view.unsupported, 0);
    assert_eq!(
        view.text,
        "rva=0x00001000 bytes=B800000000 mnemonic=mov operands=eax,0\nrva=0x00001005 bytes=C3 mnemonic=ret operands=none\n"
    );
    assert!(!view.text.contains("private") && !view.text.contains("18000"));
    let private = image
        .qualify_static(
            "  0000000180001005: C3     ret C:\\private\\secret.dll\n",
            slice,
        )
        .unwrap();
    assert_eq!(private.unsupported, 1);
    assert!(private.text.ends_with("operands=withheld\n"));
    for invalid in [
        "",
        "  0000000180001000: C3     ret\n",
        "  0000000180001005: C3     ret\n  0000000180001000: B8     mov\n",
        "  0000000180001000: B8 00 00 00 00     mov eax,0\n       00\n",
    ] {
        assert!(image.qualify_static(invalid, slice).is_err());
    }
    let mut wrong = slice;
    wrong.raw += 1;
    assert!(image.qualify_static(text, wrong).is_err());
}

#[test]
fn cached_codeview_identity_binds_guid_age_name_and_entire_image_hash() {
    check_identity_validation().unwrap();
    let mut bytes = fixture();
    put(&mut bytes, 0x88, 0x12345678);
    put(&mut bytes, 0x138, 0x1400);
    put(&mut bytes, 0x13c, 28);
    for (offset, value) in [
        (0x60c, 2),
        (0x610, 39),
        (0x614, 0x1480),
        (0x618, 0x680),
        (0x680, 0x53445352),
        (0x694, 7),
    ] {
        put(&mut bytes, offset, value);
    }
    bytes[0x684..0x694].copy_from_slice(&[
        0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    let pdb = b"kernelbase.pdb\0";
    bytes[0x698..0x698 + pdb.len()].copy_from_slice(pdb);
    let identity = PeImage::parse(&bytes, 1)
        .unwrap()
        .kernelbase_identity()
        .unwrap();
    assert!(identity.contains(
        "pdb_guid=00112233-4455-6677-8899-aabbccddeeff pdb_age=7 pdb_name=kernelbase.pdb"
    ));
    assert!(identity.ends_with("pe_timestamp=305419896 image_size=12288 file_size=4096"));
    for (offset, value) in [
        (0x138, 0),
        (0x13c, 27),
        (0x600, 1),
        (0x610, 24),
        (0x614, 0x1481),
        (0x618, u32::MAX),
        (0x680, 0),
        (0x694, 0),
    ] {
        let mut bad = bytes.clone();
        put(&mut bad, offset, value);
        assert!(
            PeImage::parse(&bad, 1)
                .unwrap()
                .kernelbase_identity()
                .is_err()
        );
    }
    let mut changed = bytes.clone();
    changed[0xf00] ^= 1;
    assert_ne!(
        PeImage::parse(&changed, 1)
            .unwrap()
            .kernelbase_identity()
            .unwrap(),
        identity
    );
    changed = bytes.clone();
    changed[0x698] = b'/';
    assert!(
        PeImage::parse(&changed, 1)
            .unwrap()
            .kernelbase_identity()
            .is_err()
    );
}

#[cfg(windows)]
#[test]
fn actual_current_profile_explicit_id2_image_has_exact_nonautomatic_manifest() {
    let executable = std::env::current_exe().unwrap();
    let path = executable
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("startup-explicit-id2.exe");
    let bytes = std::fs::read(&path).unwrap();
    assert!((256..=8 * 1024 * 1024).contains(&bytes.len()));
    let image = PeImage::parse(&bytes, 1).unwrap();
    image.qualify_explicit_id2().unwrap();
    let mut drift = bytes.clone();
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    drift[pe + 24 + 71] ^= 2;
    assert!(
        PeImage::parse(&drift, 1)
            .unwrap()
            .qualify_explicit_id2()
            .is_err()
    );
    let manifest = image.manifest(2, true).unwrap();
    assert_eq!(manifest.language, 1033);
    let pointer = manifest.bytes.as_ptr() as usize - bytes.as_ptr() as usize;
    let mut drift = bytes.clone();
    drift[pointer] ^= 1;
    assert!(
        PeImage::parse(&drift, 1)
            .unwrap()
            .qualify_explicit_id2()
            .is_err()
    );
}
#[test]
fn identity_and_checkpoint_never_accept_arbitrary_rvas_or_unreviewed_hashes() {
    assert_eq!(
        sha256(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    for profile in observation_profiles() {
        assert_eq!(
            select_observation(&profile.identity).unwrap().checkpoint,
            profile.checkpoint
        );
        assert!(select_observation(&format!("{} ", profile.identity)).is_err());
        let section = profile.section;
        assert_eq!(
            checkpoint_address(&[section], profile.image_size, 0x180000000, &profile).unwrap(),
            0x180000000 + u64::from(profile.checkpoint)
        );
        for field in 0..5 {
            let mut changed = section;
            match field {
                0 => changed.rva += 1,
                1 => changed.raw += 1,
                2 => changed.raw_size += 1,
                3 => changed.virtual_size += 1,
                _ => changed.flags ^= 0x20000000,
            }
            assert!(
                checkpoint_address(&[changed], profile.image_size, 0x180000000, &profile).is_err()
            );
        }
        assert!(
            checkpoint_address(
                &[section, section],
                profile.image_size,
                0x180000000,
                &profile
            )
            .is_err()
        );
        assert!(checkpoint_address(&[], profile.image_size, 0x180000000, &profile).is_err());
    }
}
