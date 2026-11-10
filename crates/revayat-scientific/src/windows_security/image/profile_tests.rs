//! The full-hash admission path must refuse these synthetic fixtures even when structural bytes pass.
use super::*;
fn put(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn short(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn raw(rva: u32) -> usize {
    if rva < 0x80000 {
        (rva - 0x22000 + 0x200) as usize
    } else {
        rva as usize
    }
}
fn fixture(p: &Profile) -> Vec<u8> {
    let mut b = vec![0; 0xc9000];
    short(&mut b, 0, 0x5a4d);
    put(&mut b, 0x3c, 0x80);
    put(&mut b, 0x80, 0x4550);
    short(&mut b, 0x84, 0x8664);
    short(&mut b, 0x86, 2);
    short(&mut b, 0x94, 240);
    short(&mut b, 0x96, 0x2002);
    short(&mut b, 0x98, 0x20b);
    put(&mut b, 0xa8, p.entry);
    b[0xb0..0xb8].copy_from_slice(&0x180000000u64.to_le_bytes());
    put(&mut b, 0xd0, 0xca000);
    put(&mut b, 0xd4, 0x200);
    put(&mut b, 0x104, 16);
    for (section, values) in [
        (0x188, [0xd000, 0x22000, 0xd000, 0x200, 0x60000020]),
        (0x1b0, [0x49000, 0x80000, 0x49000, 0x80000, 0x40000040]),
    ] {
        for (at, value) in [8, 12, 16, 20, 36].into_iter().zip(values) {
            put(&mut b, section + at, value);
        }
    }
    for (rvas, bytes) in [(p.code, p.bytes), (p.callback, p.callback_bytes)] {
        for (&rva, text) in rvas.iter().zip(bytes) {
            let value = decode(text).unwrap();
            b[raw(rva)..raw(rva) + value.len()].copy_from_slice(&value);
        }
    }
    put(&mut b, 0x110, p.import_directory);
    put(&mut b, 0x114, 0x834);
    let mut owner = 0xc1000;
    for import in p.imports {
        put(&mut b, raw(import.descriptor), import.lookup);
        put(&mut b, raw(import.descriptor) + 12, owner);
        put(&mut b, raw(import.descriptor) + 16, import.address);
        b[owner as usize..owner as usize + import.owner.len()]
            .copy_from_slice(import.owner.as_bytes());
        owner += 128;
        for index in 0..import.count {
            for table in [import.lookup, import.address] {
                b[raw(table + index * 8)..raw(table + index * 8) + 8]
                    .copy_from_slice(&0xc0000u64.to_le_bytes());
            }
        }
        for item in import.symbols {
            for table in [import.lookup, import.address] {
                b[raw(table + item.index * 8)..raw(table + item.index * 8) + 8]
                    .copy_from_slice(&u64::from(item.record).to_le_bytes());
            }
            short(&mut b, raw(item.record), item.hint);
            b[raw(item.record + 2)..raw(item.record + 2) + item.name.len()]
                .copy_from_slice(item.name.as_bytes());
        }
    }
    // Original's general callback profile did not bind this extra CSR slot; the dispatch role does.
    let import = &p.imports[0];
    let record = if p.entry == 0x2e1d0 { 0xc1800 } else { 0xb6da8 };
    for table in [import.lookup, import.address] {
        b[raw(table + 162 * 8)..raw(table + 162 * 8) + 8]
            .copy_from_slice(&u64::from(record).to_le_bytes());
    }
    b[raw(record + 2)..raw(record + 2) + 20].copy_from_slice(b"CsrClientCallServer\0");
    put(&mut b, 0x108, 0xc2000);
    put(&mut b, 0x10c, 0x200);
    for (at, value) in [
        (0x10, 1),
        (0x14, 1),
        (0x18, 1),
        (0x1c, 0xc2040),
        (0x20, 0xc2050),
        (0x24, 0xc2058),
    ] {
        put(&mut b, 0xc2000 + at, value);
    }
    put(&mut b, 0xc2040, p.worker);
    put(&mut b, 0xc2050, 0xc2080);
    b[0xc2080..0xc2080 + 20].copy_from_slice(b"CreateActCtxWWorker\0");
    b
}
#[test]
fn both_reviewed_profiles_bind_all_literal_bytes_edges_imports_and_separate_sites() {
    for p in PROFILES {
        let b = fixture(p);
        let image = PeImage::parse(&b, 1).unwrap();
        structural(&image, p).unwrap();
        let sites = dispatch_sites(&image, p).unwrap();
        assert_eq!(
            sites,
            if p.entry == 0x2e1d0 {
                [0x24bd5, 0x24bdc, 0x8b3c0]
            } else {
                [0x23f85, 0x23f8c, 0x8b3f0]
            }
        );
        assert_eq!(image.activation_worker_slice().unwrap().rva, p.worker);
        assert!(image.require_activation_profile().is_err());
        for rva in p.code.iter().chain(p.callback) {
            let mut bad = b.clone();
            bad[raw(*rva)] ^= 1;
            assert!(structural(&PeImage::parse(&bad, 1).unwrap(), p).is_err());
        }
        let other = &PROFILES[usize::from(p.entry == 0x2e1d0)];
        assert!(structural(&image, other).is_err());
        for import in p.imports {
            for at in [
                import.descriptor,
                import.lookup + import.count * 8,
                import.address,
                import.symbols[0].record,
                import.symbols[0].record + 2,
            ] {
                let mut bad = b.clone();
                bad[raw(at)] ^= 1;
                assert!(structural(&PeImage::parse(&bad, 1).unwrap(), p).is_err());
            }
        }
        for at in [p.imports[0].lookup + 162 * 8, sites[2]] {
            let mut bad = b.clone();
            bad[raw(at)] ^= 1;
            assert!(dispatch_sites(&PeImage::parse(&bad, 1).unwrap(), p).is_err());
        }
    }
}
#[test]
fn csr_export_rejects_forwarder_alias_ordinal_and_non_executable_target() {
    let mut bytes = fixture(&PROFILES[0]);
    bytes[0xc2080..0xc2101].fill(0);
    bytes[0xc2080..0xc2094].copy_from_slice(b"CsrClientCallServer\0");
    assert_eq!(
        PeImage::parse(&bytes, 0x10000000)
            .unwrap()
            .csr_dispatch_export()
            .unwrap(),
        0x10024d20
    );
    for (at, value) in [
        (0x108, 0),
        (0x10c, 39),
        (0xc2014, 4097),
        (0xc2018, 4097),
        (0xc2040, 0xc2000),
        (0xc2040, 0xc2200),
        (0xc2040, 0x80000),
        (0xc2050, u32::MAX),
    ] {
        let mut bad = bytes.clone();
        put(&mut bad, at, value);
        assert!(
            PeImage::parse(&bad, 1)
                .unwrap()
                .csr_dispatch_export()
                .is_err()
        );
    }
    let mut alias = bytes.clone();
    put(&mut alias, 0xc2018, 2);
    put(&mut alias, 0xc2054, 0xc20b0);
    alias[0xc20b0..0xc20bc].copy_from_slice(b"OtherExport\0");
    // Both names referring to ordinal zero must not qualify the selected export.
    assert!(
        PeImage::parse(&alias, 1)
            .unwrap()
            .csr_dispatch_export()
            .is_err()
    );
    short(&mut alias, 0xc205a, 1);
    put(&mut alias, 0xc2014, 2);
    put(&mut alias, 0xc2044, PROFILES[0].worker + 1);
    assert!(
        PeImage::parse(&alias, 1)
            .unwrap()
            .csr_dispatch_export()
            .is_ok()
    );
}
#[test]
fn profile_selection_accepts_no_whitespace_digest_timestamp_module_or_size_drift() {
    for p in PROFILES {
        assert_eq!(select(p.identity).unwrap().entry, p.entry);
        for bad in [
            String::new(),
            format!("{} ", p.identity),
            p.identity.replace("kernel32.dll", "kernelbase.dll"),
            p.identity.replace("sha256=", "sha256=0"),
            p.identity.replace("pe_timestamp=", "pe_timestamp=0"),
            p.identity.replace("image_size=", "image_size=0"),
            p.identity.replace("file_size=", "file_size=0"),
        ] {
            assert!(select(&bad).is_err());
        }
    }
}
