//! Synthetic structural fixtures never satisfy full-hash admission.
use super::csr::{fixture, put, raw, short};
use super::*;
#[test]
fn both_reviewed_profiles_bind_all_literal_bytes_edges_imports_and_separate_sites() {
    super::super::validation::check_validation().unwrap();
    super::super::validation::check_checkpoint_validation().unwrap();
    super::super::validation::check_child_activation_validation().unwrap();
    super::super::validation::check_self_activation_validation().unwrap();
    super::super::validation::check_independent_id2_validation().unwrap();
    for p in PROFILES {
        let b = fixture(p);
        let image = PeImage::parse(&b, 1).unwrap();
        structural(&image, p).unwrap();
        module_callback_profile(&image, p).unwrap();
        assert_eq!(
            activation_boundary_profile(&image, p).unwrap(),
            BoundarySites {
                worker: p.worker,
                registry: p.code[62],
                funnel: p.code[13]
            }
        );
        let callback_only_rva =
            p.callback
                .iter()
                .find(|rva| {
                    !p.code.iter().zip(p.bytes).any(|(code, bytes)| {
                        **rva >= *code && **rva < *code + (bytes.len() / 2) as u32
                    })
                })
                .unwrap();
        let mut callback_drift = b.clone();
        callback_drift[raw(*callback_only_rva)] ^= 1;
        let callback_drift = PeImage::parse(&callback_drift, 1).unwrap();
        activation_boundary_profile(&callback_drift, p).unwrap();
        assert!(module_callback_profile(&callback_drift, p).is_err());
        let mut wrong_worker = b.clone();
        put(&mut wrong_worker, 0xc2040, p.worker + 1);
        assert_eq!(
            module_callback_profile(&PeImage::parse(&wrong_worker, 1).unwrap(), p)
                .unwrap_err()
                .to_string(),
            "activation worker export differs"
        );
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
        assert!(image.require_module_callback_profile().is_err());
        assert!(image.module_callback_site().is_err());
        assert!(image.require_activation_boundary_profile().is_err());
        assert!(
            KernelImage::from_activation_worker(&b)
                .unwrap()
                .require_module_callback_profile()
                .is_err()
        );
        assert!(
            KernelImage::from_activation_worker(&b)
                .unwrap()
                .require_activation_boundary_profile()
                .is_err()
        );
        assert_eq!(
            KernelImage::from_static(&b)
                .unwrap()
                .require_activation_boundary_profile()
                .unwrap_err()
                .to_string(),
            "wrong activation-worker identity subject"
        );
        let wrong_subject = KernelImage::from_static(&b)
            .unwrap()
            .require_module_callback_profile()
            .unwrap_err();
        assert_eq!(
            wrong_subject.to_string(),
            "wrong activation-worker identity subject"
        );
        for rva in p.code.iter().chain(p.callback) {
            let mut bad = b.clone();
            bad[raw(*rva)] ^= 1;
            assert!(structural(&PeImage::parse(&bad, 1).unwrap(), p).is_err());
            assert!(module_callback_profile(&PeImage::parse(&bad, 1).unwrap(), p).is_err());
            if p.code.contains(rva) {
                assert!(activation_boundary_profile(&PeImage::parse(&bad, 1).unwrap(), p).is_err());
            }
        }
        let other = &PROFILES[usize::from(p.entry == 0x2e1d0)];
        assert!(structural(&image, other).is_err());
        assert!(module_callback_profile(&image, other).is_err());
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
                assert!(module_callback_profile(&PeImage::parse(&bad, 1).unwrap(), p).is_err());
            }
        }
        for at in [p.imports[0].lookup + 162 * 8, sites[2]] {
            let mut bad = b.clone();
            bad[raw(at)] ^= 1;
            assert!(dispatch_sites(&PeImage::parse(&bad, 1).unwrap(), p).is_err());
        }
        if p.entry == 0x2e1d0 {
            // Original CallbackBytes did not bind the additional CSR symbol
            // at thunk162. Keep lookup/IAT equal and otherwise valid: the
            // genuine callback body must still pass while CSR qualification
            // independently refuses the changed target. The public full-hash
            // gate continues to refuse all such synthetic images.
            let import = &p.imports[0];
            let mut callback_only = b.clone();
            for table in [import.lookup, import.address] {
                callback_only[raw(table + 162 * 8)..raw(table + 162 * 8) + 8]
                    .copy_from_slice(&0xc0000u64.to_le_bytes());
            }
            let callback_only = PeImage::parse(&callback_only, 1).unwrap();
            activation_boundary_profile(&callback_only, p).unwrap();
            module_callback_profile(&callback_only, p).unwrap();
            assert!(dispatch_sites(&callback_only, p).is_err());
            assert!(callback_only.require_module_callback_profile().is_err());
        }
    }
}
#[test]
fn csr_export_rejects_forwarder_alias_ordinal_and_non_executable_target() {
    super::super::validation::check_activation_worker_validation().unwrap();
    check_csr_dispatch_validation().unwrap();
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
    super::super::validation::check_python_dispatch_identity().unwrap();
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
