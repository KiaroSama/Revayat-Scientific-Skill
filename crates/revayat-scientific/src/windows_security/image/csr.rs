//! Original CSR dispatch parser assertions and subject-bound address seams.
use super::*;
pub(super) fn put(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
pub(super) fn short(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
pub(super) fn raw(rva: u32) -> usize {
    if rva < 0x80000 {
        (rva - 0x22000 + 0x200) as usize
    } else {
        rva as usize
    }
}
pub(super) fn fixture(p: &Profile) -> Vec<u8> {
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

impl KernelImage<'_> {
    pub fn csr_dispatch_sites(&self) -> Result<[u32; 3]> {
        self.require_module_callback_profile()?;
        dispatch_sites(&self.pe, select(&self.kernel32_identity()?)?)
    }
    pub fn csr_dispatch_iat_address(&self, rva: u32) -> Result<u64> {
        ensure!(
            self.subject == "kernel32.dll",
            "wrong CSR caller image subject"
        );
        self.pe.map(rva, 8)?;
        ensure!(
            self.pe
                .sections
                .iter()
                .filter(|section| {
                    section.flags & 0x40000000 != 0
                        && section.flags & 0x20000000 == 0
                        && rva >= section.rva
                        && u64::from(rva) + 8
                            <= u64::from(section.rva)
                                + u64::from(section.virtual_size.min(section.raw_size))
                })
                .count()
                == 1,
            "CSR IAT needs one file-backed readable non-executable section"
        );
        Ok(self.pe.base + u64::from(rva))
    }
    pub fn csr_dispatch_export(&self) -> Result<u64> {
        ensure!(
            self.subject == "ntdll.dll",
            "wrong CSR target image subject"
        );
        self.pe.csr_dispatch_export()
    }
}

/// All reachable original pure CheckCsrDispatchValidation products. These
/// assertions inspect fixture bytes; they do not claim a native call occurred.
pub fn check_csr_dispatch_validation() -> Result<()> {
    check_pair_validation()?;
    for profile in PROFILES {
        let bytes = fixture(profile);
        let image = KernelImage::from_activation_worker(&bytes)?;
        let sites = dispatch_sites(&image.pe, profile)?;
        let expected = if profile.entry == 0x2e1d0 {
            [0x24bd5, 0x24bdc, 0x8b3c0]
        } else {
            [0x23f85, 0x23f8c, 0x8b3f0]
        };
        ensure!(
            sites == expected
                && image.csr_dispatch_iat_address(sites[2])? == 1 + u64::from(sites[2]),
            "CSR profile call/post/IAT products differ"
        );
        let import = &profile.imports[0];
        let record = if profile.entry == 0x2e1d0 {
            0xc1800
        } else {
            0xb6da8
        };
        for at in [import.lookup + 162 * 8, sites[2], record + 2] {
            let mut bad = bytes.clone();
            bad[image.pe.map(at, 1)?] ^= 1;
            ensure!(
                dispatch_sites(&PeImage::parse(&bad, 1)?, profile).is_err(),
                "CSR import mutation accepted rva={at}"
            );
        }
        ensure!(
            KernelImage::from_static(&bytes)?
                .csr_dispatch_iat_address(sites[2])
                .is_err(),
            "CSR IAT admitted wrong module subject"
        );
    }
    super::super::validation::check_csr_export_validation()?;
    check_target_validation()
}

fn check_pair_validation() -> Result<()> {
    use crate::windows_security::activation::{CONTEXT_SIZE, dispatch::CsrPair};
    let context = || {
        let mut value = vec![0; CONTEXT_SIZE];
        for (at, number) in [(152, 0x8000u64), (184, 0x1001001e), (192, 0x1f8)] {
            value[at..at + 8].copy_from_slice(&number.to_le_bytes());
        }
        value
    };
    let mut value = context();
    let pair = || CsrPair::new(0x1000, 0x1007);
    let mut observed = pair()?;
    ensure!(
        observed.sites(1) == [0x1000, 0x1007],
        "CSR initial pair sites differ"
    );
    ensure!(pair()?.end(1, &value).is_err(), "CSR early return accepted");
    observed.begin(1, &value)?;
    ensure!(
        observed.sites(1) == [0, 0x1007] && observed.sites(2) == [0, 0],
        "CSR started pair sites differ"
    );
    let mut repeated = pair()?;
    repeated.begin(1, &value)?;
    ensure!(
        repeated.begin(1, &value).is_err() && repeated.end(1, &value).is_err(),
        "CSR reused begin was not consumed"
    );
    for wrong_generation in [false, true] {
        let mut mismatch = pair()?;
        mismatch.begin(1, &value)?;
        let mut nested = value.clone();
        if !wrong_generation {
            nested[152..160].copy_from_slice(&0x7f00u64.to_le_bytes());
        }
        ensure!(
            mismatch
                .end(if wrong_generation { 2 } else { 1 }, &nested)
                .is_err()
                && mismatch.end(1, &value).is_err(),
            "CSR nested/generation attempt was reused"
        );
    }
    value[184..192].copy_from_slice(&u64::MAX.to_le_bytes());
    value[192..200].fill(0);
    value[120..128].copy_from_slice(&0x12345678c0150002u64.to_le_bytes());
    observed.end(1, &value)?;
    ensure!(
        observed.paired() && observed.result()? == 0xc0150002 && observed.sites(1) == [0, 0],
        "CSR low32 return or completed sites differ"
    );
    ensure!(
        observed.end(1, &value).is_err(),
        "CSR repeated return accepted"
    );
    for offset in [152, 184, 192] {
        let mut bad = context();
        bad[offset] ^= 1;
        let mut failed = pair()?;
        ensure!(
            failed.begin(1, &bad).is_err()
                && failed.started()
                && !failed.paired()
                && failed.begin(1, &value).is_err(),
            "CSR malformed begin did not consume attempt"
        );
    }
    Ok(())
}

fn check_target_validation() -> Result<()> {
    use crate::windows_security::activation::dispatch::{DispatchRegion, DispatchTarget};
    let region = || {
        Ok(DispatchRegion {
            address: 0x8000,
            allocation: 0x1000,
            size: 8,
            state: 0x1000,
            kind: 0x1000000,
            protect: 4,
        })
    };
    let mut target = DispatchTarget::default();
    target.read(0x8000, 0x1000, 0x9000, region, |bytes| {
        *bytes = 0x9000u64.to_le_bytes();
        Ok(8)
    })?;
    ensure!(
        target
            .read(0x8000, 0x1000, 0x9000, region, |_| unreachable!())
            .is_err(),
        "CSR target read attempt reused"
    );
    for count in [0, 7, 8] {
        let mut target = DispatchTarget::default();
        ensure!(
            target
                .read(0x8000, 0x1000, 0x9000, region, |bytes| {
                    *bytes = 0x9001u64.to_le_bytes();
                    Ok(count)
                })
                .is_err(),
            "CSR short or foreign pointer accepted"
        );
        ensure!(
            target
                .read(0x8000, 0x1000, 0x9000, region, |_| unreachable!())
                .is_err(),
            "CSR failed target read attempt reused"
        );
    }
    Ok(())
}

impl PeImage<'_> {
    /// Fail-closed structural CSR dispatch site resolver for OS-verified serviced
    /// `System32\kernel32.dll` builds whose SHA-256 hash falls outside `PROFILES`.
    pub fn resolve_serviced_csr_dispatch_sites(&self) -> Result<[u32; 3]> {
        const PREFIX: [u8; 12] = [
            0x41, 0xb9, 0xf8, 0x01, 0x00, 0x00, 0x41, 0xb8, 0x1e, 0x00, 0x01, 0x10,
        ];
        const SUFFIX: [u8; 7] = [0x0f, 0x1f, 0x44, 0x00, 0x00, 0x8b, 0xd8];

        self.activation_worker_slice()?;
        let csr_iat = self.resolve_serviced_csr_iat()?;
        let mut matches = Vec::new();
        for section in &self.sections {
            if section.flags & 0x20000000 == 0 {
                continue;
            }
            let len = section.virtual_size.min(section.raw_size) as usize;
            if len < PREFIX.len() + 7 + SUFFIX.len() {
                continue;
            }
            let data = span(self.bytes, section.raw as usize, len)?;
            for rel in PREFIX.len()..=len - 7 - SUFFIX.len() {
                if data[rel..rel + 3] != [0x48, 0xff, 0x15]
                    || data[rel - PREFIX.len()..rel] != PREFIX
                    || data[rel + 7..rel + 7 + SUFFIX.len()] != SUFFIX
                {
                    continue;
                }
                let disp = i32::from_le_bytes(data[rel + 3..rel + 7].try_into()?);
                let call = section
                    .rva
                    .checked_add(rel as u32)
                    .ok_or_else(|| anyhow::anyhow!("serviced CSR call RVA overflow"))?;
                let post = call
                    .checked_add(7)
                    .ok_or_else(|| anyhow::anyhow!("serviced CSR post RVA overflow"))?;
                if i64::from(post) + i64::from(disp) == i64::from(csr_iat)
                    && self.executable(call, 7)
                    && self.executable(post, 5)
                {
                    matches.push([call, post, csr_iat]);
                }
            }
        }
        ensure!(
            matches.len() == 1,
            "serviced kernel32 CSR dispatch site count {} != 1",
            matches.len()
        );
        Ok(matches[0])
    }

    fn resolve_serviced_csr_iat(&self) -> Result<u32> {
        let (imp_rva, imp_size) = self.directory(1)?;
        ensure!(
            imp_rva >= self.headers && (20..=1048576).contains(&imp_size),
            "serviced CSR import directory differs"
        );
        let max_descs = (imp_size / 20).min(4096);
        let mut csr_iat = None;
        for idx in 0..max_descs {
            let desc_rva = imp_rva
                .checked_add(idx * 20)
                .ok_or_else(|| anyhow::anyhow!("serviced CSR descriptor RVA overflow"))?;
            let desc_off = self.map(desc_rva, 20)?;
            let raw = span(self.bytes, desc_off, 20)?;
            if raw.iter().all(|byte| *byte == 0) {
                break;
            }
            let ilt = u32_at(self.bytes, desc_off)?;
            let name_rva = u32_at(self.bytes, desc_off + 12)?;
            let iat = u32_at(self.bytes, desc_off + 16)?;
            if !self
                .text(name_rva, 64, true)?
                .eq_ignore_ascii_case("ntdll.dll")
            {
                continue;
            }
            ensure!(ilt != 0 && iat != 0, "serviced ntdll import tables absent");
            for slot_idx in 0u32..4096 {
                let offset = slot_idx
                    .checked_mul(8)
                    .ok_or_else(|| anyhow::anyhow!("serviced CSR thunk offset overflow"))?;
                let lookup_rva = ilt
                    .checked_add(offset)
                    .ok_or_else(|| anyhow::anyhow!("serviced CSR ILT RVA overflow"))?;
                let slot_rva = iat
                    .checked_add(offset)
                    .ok_or_else(|| anyhow::anyhow!("serviced CSR IAT RVA overflow"))?;
                let lookup = u64_at(self.bytes, self.map(lookup_rva, 8)?)?;
                let bound = u64_at(self.bytes, self.map(slot_rva, 8)?)?;
                if lookup == 0 {
                    ensure!(bound == 0, "serviced ntdll import terminator mismatch");
                    break;
                }
                if lookup & (1u64 << 63) != 0 {
                    continue;
                }
                ensure!(
                    lookup <= u64::from(u32::MAX - 2),
                    "serviced ntdll import hint RVA out of bounds"
                );
                if self.text(lookup as u32 + 2, 64, false)? == "CsrClientCallServer" {
                    ensure!(bound == lookup, "serviced CSR ILT/IAT entry differs");
                    ensure!(
                        csr_iat.replace(slot_rva).is_none(),
                        "serviced CSR import slot duplicated"
                    );
                }
            }
        }
        let slot = csr_iat.ok_or_else(|| anyhow::anyhow!("serviced CSR import slot absent"))?;
        ensure!(
            self.sections
                .iter()
                .filter(|section| {
                    section.flags & 0x40000000 != 0
                        && section.flags & 0x20000000 == 0
                        && slot >= section.rva
                        && u64::from(slot) + 8
                            <= u64::from(section.rva)
                                + u64::from(section.virtual_size.min(section.raw_size))
                })
                .count()
                == 1,
            "serviced CSR import slot section differs"
        );
        Ok(slot)
    }
}
