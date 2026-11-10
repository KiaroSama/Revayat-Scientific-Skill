//! Read-only bounded PE contracts. Parsed bytes are not evidence of a loaded image or native execution.
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
#[path = "image/profiles.rs"]
mod profiles;
#[path = "image/static_view.rs"]
mod static_view;
pub use profiles::ActivationSites;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section {
    pub rva: u32,
    pub virtual_size: u32,
    pub raw: u32,
    pub raw_size: u32,
    pub flags: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticSlice {
    pub start: u64,
    pub rva: u32,
    pub length: u32,
    pub raw: usize,
}
pub struct StaticView {
    pub text: String,
    pub records: usize,
    pub unsupported: usize,
}
pub struct Manifest<'a> {
    pub language: u16,
    pub bytes: &'a [u8],
}
pub struct PeImage<'a> {
    bytes: &'a [u8],
    optional: usize,
    pe: usize,
    headers: u32,
    pub image_size: u32,
    pub base: u64,
    pub entry: u32,
    pub sections: Vec<Section>,
}
fn span(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    ensure!(
        offset <= bytes.len() && size <= bytes.len() - offset,
        "PE span exceeds image"
    );
    Ok(&bytes[offset..offset + size])
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(span(bytes, offset, 2)?.try_into()?))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(span(bytes, offset, 4)?.try_into()?))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(span(bytes, offset, 8)?.try_into()?))
}
fn overlaps(a: u64, size: u64, b: u64, other: u64) -> bool {
    a < b + other && b < a + size
}
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
impl<'a> PeImage<'a> {
    pub fn parse(bytes: &'a [u8], base: u64) -> Result<Self> {
        ensure!(
            (256..=16 * 1024 * 1024).contains(&bytes.len()) && base != 0,
            "invalid PE input bound"
        );
        ensure!(u16_at(bytes, 0)? == 0x5a4d, "invalid PE DOS header");
        let pe = u32_at(bytes, 0x3c)? as usize;
        ensure!(
            u32_at(bytes, pe)? == 0x4550 && u16_at(bytes, pe + 4)? == 0x8664,
            "PE must be x64"
        );
        let count = usize::from(u16_at(bytes, pe + 6)?);
        let optional_size = usize::from(u16_at(bytes, pe + 20)?);
        ensure!(
            (1..=64).contains(&count) && optional_size >= 240,
            "invalid PE section/optional size"
        );
        let optional = pe + 24;
        span(bytes, optional, optional_size)?;
        ensure!(
            u16_at(bytes, optional)? == 0x20b && u32_at(bytes, optional + 108)? >= 16,
            "invalid PE64 optional header"
        );
        let entry = u32_at(bytes, optional + 16)?;
        let image_size = u32_at(bytes, optional + 56)?;
        let headers = u32_at(bytes, optional + 60)?;
        ensure!(
            headers > 0
                && headers as usize <= bytes.len()
                && image_size >= headers
                && image_size <= 64 * 1024 * 1024
                && base <= 0x7fffffffffffffff - u64::from(image_size),
            "invalid PE image size"
        );
        let table = optional + optional_size;
        span(bytes, table, count * 40)?;
        ensure!(
            table + count * 40 <= headers as usize,
            "PE section table exceeds headers"
        );
        let mut sections: Vec<Section> = Vec::with_capacity(count);
        for index in 0..count {
            let offset = table + index * 40;
            let section = Section {
                virtual_size: u32_at(bytes, offset + 8)?,
                rva: u32_at(bytes, offset + 12)?,
                raw_size: u32_at(bytes, offset + 16)?,
                raw: u32_at(bytes, offset + 20)?,
                flags: u32_at(bytes, offset + 36)?,
            };
            let extent = u64::from(section.virtual_size.max(section.raw_size));
            ensure!(
                section.rva >= headers
                    && extent > 0
                    && u64::from(section.rva) + extent <= u64::from(image_size),
                "invalid PE section RVA"
            );
            span(bytes, section.raw as usize, section.raw_size as usize)?;
            for old in &sections {
                ensure!(
                    !overlaps(
                        u64::from(section.rva),
                        extent,
                        u64::from(old.rva),
                        u64::from(old.virtual_size.max(old.raw_size))
                    ),
                    "overlapping PE RVA sections"
                );
                ensure!(
                    section.raw_size == 0
                        || old.raw_size == 0
                        || !overlaps(
                            u64::from(section.raw),
                            u64::from(section.raw_size),
                            u64::from(old.raw),
                            u64::from(old.raw_size)
                        ),
                    "overlapping PE raw sections"
                );
            }
            sections.push(section);
        }
        let image = Self {
            bytes,
            optional,
            pe,
            headers,
            image_size,
            base,
            entry,
            sections,
        };
        ensure!(
            entry == 0 || image.executable(entry, 1),
            "PE entry is not executable"
        );
        Ok(image)
    }
    pub fn map(&self, rva: u32, length: u32) -> Result<usize> {
        let end = u64::from(rva) + u64::from(length);
        ensure!(
            length != 0 && end <= u64::from(self.image_size),
            "invalid PE mapped span"
        );
        let mut matches = Vec::new();
        if end <= u64::from(self.headers) {
            matches.push(rva as usize);
        }
        for section in &self.sections {
            if rva >= section.rva && end <= u64::from(section.rva) + u64::from(section.raw_size) {
                let offset = u64::from(section.raw) + u64::from(rva - section.rva);
                span(self.bytes, offset as usize, length as usize)?;
                matches.push(offset as usize);
            }
        }
        ensure!(matches.len() == 1, "PE RVA lacks one raw mapping");
        Ok(matches[0])
    }
    pub fn executable(&self, rva: u32, length: u32) -> bool {
        length != 0
            && self
                .sections
                .iter()
                .filter(|section| {
                    section.flags & 0x20000000 != 0
                        && rva >= section.rva
                        && u64::from(rva) + u64::from(length)
                            <= u64::from(section.rva) + u64::from(section.raw_size)
                })
                .count()
                == 1
    }
    fn directory(&self, index: usize) -> Result<(u32, u32)> {
        ensure!(index < 16, "unsupported PE directory index");
        Ok((
            u32_at(self.bytes, self.optional + 112 + index * 8)?,
            u32_at(self.bytes, self.optional + 116 + index * 8)?,
        ))
    }
    fn text(&self, rva: u32, maximum: u32, dll: bool) -> Result<String> {
        let mut result = Vec::new();
        for index in 0..maximum {
            let at = rva
                .checked_add(index)
                .ok_or_else(|| anyhow::anyhow!("PE text RVA overflow"))?;
            let byte = self.bytes[self.map(at, 1)?];
            if byte == 0 {
                return Ok(String::from_utf8(result)?);
            }
            ensure!(
                if dll {
                    byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)
                } else {
                    (32..=126).contains(&byte)
                },
                "invalid PE text character"
            );
            result.push(byte);
        }
        anyhow::bail!("PE text lacks bounded terminator")
    }
    pub fn direct_imports(&self) -> Result<Vec<String>> {
        ensure!(
            self.directory(13)? == (0, 0),
            "PE delay imports are unsupported"
        );
        let (rva, size) = self.directory(1)?;
        ensure!(
            rva != 0 && (40..=2580).contains(&size) && size % 20 == 0,
            "invalid PE import directory shape"
        );
        let table = self.map(rva, size)?;
        let mut names = BTreeSet::new();
        for offset in (0..size as usize).step_by(20) {
            let row = span(self.bytes, table + offset, 20)?;
            if row.iter().all(|byte| *byte == 0) {
                ensure!(
                    !names.is_empty()
                        && self.bytes[table + offset + 20..table + size as usize]
                            .iter()
                            .all(|byte| *byte == 0),
                    "PE import tail is not empty"
                );
                return Ok(names.into_iter().collect());
            }
            let name = u32_at(row, 12)?;
            ensure!(
                name != 0 && u32_at(row, 16)? != 0 && names.len() < 128,
                "invalid PE import descriptor"
            );
            let text = self.text(name, 128, true)?.to_ascii_lowercase();
            ensure!(
                text.len() > 4 && text.ends_with(".dll") && names.insert(text),
                "invalid or duplicate PE import name"
            );
        }
        anyhow::bail!("PE import directory lacks terminator")
    }
    /// Rust's console verifier is a different image subject from the historical fixed C fixture.
    /// Keep executable/CLR/import-span contracts, but do not guess its toolchain DLL allowlist.
    pub fn qualify_rust_authority(&self) -> Result<()> {
        ensure!(
            self.entry != 0
                && u16_at(self.bytes, self.pe + 22)? & 0x2002 == 2
                && u16_at(self.bytes, self.optional + 68)? == 3
                && self.directory(14)? == (0, 0),
            "wrong Rust authority PE role"
        );
        self.direct_imports()?;
        Ok(())
    }
    /// Separate fixed Rust own-module ID2 role. It is not the historical Python payload.
    pub fn qualify_explicit_id2(&self) -> Result<()> {
        self.qualify_rust_authority()?;
        ensure!(
            u16_at(self.bytes, self.optional + 70)? & 0x200 != 0,
            "fixed explicit-ID2 image permits automatic isolation"
        );
        let manifest = self.manifest(2, true)?;
        ensure!(
            manifest.language == 1033
                && manifest.bytes.len() == 243
                && sha256(manifest.bytes)
                    == "34a80b2520ff37279dd9ebf0d8227f22691b7c7b80ce3d28b1e1200a3fefca27",
            "fixed explicit-ID2 manifest payload differs"
        );
        Ok(())
    }
    pub fn qualify_registry_authority(&self) -> Result<()> {
        ensure!(
            self.entry != 0
                && u16_at(self.bytes, self.pe + 22)? & 0x2002 == 2
                && u16_at(self.bytes, self.optional + 68)? == 3
                && self.directory(14)? == (0, 0),
            "wrong registry authority PE role"
        );
        let allowed = [
            "kernel32.dll",
            "ntdll.dll",
            "advapi32.dll",
            "bcrypt.dll",
            "userenv.dll",
            "ws2_32.dll",
            "api-ms-win-core-synch-l1-2-0.dll",
            "bcryptprimitives.dll",
        ];
        ensure!(
            self.direct_imports()?
                .iter()
                .all(|name| allowed.contains(&name.as_str())),
            "registry authority import profile drift"
        );
        Ok(())
    }
    pub fn kernelbase_identity(&self) -> Result<String> {
        let (rva, length) = self.directory(6)?;
        ensure!(
            rva != 0 && length >= 28 && length % 28 == 0 && length / 28 <= 64,
            "invalid debug directory"
        );
        let table = self.map(rva, length)?;
        let mut ranges = vec![(table as u64, u64::from(length))];
        let mut selected = None;
        for index in 0..(length / 28) as usize {
            let row = table + index * 28;
            ensure!(
                u32_at(self.bytes, row)? == 0,
                "debug characteristics are reserved"
            );
            let kind = u32_at(self.bytes, row + 12)?;
            let size = u32_at(self.bytes, row + 16)?;
            let address = u32_at(self.bytes, row + 20)?;
            let raw = u32_at(self.bytes, row + 24)?;
            if size == 0 {
                ensure!(
                    kind != 2 && address == 0 && raw == 0,
                    "empty debug record has data"
                );
                continue;
            }
            ensure!(raw != 0, "debug data raw offset missing");
            span(self.bytes, raw as usize, size as usize)?;
            ensure!(
                address == 0 || self.map(address, size)? == raw as usize,
                "debug RVA/raw identity differs"
            );
            ensure!(
                ranges.iter().all(|(old, length)| !overlaps(
                    u64::from(raw),
                    u64::from(size),
                    *old,
                    *length
                )),
                "debug data overlaps another record"
            );
            ranges.push((u64::from(raw), u64::from(size)));
            if kind != 2 {
                continue;
            }
            ensure!(
                selected.is_none()
                    && address != 0
                    && (25..=512).contains(&size)
                    && u32_at(self.bytes, raw as usize)? == 0x53445352,
                "invalid or duplicate CodeView record"
            );
            let guid = span(self.bytes, raw as usize + 4, 16)?;
            let age = u32_at(self.bytes, raw as usize + 20)?;
            let name = b"kernelbase.pdb\0";
            ensure!(
                guid.iter().any(|byte| *byte != 0)
                    && age != 0
                    && size as usize == 24 + name.len()
                    && span(self.bytes, raw as usize + 24, name.len())? == name,
                "CodeView GUID/age/name differs"
            );
            let guid_text = format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
                u32_at(guid, 0)?,
                u16_at(guid, 4)?,
                u16_at(guid, 6)?,
                guid[8],
                guid[9],
                guid[10..]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            selected = Some((guid_text, age));
        }
        let (guid, age) = selected.ok_or_else(|| anyhow::anyhow!("CodeView identity missing"))?;
        Ok(format!(
            "phase=image-identity module=kernelbase.dll sha256={} pdb_guid={guid} pdb_age={age} pdb_name=kernelbase.pdb pe_timestamp={} image_size={} file_size={}",
            sha256(self.bytes),
            u32_at(self.bytes, self.pe + 8)?,
            self.image_size,
            self.bytes.len()
        ))
    }
    pub fn static_slice(&self, rva: u32) -> Result<StaticSlice> {
        let preferred = u64_at(self.bytes, self.optional + 24)?;
        ensure!(
            rva != 0
                && preferred != 0
                && preferred <= 0x7fffffffffffffff - u64::from(self.image_size)
                && self.directory(14)? == (0, 0),
            "invalid static PE identity/span"
        );
        let mut spans = Vec::new();
        for section in &self.sections {
            let end =
                u64::from(section.rva) + u64::from(section.virtual_size.min(section.raw_size));
            if section.flags & 0x20000000 != 0 && rva >= section.rva && u64::from(rva) < end {
                ensure!(section.raw >= self.headers, "static PE overlaps headers");
                let length = 4096u64
                    .min(end - u64::from(rva))
                    .min(u64::from(self.image_size - rva)) as u32;
                spans.push(StaticSlice {
                    start: preferred + u64::from(rva),
                    rva,
                    length,
                    raw: self.map(rva, length)?,
                });
            }
        }
        ensure!(spans.len() == 1, "static PE needs one executable raw span");
        Ok(spans[0])
    }
    pub fn activation_worker_slice(&self) -> Result<StaticSlice> {
        ensure!(
            u16_at(self.bytes, self.pe + 22)? & 0x2002 == 0x2002,
            "activation worker must be a DLL"
        );
        let (rva, size) = self.directory(0)?;
        ensure!(
            rva >= self.headers && (40..=1048576).contains(&size),
            "invalid export directory"
        );
        let table = self.map(rva, size)?;
        ensure!(
            u32_at(self.bytes, table)? == 0,
            "export characteristics are reserved"
        );
        let functions = u32_at(self.bytes, table + 20)?;
        let names = u32_at(self.bytes, table + 24)?;
        let base = u32_at(self.bytes, table + 16)?;
        ensure!(
            (1..=4096).contains(&functions)
                && (1..=4096).contains(&names)
                && u64::from(base) + u64::from(functions) - 1 <= u64::from(u32::MAX),
            "invalid export counts"
        );
        let addresses = self.map(u32_at(self.bytes, table + 28)?, functions * 4)?;
        let pointers = self.map(u32_at(self.bytes, table + 32)?, names * 4)?;
        let ordinals = self.map(u32_at(self.bytes, table + 36)?, names * 2)?;
        let mut unique = BTreeSet::new();
        let mut selected = None;
        for index in 0..names as usize {
            let name_rva = u32_at(self.bytes, pointers + index * 4)?;
            ensure!(name_rva >= self.headers, "export name points into headers");
            let name = self.text(name_rva, 129, false)?;
            ensure!(
                !name.is_empty() && name.len() <= 128 && unique.insert(name.clone()),
                "duplicate or empty export name"
            );
            let ordinal = u16_at(self.bytes, ordinals + index * 2)?;
            ensure!(
                u32::from(ordinal) < functions,
                "export ordinal exceeds function table"
            );
            if name == "CreateActCtxWWorker" {
                selected = Some(u32_at(self.bytes, addresses + usize::from(ordinal) * 4)?);
            }
        }
        let target =
            selected.ok_or_else(|| anyhow::anyhow!("fixed activation worker export missing"))?;
        ensure!(
            target != 0 && (target < rva || u64::from(target) >= u64::from(rva) + u64::from(size)),
            "forwarded activation export refused"
        );
        self.static_slice(target)
    }
    pub fn manifest(&self, id: u32, sole: bool) -> Result<Manifest<'a>> {
        ensure!(
            matches!(id, 1 | 2) || id == 101 && sole,
            "unsupported fixed manifest resource"
        );
        let (rva, size) = self.directory(2)?;
        ensure!(
            rva != 0 && (16..=1048576).contains(&size),
            "invalid resource directory"
        );
        let root = self.map(rva, size)?;
        let mut spans = Vec::new();
        let kind = self.resource_entry(root, size, 0, 24, 128, &mut spans)?;
        ensure!(
            kind & 0x80000000 != 0 && (!sole || u16_at(self.bytes, root + 14)? == 1),
            "manifest resource type differs"
        );
        let type_offset = kind & 0x7fffffff;
        let name = self.resource_entry(root, size, type_offset, id, 16, &mut spans)?;
        ensure!(
            name & 0x80000000 != 0
                && (!sole || u16_at(self.bytes, root + type_offset as usize + 14)? == 1),
            "manifest resource ID differs"
        );
        let language_offset = name & 0x7fffffff;
        resource_span(size, language_offset, 24, &mut spans)?;
        let table = root + language_offset as usize;
        ensure!(
            u16_at(self.bytes, table + 12)? == 0 && u16_at(self.bytes, table + 14)? == 1,
            "manifest must have one numeric language"
        );
        let language = u32_at(self.bytes, table + 16)?;
        let entry = u32_at(self.bytes, table + 20)?;
        ensure!(
            language <= u32::from(u16::MAX) && entry & 0x80000000 == 0,
            "invalid manifest language entry"
        );
        resource_span(size, entry, 16, &mut spans)?;
        let data = root + entry as usize;
        let payload = u32_at(self.bytes, data)?;
        let length = u32_at(self.bytes, data + 4)?;
        ensure!(
            u32_at(self.bytes, data + 12)? == 0 && (1..=65536).contains(&length) && payload >= rva,
            "invalid manifest payload"
        );
        resource_span(size, payload - rva, length, &mut spans)?;
        let offset = self.map(payload, length)?;
        ensure!(
            offset == root + (payload - rva) as usize,
            "manifest payload has a different mapping"
        );
        Ok(Manifest {
            language: language as u16,
            bytes: span(self.bytes, offset, length as usize)?,
        })
    }
    fn resource_entry(
        &self,
        root: usize,
        size: u32,
        offset: u32,
        selected: u32,
        maximum: u16,
        spans: &mut Vec<(u32, u32)>,
    ) -> Result<u32> {
        ensure!(
            offset <= size && size - offset >= 16,
            "resource table exceeds directory"
        );
        let table = root + offset as usize;
        let count = u16_at(self.bytes, table + 14)?;
        ensure!(
            u16_at(self.bytes, table + 12)? == 0 && count > 0 && count <= maximum,
            "invalid resource table count"
        );
        resource_span(size, offset, 16 + u32::from(count) * 8, spans)?;
        let mut prior = None;
        let mut found = None;
        for index in 0..usize::from(count) {
            let id = u32_at(self.bytes, table + 16 + index * 8)?;
            ensure!(
                id <= u32::from(u16::MAX) && prior.is_none_or(|old| id > old),
                "unordered or duplicate resource ID"
            );
            prior = Some(id);
            if id == selected {
                found = Some(u32_at(self.bytes, table + 20 + index * 8)?);
            }
        }
        found.ok_or_else(|| anyhow::anyhow!("required manifest resource missing"))
    }
    pub fn require_manifest(&self, id: u32, language: u16, expected: &[u8]) -> Result<()> {
        let actual = self.manifest(id, true)?;
        ensure!(
            actual.language == language && actual.bytes == expected,
            "fixed manifest bytes or language differ"
        );
        Ok(())
    }
}
fn resource_span(size: u32, offset: u32, length: u32, spans: &mut Vec<(u32, u32)>) -> Result<()> {
    ensure!(
        offset <= size && length <= size - offset,
        "resource span exceeds directory"
    );
    ensure!(
        spans.iter().all(|(old, count)| !overlaps(
            u64::from(offset),
            u64::from(length),
            u64::from(*old),
            u64::from(*count)
        )),
        "resource structures overlap"
    );
    spans.push((offset, length));
    Ok(())
}

#[derive(Clone)]
pub struct ObservationProfile {
    pub identity: String,
    pub checkpoint: u32,
    pub image_size: u32,
    pub section: Section,
}
pub fn observation_profiles() -> [ObservationProfile; 2] {
    [
        ObservationProfile { identity: "phase=image-identity module=kernelbase.dll sha256=f4acdac5f1dc54b20c84a51ad0f507f421f5d1170e276a5a75d4e7dcf88750e2 pdb_guid=0b01ed22-aa49-026d-b0b3-95e011af2a5e pdb_age=1 pdb_name=kernelbase.pdb pe_timestamp=2900858579 image_size=4120576 file_size=4129456".into(), checkpoint: 0x39b8f8, image_size: 0x3ee000,
            section: Section { rva: 0x395000, virtual_size: 0xa368, raw: 0x395000, raw_size: 0x2000, flags: 0xc0000040 } },
        ObservationProfile { identity: "phase=image-identity module=kernelbase.dll sha256=96c0459f0d73d728e5c13a10d83d840f56913ef7281d17370a5e1eb197faa450 pdb_guid=cabdac12-ca43-8c8b-4dc4-b60b7499c804 pdb_age=1 pdb_name=kernelbase.pdb pe_timestamp=1038034819 image_size=4116480 file_size=4171392".into(), checkpoint: 0x39a7e8, image_size: 0x3ed000,
            section: Section { rva: 0x394000, virtual_size: 0xa338, raw: 0x394000, raw_size: 0x2000, flags: 0xc0000040 } },
    ]
}
pub fn select_observation(identity: &str) -> Result<ObservationProfile> {
    observation_profiles()
        .into_iter()
        .find(|profile| profile.identity == identity)
        .ok_or_else(|| anyhow::anyhow!("unsupported fixed image identity"))
}
pub fn checkpoint_address(
    sections: &[Section],
    image_size: u32,
    base: u64,
    profile: &ObservationProfile,
) -> Result<u64> {
    ensure!(
        base != 0
            && base <= 0x7fffffffffffffff - u64::from(image_size)
            && u64::from(profile.checkpoint) + 2 <= u64::from(image_size),
        "invalid checkpoint address bound"
    );
    let mut matches = 0;
    for section in sections {
        if profile.checkpoint >= section.rva
            && u64::from(profile.checkpoint) + 2
                <= u64::from(section.rva) + u64::from(section.virtual_size)
        {
            ensure!(
                *section == profile.section
                    && profile.checkpoint - section.rva >= section.raw_size
                    && u64::from(section.rva) + u64::from(section.virtual_size)
                        <= u64::from(image_size),
                "checkpoint is not the exact zero-filled profile suffix"
            );
            matches += 1;
        }
    }
    ensure!(matches == 1, "checkpoint needs one reviewed data section");
    Ok(base + u64::from(profile.checkpoint))
}
