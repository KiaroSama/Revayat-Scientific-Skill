//! Literal-byte kernel32 activation profiles. Synthetic structural fixtures never satisfy hash admission.
use super::*;
#[path = "profiles_data.rs"]
mod data;
use data::PROFILES;
#[path = "csr.rs"]
mod csr;
pub use csr::check_csr_dispatch_validation;
#[path = "boundary_checks.rs"]
mod boundary_checks;
pub use boundary_checks::check_activation_boundary_validation;
#[path = "module_callback_checks.rs"]
mod module_callback_checks;
pub use module_callback_checks::{
    check_activation_profiles, check_module_callback_profile_validation,
    qualify_module_callback_host, qualify_module_callback_path,
};
struct Symbol {
    index: u32,
    record: u32,
    hint: u16,
    name: &'static str,
}
struct Import {
    descriptor: u32,
    owner: &'static str,
    lookup: u32,
    address: u32,
    count: u32,
    symbols: &'static [Symbol],
}
struct Profile {
    identity: &'static str,
    entry: u32,
    worker: u32,
    code: &'static [u32],
    bytes: &'static [&'static str],
    edges: &'static [u32],
    target: u32,
    callback: &'static [u32],
    callback_bytes: &'static [&'static str],
    callback_edges: &'static [u32],
    short_edges: &'static [u32],
    import_directory: u32,
    null_descriptor: u32,
    imports: &'static [Import],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivationSites {
    pub worker: u32,
    pub registry: u32,
    pub funnel: u32,
    pub resource: u32,
    pub callback: u32,
    pub csr_call: u32,
    pub csr_post: u32,
    pub csr_iat: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundarySites {
    pub worker: u32,
    pub registry: u32,
    pub funnel: u32,
}
fn select(identity: &str) -> Result<&'static Profile> {
    select_nullable(Some(identity))
}
fn select_nullable(identity: Option<&str>) -> Result<&'static Profile> {
    let identity =
        identity.ok_or_else(|| anyhow::anyhow!("fixed kernel32 identity is unsupported"))?;
    PROFILES
        .iter()
        .find(|profile| profile.identity == identity)
        .ok_or_else(|| anyhow::anyhow!("fixed kernel32 identity is unsupported"))
}
fn decode(text: &str) -> Result<Vec<u8>> {
    ensure!(
        !text.is_empty()
            && text.len().is_multiple_of(2)
            && text.len() <= 30
            && text.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid fixed activation encoding"
    );
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).map_err(Into::into))
        .collect()
}
fn literal(image: &PeImage<'_>, rvas: &[u32], encodings: &[&str]) -> Result<()> {
    ensure!(
        rvas.len() == encodings.len(),
        "activation code profile shape differs"
    );
    for (&rva, encoding) in rvas.iter().zip(encodings) {
        let expected = decode(encoding)?;
        ensure!(
            image.full_executable(rva, expected.len() as u32),
            "activation code lacks one complete executable span"
        );
        let at = image.map(rva, expected.len() as u32)?;
        ensure!(
            span(image.bytes, at, expected.len())? == expected,
            "activation literal bytes differ"
        );
    }
    Ok(())
}
fn edge(image: &PeImage<'_>, rva: u32, size: usize, offset: usize, expected: u32) -> Result<()> {
    let length = size
        .checked_sub(offset)
        .ok_or_else(|| anyhow::anyhow!("invalid activation displacement"))?;
    ensure!(
        matches!(length, 1 | 4),
        "invalid activation displacement width"
    );
    let at = image.map(
        rva.checked_add(offset as u32)
            .ok_or_else(|| anyhow::anyhow!("activation displacement overflow"))?,
        length as u32,
    )?;
    let displacement = if length == 1 {
        i64::from(image.bytes[at] as i8)
    } else {
        i64::from(i32::from_le_bytes(image.bytes[at..at + 4].try_into()?))
    };
    ensure!(
        i64::from(rva) + size as i64 + displacement == i64::from(expected),
        "activation control-flow edge differs"
    );
    Ok(())
}
fn imports(image: &PeImage<'_>, import: &Import) -> Result<()> {
    let at = image.map(import.descriptor, 20)?;
    ensure!(
        u32_at(image.bytes, at)? == import.lookup
            && u32_at(image.bytes, at + 16)? == import.address
            && u32_at(image.bytes, at + 4)? == 0
            && u32_at(image.bytes, at + 8)? == 0
            && image.text(u32_at(image.bytes, at + 12)?, 64, false)? == import.owner,
        "activation import descriptor differs"
    );
    ensure!(
        import.count <= 4096,
        "activation import thunk budget exceeded"
    );
    for index in 0..=import.count {
        let value = u64_at(image.bytes, image.map(import.lookup + index * 8, 8)?)?;
        ensure!(
            value == u64_at(image.bytes, image.map(import.address + index * 8, 8)?)?
                && if index == import.count {
                    value == 0
                } else {
                    value != 0 && value <= u64::from(u32::MAX)
                },
            "activation lookup/IAT thunk differs"
        );
    }
    for item in import.symbols {
        ensure!(
            item.index < import.count
                && u64_at(image.bytes, image.map(import.lookup + item.index * 8, 8)?)?
                    == u64::from(item.record)
                && u16_at(image.bytes, image.map(item.record, 2)?)? == item.hint
                && image.text(item.record + 2, 64, false)? == item.name,
            "activation import symbol/hint differs"
        );
    }
    Ok(())
}
fn structural(image: &PeImage<'_>, profile: &Profile) -> Result<()> {
    activation_boundary_bytes(image, profile)?;
    callback_bytes(image, profile)?;
    require_worker(image, profile)
}
fn activation_boundary_bytes(image: &PeImage<'_>, profile: &Profile) -> Result<()> {
    ensure!(
        profile.code.len() == 65
            && profile.bytes.len() == 65
            && profile.edges.len() == 22
            && profile.code[10] == profile.worker,
        "activation boundary profile shape differs"
    );
    literal(image, profile.code, profile.bytes)?;
    for ((record, offset), expected) in [
        0, 7, 4, 12, 14, 17, 21, 22, 25, 27, 31, 32, 36, 38, 40, 45, 46, 52, 53, 58, 60, 64,
    ]
    .into_iter()
    .zip([
        3, 3, 1, 1, 1, 3, 1, 1, 2, 3, 2, 3, 1, 1, 3, 2, 1, 2, 3, 1, 3, 2,
    ])
    .zip(profile.edges)
    {
        edge(
            image,
            profile.code[record],
            profile.bytes[record].len() / 2,
            offset,
            *expected,
        )?;
    }
    ensure!(
        image.full_executable(profile.target, 1),
        "activation target is not executable"
    );
    image.map(profile.target, 1)?;
    Ok(())
}
fn callback_bytes(image: &PeImage<'_>, profile: &Profile) -> Result<()> {
    ensure!(
        image.entry == profile.entry
            && profile.callback.len() == 72
            && profile.callback_bytes.len() == 72
            && profile.callback_edges.len() == 7
            && profile.short_edges.len() == 11,
        "activation callback profile entry/shape differs"
    );
    literal(image, profile.callback, profile.callback_bytes)?;
    for ((record, offset), expected) in [0, 1, 2, 3, 25, 38, 62]
        .into_iter()
        .zip([3, 3, 3, 3, 1, 3, 3])
        .zip(profile.callback_edges)
    {
        edge(
            image,
            profile.callback[record],
            profile.callback_bytes[record].len() / 2,
            offset,
            *expected,
        )?;
    }
    for (record, expected) in [23, 27, 30, 41, 50, 52, 55, 56, 65, 68, 71]
        .into_iter()
        .zip(profile.short_edges)
    {
        let size = profile.callback_bytes[record].len() / 2;
        edge(image, profile.callback[record], size, size - 1, *expected)?;
    }
    ensure!(
        image.directory(1)? == (profile.import_directory, 0x834),
        "activation import directory differs"
    );
    let null = image.map(profile.null_descriptor, 20)?;
    ensure!(
        span(image.bytes, null, 20)?.iter().all(|byte| *byte == 0),
        "activation null import descriptor differs"
    );
    for import in profile.imports {
        imports(image, import)?;
    }
    Ok(())
}
fn require_worker(image: &PeImage<'_>, profile: &Profile) -> Result<()> {
    ensure!(
        image.activation_worker_slice()?.rva == profile.worker,
        "activation worker export differs"
    );
    Ok(())
}
fn activation_boundary_profile(image: &PeImage<'_>, profile: &Profile) -> Result<BoundarySites> {
    require_worker(image, profile)?;
    activation_boundary_bytes(image, profile)?;
    Ok(BoundarySites {
        worker: profile.worker,
        registry: profile.code[62],
        funnel: profile.code[13],
    })
}
// Original RequireModuleCallbackProfile order: identity is selected by the
// caller, then worker export, activation boundary, and callback. CSR dispatch
// predicates belong exclusively to dispatch_sites and are not a prerequisite.
fn module_callback_profile(image: &PeImage<'_>, profile: &Profile) -> Result<()> {
    require_worker(image, profile)?;
    activation_boundary_bytes(image, profile)?;
    callback_bytes(image, profile)
}
fn dispatch_sites(image: &PeImage<'_>, profile: &Profile) -> Result<[u32; 3]> {
    structural(image, profile)?;
    ensure!(
        profile.code[8] == profile.code[7] + 7,
        "CSR return site differs"
    );
    let import = &profile.imports[0];
    let slot = profile.edges[1];
    ensure!(
        import.owner == "ntdll.dll" && slot == import.address + 162 * 8,
        "CSR import slot differs"
    );
    let record = u64_at(image.bytes, image.map(import.lookup + 162 * 8, 8)?)?;
    ensure!(
        record != 0
            && record <= u64::from(u32::MAX - 2)
            && record == u64_at(image.bytes, image.map(slot, 8)?)?
            && image.text(record as u32 + 2, 64, false)? == "CsrClientCallServer",
        "CSR imported target differs"
    );
    ensure!(
        image
            .sections
            .iter()
            .filter(|section| section.flags & 0x40000000 != 0
                && section.flags & 0x20000000 == 0
                && slot >= section.rva
                && u64::from(slot) + 8
                    <= u64::from(section.rva)
                        + u64::from(section.virtual_size.min(section.raw_size)))
            .count()
            == 1,
        "CSR IAT is not one file-backed non-executable readable section"
    );
    Ok([profile.code[7], profile.code[8], slot])
}
impl PeImage<'_> {
    pub(super) fn full_executable(&self, rva: u32, length: u32) -> bool {
        length != 0
            && self
                .sections
                .iter()
                .filter(|section| {
                    section.flags & 0x20000000 != 0
                        && rva >= section.rva
                        && u64::from(rva) + u64::from(length)
                            <= u64::from(section.rva)
                                + u64::from(section.virtual_size.min(section.raw_size))
                })
                .count()
                == 1
    }
    pub fn kernel32_identity(&self) -> Result<String> {
        Ok(format!(
            "phase=image-identity module=kernel32.dll sha256={} pe_timestamp={} image_size={} file_size={}",
            sha256(self.bytes),
            u32_at(self.bytes, self.pe + 8)?,
            self.image_size,
            self.bytes.len()
        ))
    }
    /// Both full hash identity and every named code/import/edge predicate must match before use.
    pub fn require_activation_profile(&self) -> Result<ActivationSites> {
        let profile = select(&self.kernel32_identity()?)?;
        let [call, post, iat] = dispatch_sites(self, profile)?;
        Ok(ActivationSites {
            worker: profile.worker,
            registry: profile.code[62],
            funnel: profile.code[13],
            resource: profile.callback[39],
            callback: profile.callback[63],
            csr_call: call,
            csr_post: post,
            csr_iat: iat,
        })
    }
    /// Full cached-file identity and original worker/boundary/callback profile.
    /// This does not qualify the separate CSR-dispatch observation role.
    pub fn require_module_callback_profile(&self) -> Result<()> {
        let profile = select(&self.kernel32_identity()?)?;
        module_callback_profile(self, profile)
    }
    pub fn module_callback_site(&self) -> Result<u32> {
        self.require_module_callback_profile()?;
        Ok(select(&self.kernel32_identity()?)?.callback[63])
    }
    /// Original boundary-only qualifier. Callback/import and CSR byte products
    /// are separate roles and are not prerequisites for these three sites.
    pub fn require_activation_boundary_profile(&self) -> Result<BoundarySites> {
        activation_boundary_profile(self, select(&self.kernel32_identity()?)?)
    }
    pub fn csr_dispatch_export(&self) -> Result<u64> {
        let (rva, size) = self.directory(0)?;
        ensure!(
            rva >= self.headers && (40..=1048576).contains(&size),
            "CSR export directory differs"
        );
        let table = self.map(rva, size)?;
        let functions = u32_at(self.bytes, table + 20)?;
        let names = u32_at(self.bytes, table + 24)?;
        ensure!(
            (1..=4096).contains(&functions) && (1..=4096).contains(&names),
            "CSR export count differs"
        );
        let addresses = self.map(u32_at(self.bytes, table + 28)?, functions * 4)?;
        let pointers = self.map(u32_at(self.bytes, table + 32)?, names * 4)?;
        let ordinals = self.map(u32_at(self.bytes, table + 36)?, names * 2)?;
        let mut unique = BTreeSet::new();
        let mut uses = std::collections::BTreeMap::new();
        let mut selected = None;
        for index in 0..names as usize {
            let name_rva = u32_at(self.bytes, pointers + index * 4)?;
            ensure!(
                name_rva >= self.headers,
                "CSR export name points into headers"
            );
            let name = self.text(name_rva, 129, false)?;
            ensure!(
                !name.is_empty() && name.len() <= 128 && unique.insert(name.clone()),
                "CSR duplicate/empty export name"
            );
            let ordinal = u16_at(self.bytes, ordinals + index * 2)?;
            ensure!(
                u32::from(ordinal) < functions,
                "CSR export ordinal exceeds table"
            );
            *uses.entry(ordinal).or_insert(0usize) += 1;
            if name == "CsrClientCallServer" {
                selected = Some((
                    ordinal,
                    u32_at(self.bytes, addresses + usize::from(ordinal) * 4)?,
                ));
            }
        }
        let (ordinal, target) =
            selected.ok_or_else(|| anyhow::anyhow!("fixed CSR export absent"))?;
        ensure!(
            uses.get(&ordinal) == Some(&1)
                && target != 0
                && (target < rva || u64::from(target) >= u64::from(rva) + u64::from(size))
                && self.full_executable(target, 1),
            "CSR export alias/forwarder/non-code target refused"
        );
        Ok(self.base + u64::from(target))
    }
}
impl KernelImage<'_> {
    /// Exact subject/full-hash/worker/boundary qualification for the held image.
    pub fn require_activation_boundary_profile(&self) -> Result<BoundarySites> {
        activation_boundary_profile(&self.pe, select(&self.kernel32_identity()?)?)
    }
    /// Subject-bound original RequireModuleCallbackProfile. Call this on the
    /// same held image used by the owner; successful byte qualification alone
    /// does not attest that Windows loaded it or bind a later load event.
    pub fn require_module_callback_profile(&self) -> Result<()> {
        let profile = select(&self.kernel32_identity()?)?;
        module_callback_profile(&self.pe, profile)
    }
    pub fn module_callback_site(&self) -> Result<u32> {
        self.require_module_callback_profile()?;
        Ok(select(&self.kernel32_identity()?)?.callback[63])
    }
}
#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
