//! Fixed default/module image roles; imports are inspected, never loaded or resolved.
use super::*;
const HOST: &[&str] = &["ExitProcess", "GetStdHandle", "WriteFile"];
const DLL: &[&str] = &[
    "CompareStringOrdinal",
    "GetLastError",
    "GetModuleFileNameW",
    "QueryActCtxW",
];
impl PeImage<'_> {
    pub fn qualify_python_imports(&self, label: &str) -> Result<usize> {
        let expected: &[&str] = match label {
            "python-exe" => &["kernel32.dll", "python311.dll", "vcruntime140.dll"],
            "python311" => &[
                "advapi32.dll",
                "bcrypt.dll",
                "kernel32.dll",
                "vcruntime140.dll",
                "version.dll",
                "ws2_32.dll",
            ],
            "vcruntime140" => &["kernel32.dll"],
            _ => anyhow::bail!("unsupported fixed Python import profile"),
        };
        let names = self.direct_imports()?;
        let physical: BTreeSet<_> = names
            .iter()
            .filter(|name| !name.starts_with("api-ms-win-"))
            .map(String::as_str)
            .collect();
        ensure!(
            physical == expected.iter().copied().collect(),
            "fixed Python physical import profile differs"
        );
        Ok(names.len() - physical.len())
    }
    pub fn qualify_default_activation(&self, language: u16, payload: &[u8]) -> Result<()> {
        self.activation_role(false, true)?;
        let (rva, size) = self.directory(1)?;
        ensure!(
            rva != 0 && (40..=128).contains(&size),
            "fixed activation import directory differs"
        );
        let table = self.map(rva, size)?;
        let name = self.activation_descriptor(table, HOST)?;
        ensure!(
            name.eq_ignore_ascii_case("KERNEL32.dll")
                && self.bytes[table + 20..table + size as usize]
                    .iter()
                    .all(|byte| *byte == 0),
            "fixed activation import owner or tail differs"
        );
        self.require_manifest(1, language, payload)
    }
    pub fn qualify_module_activation(
        &self,
        dll: bool,
        manifest: bool,
        language: u16,
        payload: &[u8],
    ) -> Result<()> {
        ensure!(
            !manifest || dll,
            "fixed module host cannot carry DLL manifest"
        );
        self.activation_role(dll, manifest)?;
        let (rva, size) = self.directory(1)?;
        let descriptors = if dll { 1 } else { 2 };
        ensure!(
            rva != 0 && (if dll { 40 } else { 60 }..=128).contains(&size),
            "fixed module import directory differs"
        );
        let table = self.map(rva, size)?;
        let mut owners = BTreeSet::new();
        for row in 0..descriptors {
            let descriptor = table + row * 20;
            let owner = self.text(u32_at(self.bytes, descriptor + 12)?, 64, false)?;
            let expected = if owner.eq_ignore_ascii_case("KERNEL32.dll") {
                if dll { DLL } else { HOST }
            } else {
                ensure!(
                    !dll && owner == "startup-module.dll",
                    "fixed module import owner differs"
                );
                &["ObserveModuleActivation"]
            };
            self.activation_descriptor(descriptor, expected)?;
            ensure!(
                owners.insert(owner.to_ascii_lowercase()),
                "fixed module import owner is duplicated"
            );
        }
        ensure!(
            owners.contains("kernel32.dll")
                && (dll || owners.contains("startup-module.dll"))
                && self.bytes[table + descriptors * 20..table + size as usize]
                    .iter()
                    .all(|byte| *byte == 0),
            "fixed module import inventory or tail differs"
        );
        if dll {
            self.module_export()?;
        }
        if manifest {
            self.require_manifest(2, language, payload)?;
        }
        Ok(())
    }
    pub(super) fn activation_role(&self, dll: bool, manifest: bool) -> Result<()> {
        ensure!(
            self.bytes.len() <= 1048576
                && self.entry != 0
                && u16_at(self.bytes, self.pe + 22)? & 0x2002 == if dll { 0x2002 } else { 2 }
                && u16_at(self.bytes, self.optional + 68)? == 3,
            "fixed activation executable role differs"
        );
        for directory in [0, 2, 9, 13, 14] {
            if directory == 0 && dll || directory == 2 && manifest {
                continue;
            }
            ensure!(
                self.directory(directory)? == (0, 0),
                "fixed activation has an unsupported directory"
            );
        }
        Ok(())
    }
    pub(super) fn activation_descriptor(&self, row: usize, expected: &[&str]) -> Result<String> {
        let lookup = u32_at(self.bytes, row)?;
        let owner = u32_at(self.bytes, row + 12)?;
        let address = u32_at(self.bytes, row + 16)?;
        ensure!(
            lookup != 0
                && owner != 0
                && address != 0
                && u32_at(self.bytes, row + 4)? == 0
                && u32_at(self.bytes, row + 8)? == 0,
            "fixed activation descriptor differs"
        );
        let mut names = BTreeSet::new();
        for index in 0..=expected.len() {
            let offset = u32::try_from(index * 8)?;
            let left = lookup
                .checked_add(offset)
                .ok_or_else(|| anyhow::anyhow!("fixed activation thunk overflow"))?;
            let right = address
                .checked_add(offset)
                .ok_or_else(|| anyhow::anyhow!("fixed activation thunk overflow"))?;
            let symbol = u64_at(self.bytes, self.map(left, 8)?)?;
            ensure!(
                symbol == u64_at(self.bytes, self.map(right, 8)?)?,
                "fixed activation import tables differ"
            );
            if symbol == 0 {
                ensure!(
                    index == expected.len()
                        && names == expected.iter().map(|name| (*name).to_owned()).collect(),
                    "fixed activation import symbols differ"
                );
                return self.text(owner, 64, false);
            }
            ensure!(
                index < expected.len() && symbol <= u64::from(u32::MAX - 2),
                "fixed activation ordinal or symbol bound differs"
            );
            self.map(symbol as u32, 2)?;
            ensure!(
                names.insert(self.text(symbol as u32 + 2, 64, false)?),
                "fixed activation symbol is duplicated"
            );
        }
        anyhow::bail!("fixed activation imports lack terminator")
    }
    fn module_export(&self) -> Result<()> {
        let (rva, size) = self.directory(0)?;
        ensure!(
            rva != 0 && (40..=4096).contains(&size),
            "fixed module export directory differs"
        );
        let table = self.map(rva, size)?;
        ensure!(
            self.text(u32_at(self.bytes, table + 12)?, 64, false)? == "startup-module.dll"
                && u32_at(self.bytes, table + 20)? == 1
                && u32_at(self.bytes, table + 24)? == 1,
            "fixed module export inventory differs"
        );
        let function = u32_at(self.bytes, self.map(u32_at(self.bytes, table + 28)?, 4)?)?;
        let name = u32_at(self.bytes, self.map(u32_at(self.bytes, table + 32)?, 4)?)?;
        ensure!(
            u16_at(self.bytes, self.map(u32_at(self.bytes, table + 36)?, 2)?)? == 0
                && self.text(name, 64, false)? == "ObserveModuleActivation"
                && self.executable(function, 1)
                && (function < rva || u64::from(function) >= u64::from(rva) + u64::from(size)),
            "fixed module export target differs"
        );
        Ok(())
    }
}
