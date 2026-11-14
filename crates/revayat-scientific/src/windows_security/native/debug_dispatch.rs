//! Fixed OS-image binding and one actual stopped-process CSR IAT pointer qualification.
use super::*;
use crate::windows_security::{
    activation::diagnostics::{self, Numbers, Stage},
    activation::dispatch::{DispatchRegion, DispatchTarget},
    image::ActivationSites,
    sxs::ordinal_path_equal,
};
use std::{
    io::Seek,
    os::windows::io::{FromRawHandle, IntoRawHandle},
    path::PathBuf,
};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFinalPathNameByHandleW(file: Handle, text: *mut u16, capacity: u32, flags: u32) -> u32;
    fn GetSystemDirectoryW(text: *mut u16, capacity: u32) -> u32;
    fn ReadProcessMemory(
        process: Handle,
        address: Handle,
        bytes: Handle,
        length: usize,
        returned: *mut usize,
    ) -> i32;
}
struct Kernel {
    base: u64,
    sites: ActivationSites,
}
pub(super) struct DispatchImages {
    kernel: Option<Kernel>,
    ntdll: Option<(u64, u64)>,
    armed: bool,
    target: DispatchTarget,
    pub target_equal: bool,
}
impl DispatchImages {
    pub fn new() -> Self {
        Self {
            kernel: None,
            ntdll: None,
            armed: false,
            target: DispatchTarget::default(),
            target_equal: false,
        }
    }
    pub fn load(&mut self, process: Handle, file: Handle, base: u64) -> Result<Option<[u64; 2]>> {
        let Some((name, mut bytes)) = system_image(file)
            .map_err(|error| diagnostics::at(error, Stage::DebugSystemIdentity))?
        else {
            return Ok(None);
        };
        let result = (|| {
            let image = PeImage::parse(&bytes, base)?;
            match name.as_str() {
                "kernel32.dll" => {
                    ensure!(self.kernel.is_none(), "CSR kernel32 load repeated");
                    let sites = image
                        .require_activation_profile()
                        .map_err(|error| diagnostics::at(error, Stage::DebugKernelProfile))?;
                    executable(process, base, sites.csr_call, 7)
                        .map_err(|error| diagnostics::at(error, Stage::DebugExecutable))?;
                    executable(process, base, sites.csr_post, 5)
                        .map_err(|error| diagnostics::at(error, Stage::DebugExecutable))?;
                    self.kernel = Some(Kernel { base, sites });
                }
                "ntdll.dll" => {
                    ensure!(self.ntdll.is_none(), "CSR ntdll load repeated");
                    let target = image
                        .csr_dispatch_export()
                        .map_err(|error| diagnostics::at(error, Stage::DebugNtdllExport))?;
                    executable(process, base, (target - base) as u32, 1)
                        .map_err(|error| diagnostics::at(error, Stage::DebugExecutable))?;
                    self.ntdll = Some((base, target));
                }
                _ => anyhow::bail!("unsupported CSR image role"),
            }
            if !self.armed
                && let (Some(kernel), Some(_)) = (&self.kernel, &self.ntdll)
            {
                self.armed = true;
                return Ok(Some([
                    kernel.base + u64::from(kernel.sites.csr_call),
                    kernel.base + u64::from(kernel.sites.csr_post),
                ]));
            }
            Ok(None)
        })();
        bytes.fill(0);
        result.map_err(|error| diagnostics::at(error, Stage::DebugDispatchLoad))
    }
    pub fn require_unload(&self, base: u64) -> Result<()> {
        ensure!(
            self.kernel.as_ref().is_none_or(|image| image.base != base)
                && self.ntdll.is_none_or(|(image, _)| image != base),
            "CSR observed system image unloaded"
        );
        Ok(())
    }
    pub fn require_target(&mut self, process: Handle) -> Result<()> {
        let kernel = self
            .kernel
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("CSR kernel image absent"))?;
        let (_, expected) = self
            .ntdll
            .ok_or_else(|| anyhow::anyhow!("CSR ntdll image absent"))?;
        let address = kernel.base + u64::from(kernel.sites.csr_iat);
        self.target
            .read(
                address,
                kernel.base,
                expected,
                || {
                    let region = query(process, address)?;
                    let view = DispatchRegion {
                        address: region.address as u64,
                        allocation: region.allocation as u64,
                        size: region.size as u64,
                        state: region.state,
                        kind: region.kind,
                        protect: region.protect,
                    };
                    ensure!(
                        view.readable(address, kernel.base),
                        diagnostics::native(
                            Stage::DebugDispatchRegion,
                            Numbers {
                                result: Some(region.state),
                                properties: Some(region.protect),
                                count: Some(region.kind),
                                ..Default::default()
                            }
                        )
                    );
                    Ok(view)
                },
                |bytes| {
                    let mut returned = 0;
                    let success = unsafe {
                        ReadProcessMemory(
                            process,
                            address as Handle,
                            bytes.as_mut_ptr().cast(),
                            8,
                            &mut returned,
                        )
                    };
                    let error = if success == 0 {
                        unsafe { GetLastError() }
                    } else {
                        0
                    };
                    if success == 0 {
                        return Err(diagnostics::native(
                            Stage::DebugDispatchTarget,
                            Numbers {
                                native_error: Some(error),
                                count: Some(returned as u32),
                                ..Default::default()
                            },
                        ));
                    }
                    ensure!(
                        returned == 8,
                        diagnostics::native(
                            Stage::DebugDispatchLength,
                            Numbers {
                                count: Some(returned as u32),
                                ..Default::default()
                            }
                        )
                    );
                    ensure!(
                        u64::from_le_bytes(*bytes) == expected,
                        diagnostics::native(Stage::DebugDispatchPointer, Numbers::default())
                    );
                    Ok(returned)
                },
            )
            .map_err(|error| diagnostics::at(error, Stage::DebugDispatchTarget))?;
        self.target_equal = true;
        Ok(())
    }
}
fn query(process: Handle, address: u64) -> Result<Region> {
    let mut region = Region::default();
    let returned = unsafe {
        abi::VirtualQueryEx(process, address as Handle, &mut region, size_of::<Region>())
    };
    if returned != size_of::<Region>() {
        let error = unsafe { GetLastError() };
        return Err(diagnostics::native(
            Stage::DebugExecutable,
            Numbers {
                native_error: Some(error),
                bytes: Some(returned as u32),
                ..Default::default()
            },
        ));
    }
    Ok(region)
}
fn executable(process: Handle, base: u64, rva: u32, length: u64) -> Result<()> {
    let address = base + u64::from(rva);
    let region = query(process, address)?;
    ensure!(
        region.state == 0x1000
            && region.kind == 0x1000000
            && region.allocation as u64 == base
            && address >= region.address as u64
            && address - region.address as u64 <= region.size as u64
            && length <= region.size as u64 - (address - region.address as u64)
            && region.protect & 0x100 == 0
            && matches!(region.protect & 0xff, 0x10 | 0x20 | 0x40 | 0x80),
        "CSR code region is not the owned executable image"
    );
    Ok(())
}
fn system_image(raw: Handle) -> Result<Option<(String, Vec<u8>)>> {
    if raw.is_null() || raw as usize == usize::MAX {
        return Ok(None);
    }
    let mut path = [0u16; 32768];
    let length = unsafe { GetFinalPathNameByHandleW(raw, path.as_mut_ptr(), 32768, 0) };
    let error = if length == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    ensure!(
        (1..32768).contains(&length),
        "CSR load event path query failed winerror={error}"
    );
    let text = String::from_utf16(&path[..length as usize])?;
    let plain = text
        .strip_prefix(r"\\?\")
        .ok_or_else(|| anyhow::anyhow!("CSR load event path is not canonical DOS"))?;
    let path = PathBuf::from(plain);
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow::anyhow!("CSR image leaf encoding differs"))?
        .to_ascii_lowercase();
    if !matches!(name.as_str(), "kernel32.dll" | "ntdll.dll") {
        return Ok(None);
    }
    let mut system = [0u16; 32768];
    let count = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), 32768) };
    ensure!(
        (3..32768).contains(&count),
        "CSR system directory query failed"
    );
    let expected = PathBuf::from(String::from_utf16(&system[..count as usize])?).join(&name);
    ensure!(
        ordinal_path_equal(
            plain,
            expected
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("CSR expected system path encoding differs"))?
        )?,
        "CSR fixed system image came from another path"
    );
    plain_path(&expected)?;
    let mut file = unsafe { std::fs::File::from_raw_handle(duplicate(raw)?) };
    let result = (|| {
        let id = identity::object_id(&file)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && (256..=16 * 1024 * 1024).contains(&metadata.len())
                && identity::path_object_id(&expected)? == id,
            "CSR system file identity/length differs"
        );
        file.rewind()?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == metadata.len(),
            "CSR system file length changed"
        );
        let current = identity::file_identity(&expected, Some(16 * 1024 * 1024))?;
        ensure!(
            current.identity == id && current.sha256 == sha256(&bytes),
            "CSR system event bytes differ from fixed path"
        );
        Ok(Some((name, bytes)))
    })();
    let cleanup = close(file.into_raw_handle());
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Err(first), Err(second)) => Err(Failures {
            errors: vec![first, second],
        }
        .into()),
        (Ok(_), Err(error)) => Err(error),
    }
}
