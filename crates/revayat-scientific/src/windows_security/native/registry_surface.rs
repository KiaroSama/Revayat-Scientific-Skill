//! Read-only SideBySide inventory adapter. No key selector or registry contents are exported.
use super::{Attributes, KEY, Name, NtClose, valid};
use crate::windows_security::policy::registry_comparison::surface::{
    self, Information, Snapshot, SurfaceIo, Value,
};
use anyhow::{Result, ensure};
use std::{
    ffi::c_void,
    mem::size_of,
    ptr::null_mut,
    time::{Duration, Instant},
};
type Handle = *mut c_void;
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenKeyEx(
        key: *mut Handle,
        access: u32,
        attributes: *const Attributes,
        options: u32,
    ) -> i32;
    fn NtQueryKey(
        key: Handle,
        kind: u32,
        data: *mut c_void,
        capacity: u32,
        returned: *mut u32,
    ) -> i32;
    fn NtQuerySecurityObject(
        key: Handle,
        information: u32,
        data: *mut c_void,
        capacity: u32,
        returned: *mut u32,
    ) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegQueryInfoKeyW(
        key: Handle,
        class: *mut u16,
        class_len: *mut u32,
        reserved: *mut u32,
        subkeys: *mut u32,
        max_subkey: *mut u32,
        max_class: *mut u32,
        values: *mut u32,
        max_name: *mut u32,
        max_value: *mut u32,
        security: *mut u32,
        modified: *mut i64,
    ) -> i32;
    fn RegEnumValueW(
        key: Handle,
        index: u32,
        name: *mut u16,
        length: *mut u32,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        bytes: *mut u32,
    ) -> i32;
    fn RegEnumKeyExW(
        key: Handle,
        index: u32,
        name: *mut u16,
        length: *mut u32,
        reserved: Handle,
        class: Handle,
        class_length: Handle,
        time: Handle,
    ) -> i32;
}
struct NativeSurface {
    key: Handle,
    clock: Instant,
    closed: bool,
}
impl NativeSurface {
    fn open() -> Result<Self> {
        crate::windows_security::activation::native::require_host()?;
        let mut io = Self {
            key: null_mut(),
            clock: Instant::now(),
            closed: false,
        };
        let opened = (|| {
            ensure!(
                size_of::<Name>() == 16 && size_of::<Attributes>() == 48,
                "registry surface requires x64 ABI"
            );
            let text = KEY.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let name = Name {
                length: 140,
                maximum: 142,
                buffer: text.as_ptr(),
            };
            let attributes = Attributes {
                length: 48,
                root: null_mut(),
                name: &name,
                flags: 0x1040,
                descriptor: null_mut(),
                qos: null_mut(),
            };
            // SAFETY: fixed counted UTF-16 and object attributes remain live. No writable key rights.
            let status = unsafe { NtOpenKeyEx(&mut io.key, 0x20019, &attributes, 0) };
            ensure!(
                status == 0 && valid(io.key),
                "fixed registry surface key could not be opened"
            );
            let mut basic = [0u64; 7];
            let mut returned = 0;
            // SAFETY: retained fixed key and aligned exact 56-byte native output storage.
            let status = unsafe {
                registry_authority::native::NtQueryObject(
                    io.key,
                    0,
                    basic.as_mut_ptr().cast(),
                    56,
                    &mut returned,
                )
            };
            ensure!(
                registry_authority::protocol::basic(
                    status as u32,
                    returned,
                    basic[0] as u32,
                    (basic[0] >> 32) as u32
                ),
                "fixed registry surface rights differ"
            );
            let mut data = [0u32; 1024];
            // SAFETY: retained key, aligned 4096-byte query buffer, returned controls all reads.
            let status =
                unsafe { NtQueryKey(io.key, 3, data.as_mut_ptr().cast(), 4096, &mut returned) };
            ensure!(
                status == 0 && (144..=4096).contains(&returned) && data[0] == 140,
                "fixed registry surface name query failed"
            );
            let bytes = unsafe {
                std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), returned as usize)
            };
            let units = bytes[4..144]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>();
            ensure!(
                String::from_utf16(&units)?.eq_ignore_ascii_case(KEY),
                "fixed registry surface identity differs"
            );
            Ok(())
        })();
        if let Err(primary) = opened {
            return crate::runtime::with_cleanup(Err(primary), io.close())
                .map_err(surface::sanitize);
        }
        Ok(io)
    }
    fn live(&self) -> Result<()> {
        ensure!(
            !self.closed && valid(self.key),
            "registry surface key is closed"
        );
        Ok(())
    }
}
impl SurfaceIo for NativeSurface {
    fn information(&mut self) -> Result<Information> {
        self.live()?;
        let (mut values, mut subkeys, mut modified) = (0, 0, 0);
        // SAFETY: exact writable scalar outputs; all optional output pointers are null.
        let status = unsafe {
            RegQueryInfoKeyW(
                self.key,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut subkeys,
                null_mut(),
                null_mut(),
                &mut values,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut modified,
            )
        };
        ensure!(
            status == 0,
            "fixed registry surface information failed winerror={status}"
        );
        Ok(Information {
            values,
            subkeys,
            modified,
        })
    }
    fn value(&mut self, index: u32) -> Result<Option<Value>> {
        self.live()?;
        let mut name = vec![0u16; 512];
        let (mut length, mut kind, mut bytes) = (512, 0, 4096);
        let mut data = vec![0u8; 4096];
        // SAFETY: all buffers exactly match their supplied capacities and remain live for the call.
        let status = unsafe {
            RegEnumValueW(
                self.key,
                index,
                name.as_mut_ptr(),
                &mut length,
                null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut bytes,
            )
        };
        if status == 259 {
            data.fill(0);
            name.fill(0);
            return Ok(None);
        }
        if status != 0 || length >= 512 || bytes > 4096 {
            data.fill(0);
            name.fill(0);
            anyhow::bail!("fixed registry value enumeration failed or exceeded bounds");
        }
        name.truncate(length as usize);
        data.truncate(bytes as usize);
        Ok(Some(Value { name, kind, data }))
    }
    fn subkey(&mut self, index: u32) -> Result<Option<Vec<u16>>> {
        self.live()?;
        let mut name = vec![0u16; 512];
        let mut length = 512;
        // SAFETY: counted UTF-16 output and null optional class/time outputs.
        let status = unsafe {
            RegEnumKeyExW(
                self.key,
                index,
                name.as_mut_ptr(),
                &mut length,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if status == 259 {
            name.fill(0);
            return Ok(None);
        }
        if status != 0 || length >= 512 {
            name.fill(0);
            anyhow::bail!("fixed registry subkey enumeration failed or exceeded bounds");
        }
        name.truncate(length as usize);
        Ok(Some(name))
    }
    fn descriptor(&mut self) -> Result<Vec<u8>> {
        self.live()?;
        let mut descriptor = vec![0u8; 65536];
        let mut returned = 0;
        // SAFETY: exact capacity and valid retained key; OWNER|GROUP|DACL|LABEL only.
        let status = unsafe {
            NtQuerySecurityObject(
                self.key,
                0x17,
                descriptor.as_mut_ptr().cast(),
                65536,
                &mut returned,
            )
        };
        if status != 0 || !(20..=65536).contains(&returned) {
            descriptor.fill(0);
            anyhow::bail!("fixed registry surface descriptor query failed");
        }
        descriptor.truncate(returned as usize);
        Ok(descriptor)
    }
    fn deadline(&mut self) -> Result<()> {
        if self.clock.elapsed() > Duration::from_secs(10) {
            return Err(crate::runtime::DeadlineExceeded {
                idle: false,
                limit: Duration::from_secs(10),
            }
            .into());
        }
        Ok(())
    }
    fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let handle = std::mem::replace(&mut self.key, null_mut());
        if valid(handle) {
            let status = unsafe { NtClose(handle) };
            ensure!(
                status == 0,
                "fixed registry surface key close failed status={:08X}",
                status as u32
            );
        }
        Ok(())
    }
}
impl Drop for NativeSurface {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
pub fn read_surface() -> Result<Snapshot> {
    surface::read(&mut NativeSurface::open()?)
}
