//! Counted, read-only Windows discovery. Environment values never select the Windows/SDK roots.
use super::{Numbers, Stage, diagnostics};
use anyhow::{Result, ensure};
use std::{ffi::c_void, path::PathBuf, ptr};
#[repr(C)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(
        id: *const Guid,
        flags: u32,
        token: *mut c_void,
        path: *mut *mut u16,
    ) -> i32;
}
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemFree(value: *mut c_void);
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetWindowsDirectoryW(path: *mut u16, length: u32) -> u32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegGetValueW(
        key: *mut c_void,
        subkey: *const u16,
        value: *const u16,
        flags: u32,
        kind: *mut u32,
        data: *mut c_void,
        bytes: *mut u32,
    ) -> i32;
}
fn folder(id: Guid, stage: Stage) -> Result<PathBuf> {
    struct Allocated(*mut u16);
    impl Drop for Allocated {
        fn drop(&mut self) {
            unsafe { CoTaskMemFree(self.0.cast()) }
        }
    }
    let mut allocated = Allocated(ptr::null_mut());
    // The OS returns an allocated NUL-terminated known-folder string; its owner
    // is installed before checking HRESULT or decoding the counted prefix.
    let result = unsafe { SHGetKnownFolderPath(&id, 0, ptr::null_mut(), &mut allocated.0) };
    let parsed = (|| {
        ensure!(
            result == 0 && !allocated.0.is_null(),
            "fixed Windows known-folder discovery failed result={result}"
        );
        let mut length = 0;
        while length < 32768 && unsafe { *allocated.0.add(length) } != 0 {
            length += 1;
        }
        ensure!(
            (1..32768).contains(&length),
            "fixed Windows known-folder length differs"
        );
        let units = unsafe { std::slice::from_raw_parts(allocated.0, length) };
        Ok(PathBuf::from(String::from_utf16(units)?))
    })();
    parsed.map_err(|error| {
        diagnostics::annotate(
            error,
            stage,
            Numbers {
                result: Some(result as u32),
                ..Default::default()
            },
        )
    })
}

pub(super) fn program_files_x86() -> Result<PathBuf> {
    folder(
        Guid {
            a: 0x7c5a40ef,
            b: 0xa0fb,
            c: 0x4bfc,
            d: [0x87, 0x4a, 0xc0, 0xf2, 0xe0, 0xb9, 0xfa, 0x8e],
        },
        Stage::FixtureProgramFiles,
    )
}
pub(super) fn profile() -> Result<PathBuf> {
    folder(
        Guid {
            a: 0x5e6c858f,
            b: 0x0e22,
            c: 0x4760,
            d: [0x9a, 0xfe, 0xea, 0x33, 0x17, 0xb6, 0x71, 0x73],
        },
        Stage::FixtureRustupRoot,
    )
}
pub(super) fn system_root() -> Result<PathBuf> {
    let mut path = [0u16; 32768];
    let length = unsafe { GetWindowsDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
    let native_error =
        (length == 0).then(|| unsafe { windows_sys::Win32::Foundation::GetLastError() });
    let parsed = (|| {
        ensure!(
            (3..path.len()).contains(&length),
            "fixed Windows directory discovery failed"
        );
        Ok(PathBuf::from(String::from_utf16(&path[..length])?))
    })();
    parsed.map_err(|error| {
        diagnostics::annotate(
            error,
            Stage::FixtureWindowsRoot,
            Numbers {
                native_error,
                count: u32::try_from(length).ok(),
                ..Default::default()
            },
        )
    })
}

pub(super) fn sdk_root() -> Result<PathBuf> {
    let key = "SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots\0"
        .encode_utf16()
        .collect::<Vec<_>>();
    let value = "KitsRoot10\0".encode_utf16().collect::<Vec<_>>();
    let mut data = [0u16; 32768];
    let mut bytes = std::mem::size_of_val(&data) as u32;
    let mut kind = 0;
    // Predefined borrowed HKLM, fixed 64-bit view, exact REG_SZ; no key handle is acquired.
    let result = unsafe {
        RegGetValueW(
            (0x80000002u32 as i32 as isize) as *mut c_void,
            key.as_ptr(),
            value.as_ptr(),
            0x10002,
            &mut kind,
            data.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    let parsed = (|| {
        ensure!(
            result == 0
                && kind == 1
                && bytes >= 4
                && bytes as usize <= std::mem::size_of_val(&data)
                && bytes.is_multiple_of(2),
            "fixed Windows SDK root discovery failed result={result}"
        );
        let units = &data[..bytes as usize / 2];
        ensure!(
            units.last() == Some(&0) && !units[..units.len() - 1].contains(&0),
            "fixed SDK root is not one terminated path"
        );
        Ok(PathBuf::from(String::from_utf16(
            &units[..units.len() - 1],
        )?))
    })();
    parsed.map_err(|error| {
        diagnostics::annotate(
            error,
            Stage::FixtureSdkRoot,
            Numbers {
                native_error: (result != 0).then_some(result as u32),
                result: Some(result as u32),
                bytes: Some(bytes),
                properties: Some(kind),
                ..Default::default()
            },
        )
    })
}
