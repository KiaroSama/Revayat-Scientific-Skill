//! Fixed read-only measurements AFTER failed startup. No retry, provider load or policy change.
use crate::{
    native::{CloseHandle, GetLastError, Raw},
    protocol::NetworkDiagnostic,
};
use std::{ffi::c_void, ptr::null_mut};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentThread() -> Raw;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenThreadToken(thread: Raw, access: u32, as_self: i32, token: *mut Raw) -> i32;
    fn RegOpenKeyExW(
        root: Raw,
        name: *const u16,
        options: u32,
        access: u32,
        output: *mut Raw,
    ) -> i32;
    fn RegCloseKey(key: Raw) -> i32;
}
#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSCEnumProtocols(
        protocols: *const i32,
        output: *mut c_void,
        bytes: *mut u32,
        error: *mut i32,
    ) -> i32;
}
fn token_valid(raw: Raw) -> bool {
    !raw.is_null() && !matches!(raw as isize, -1 | -2)
}
fn key_valid(raw: Raw) -> bool {
    token_valid(raw) && !((-2_147_483_648..=-2_147_483_641).contains(&(raw as isize)))
}
pub(super) fn measure(immediate_error: u32) -> Option<NetworkDiagnostic> {
    let mut values = [0u32; NetworkDiagnostic::WORDS];
    values[0] = 1;
    values[1] = 0x0101;
    values[2] = immediate_error;
    let mut token = null_mut();
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), 8, 1, &mut token) };
    values[3] = if opened == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    if opened != 0 {
        values[5] |= 0x2000_0000;
    }
    if token_valid(token) {
        values[5] |= 0x8000_0000;
        let closed = unsafe { CloseHandle(token) };
        values[4] = if closed == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        if closed != 0 {
            values[5] |= 0x4000_0000;
        }
    }
    // Each path/mask is a closed constant. No catalog contents, provider path or user data leaves.
    const KEYS: [&str; 3] = [
        r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters",
        r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9",
        r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5",
    ];
    let root = (-2_147_483_646isize) as Raw;
    for (key_index, name) in KEYS.iter().enumerate() {
        let name = crate::native::wide(name);
        for (mask_index, access) in [0x101, 0x20119].into_iter().enumerate() {
            let index = key_index * 2 + mask_index;
            let mut key = null_mut();
            values[6 + index] =
                unsafe { RegOpenKeyExW(root, name.as_ptr(), 0, access, &mut key) } as u32;
            // Own any real partial output independently of the LSTATUS. Predefined handles are borrowed.
            if key_valid(key) {
                values[5] |= 1 << index;
                values[12 + index] = unsafe { RegCloseKey(key) } as u32;
            }
        }
    }
    let mut bytes = 0;
    let mut error = 0;
    values[18] =
        unsafe { WSCEnumProtocols(std::ptr::null(), null_mut(), &mut bytes, &mut error) } as u32;
    values[19] = error as u32;
    values[20] = bytes;
    // All structural values above are fixed constants; the remaining words are actual API outputs.
    NetworkDiagnostic::measured(values)
}
