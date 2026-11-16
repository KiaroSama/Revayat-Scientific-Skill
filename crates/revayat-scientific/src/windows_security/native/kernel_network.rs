//! Four Winsock denials, or exact catalog refusal plus four host-qualified AFD denials.
use super::super::ffi::{Raw, combine, note_cleanup_failure, wide};
use crate::windows_security::{
    kernel_controls::KernelPlan,
    sxs::{native_file_abi::NtCreateFile, storage::creation::IoStatus as IoStatusBlock},
};
use anyhow::{Result, ensure};
use registry_authority::native::{
    Attributes as ObjectAttributes, NtClose, Unicode as UnicodeString,
};
use std::{
    ffi::c_void,
    mem::{offset_of, size_of, zeroed},
    ptr::{null, null_mut},
};
#[repr(C)]
struct Address4 {
    family: u16,
    port: u16,
    address: [u8; 4],
    zero: [u8; 8],
}
#[repr(C)]
struct Address6 {
    family: u16,
    port: u16,
    flow: u32,
    address: [u8; 16],
    scope: u32,
}
#[repr(C)]
struct WsaData {
    version: u16,
    high: u16,
    max_sockets: u16,
    max_udp: u16,
    vendor: *mut u8,
    description: [u8; 257],
    status: [u8; 129],
}
#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAStartup(version: u16, data: *mut WsaData) -> i32;
    fn WSACleanup() -> i32;
    fn WSAGetLastError() -> i32;
    fn socket(family: i32, kind: i32, protocol: i32) -> usize;
    fn closesocket(socket: usize) -> i32;
    fn ioctlsocket(socket: usize, command: i32, value: *mut u32) -> i32;
    fn setsockopt(socket: usize, level: i32, option: i32, value: *const u8, length: i32) -> i32;
    fn connect(socket: usize, address: *const c_void, length: i32) -> i32;
    fn sendto(
        socket: usize,
        bytes: *const u8,
        length: i32,
        flags: i32,
        address: *const c_void,
        address_length: i32,
    ) -> i32;
}
struct Socket(usize);
impl Socket {
    fn close(&mut self) -> Result<()> {
        if self.0 == usize::MAX {
            return Ok(());
        }
        let raw = std::mem::replace(&mut self.0, usize::MAX);
        ensure!(
            unsafe { closesocket(raw) } == 0,
            "kernel Winsock socket close failed"
        );
        Ok(())
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        if self.close().is_err() {
            note_cleanup_failure();
        }
    }
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(root: Raw, name: *const u16, options: u32, access: u32, out: *mut Raw) -> i32;
    fn RegCloseKey(key: Raw) -> i32;
}
fn require_catalog_denial() -> Result<()> {
    for path in [
        r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters",
        r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9",
        r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5",
    ] {
        let name = wide(path);
        for access in [0x101, 0x20119] {
            let mut key = null_mut();
            // SAFETY: borrowed HKLM pseudo-handle, fixed NUL-terminated path and writable output.
            let status = unsafe {
                RegOpenKeyExW(
                    (-2_147_483_646isize) as Raw,
                    name.as_ptr(),
                    0,
                    access,
                    &mut key,
                )
            };
            let mut closed = 0;
            if !key.is_null() {
                // SAFETY: close any unexpected owned registry output before refusing the control.
                closed = unsafe { RegCloseKey(key) };
            }
            let denied = status == 5 && key.is_null();
            ensure!(closed == 0, "kernel Winsock catalog handle close failed");
            ensure!(denied, "kernel Winsock catalog was not access-denied");
        }
    }
    Ok(())
}
fn afd_packet(family: i32, kind: i32) -> [u8; 54] {
    let mut ea = [0u8; 54];
    ea[5] = 15;
    ea[6..8].copy_from_slice(&30u16.to_le_bytes());
    ea[8..23].copy_from_slice(b"AfdOpenPacketXX");
    for (offset, value) in [
        (24, if kind == 1 { 0i32 } else { 0x11 }),
        (32, family),
        (36, kind),
        (40, if kind == 1 { 6 } else { 17 }),
    ] {
        ea[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    ea
}
fn require_afd(host: bool) -> Result<()> {
    let abi = size_of::<usize>() == 8
        && size_of::<UnicodeString>() == 16
        && size_of::<ObjectAttributes>() == 48
        && offset_of!(ObjectAttributes, name) == 16
        && offset_of!(ObjectAttributes, descriptor) == 32
        && size_of::<IoStatusBlock>() == 16;
    ensure!(abi, "kernel AFD ABI differs");
    let name = wide(r"\Device\Afd\Endpoint");
    let unicode = UnicodeString {
        length: 40,
        maximum: 42,
        buffer: name.as_ptr(),
    };
    let attributes = ObjectAttributes {
        length: 48,
        root: null_mut(),
        name: &unicode,
        flags: 0x40,
        descriptor: null_mut(),
        qos: null_mut(),
    };
    for (family, kind) in [(2, 1), (2, 2), (23, 1), (23, 2)] {
        let mut ea = afd_packet(family, kind);
        let mut handle = null_mut();
        // SAFETY: zero is valid for both IO_STATUS_BLOCK union members and information.
        let mut iosb: IoStatusBlock = unsafe { zeroed() };
        // SAFETY: checked x64 layouts and live fixed 54-byte AFD open packet/name.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                0xC014_0000,
                &attributes,
                &mut iosb,
                null(),
                0,
                3,
                1,
                0,
                ea.as_mut_ptr().cast(),
                ea.len() as u32,
            )
        };
        let opened = !handle.is_null();
        let closed = if opened {
            // SAFETY: own every non-null output, even on an unexpected failing NTSTATUS.
            unsafe { NtClose(handle) }
        } else {
            0
        };
        let valid = if host {
            status == 0 && opened
        } else {
            status == 0xC0000022u32 as i32 && !opened
        };
        ensure!(closed == 0, "kernel AFD endpoint close failed");
        ensure!(
            valid,
            "kernel AFD endpoint outcome differs host={host} family={family} kind={kind} status={status:08X}"
        );
    }
    Ok(())
}
pub(crate) fn require_host_afd_positive() -> Result<()> {
    require_afd(true)
}
pub(super) fn controls(plan: &KernelPlan) -> Result<()> {
    let ports_valid = [plan.tcp_port, plan.udp_port].iter().all(|port| *port != 0);
    ensure!(ports_valid, "kernel network ports must be non-zero");
    let mut data: WsaData = unsafe { zeroed() };
    ensure!(size_of::<WsaData>() == 408, "kernel Winsock ABI differs");
    // Match the original CPython3.11 socketmodule.c os_init Winsock1.1 request.
    // SAFETY: exact initialized x64 WSADATA buffer; startup returns its own status.
    let startup = unsafe { WSAStartup(0x0101, &mut data) };
    if startup == 10107 {
        require_catalog_denial()?;
        return require_afd(false);
    }
    ensure!(startup == 0, "kernel Winsock initialization failed");
    let operation = (|| {
        ensure!(data.version == 0x0101, "kernel Winsock version differs");
        for family in [2, 23] {
            for kind in [1, 2] {
                let raw = unsafe { socket(family, kind, 0) };
                ensure!(
                    raw != usize::MAX,
                    "kernel Winsock socket creation was not permitted"
                );
                let mut owner = Socket(raw);
                let result = (|| {
                    let timeout = 1000u32;
                    for option in [0x1005, 0x1006] {
                        ensure!(
                            unsafe {
                                setsockopt(raw, 0xffff, option, (&timeout as *const u32).cast(), 4)
                            } == 0,
                            "kernel Winsock timeout setup failed"
                        );
                    }
                    // Only immediate WSAEACCES qualifies. Nonblocking mode prevents a different
                    // connect/send outcome from turning this fixed negative control into a hang.
                    let mut nonblocking = 1;
                    ensure!(
                        unsafe { ioctlsocket(raw, 0x8004667eu32 as i32, &mut nonblocking) } == 0,
                        "kernel Winsock nonblocking setup failed"
                    );
                    let port = if kind == 1 {
                        plan.tcp_port
                    } else {
                        plan.udp_port
                    };
                    let a4 = Address4 {
                        family: 2,
                        port: port.to_be(),
                        address: [127, 0, 0, 1],
                        zero: [0; 8],
                    };
                    let mut loop6 = [0u8; 16];
                    loop6[15] = 1;
                    let a6 = Address6 {
                        family: 23,
                        port: port.to_be(),
                        flow: 0,
                        address: loop6,
                        scope: 0,
                    };
                    let (address, length) = if family == 2 {
                        (
                            (&a4 as *const Address4).cast::<c_void>(),
                            size_of::<Address4>() as i32,
                        )
                    } else {
                        (
                            (&a6 as *const Address6).cast::<c_void>(),
                            size_of::<Address6>() as i32,
                        )
                    };
                    let status = unsafe {
                        if kind == 1 {
                            connect(raw, address, length)
                        } else {
                            sendto(raw, b"bounded dummy probe".as_ptr(), 19, 0, address, length)
                        }
                    };
                    let error = unsafe { WSAGetLastError() };
                    ensure!(
                        status == -1 && error == 10013,
                        "kernel network connect/sendto was not explicitly access-denied"
                    );
                    Ok(())
                })();
                combine(result, owner.close())?;
            }
        }
        Ok(())
    })();
    combine(
        operation,
        if unsafe { WSACleanup() } == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("kernel Winsock cleanup failed"))
        },
    )
}
#[cfg(test)]
mod tests {
    use super::afd_packet;

    #[test]
    fn afd_packet_encodes_all_four_verified_endpoint_tuples() {
        for (family, kind, flags, protocol) in [
            (2i32, 1i32, 0i32, 6i32),
            (2, 2, 0x11, 17),
            (23, 1, 0, 6),
            (23, 2, 0x11, 17),
        ] {
            let packet = afd_packet(family, kind);
            let mut expected = [0u8; 54];
            expected[5] = 15;
            expected[6..8].copy_from_slice(&30u16.to_le_bytes());
            expected[8..24].copy_from_slice(b"AfdOpenPacketXX\0");
            for (offset, word) in [(24, flags), (32, family), (36, kind), (40, protocol)] {
                expected[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
            }
            assert_eq!(packet, expected);
        }
    }
}
