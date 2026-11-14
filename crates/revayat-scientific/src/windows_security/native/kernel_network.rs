//! Exactly four real Winsock connect/sendto denials; socket creation is a positive prerequisite.
use super::super::ffi::{combine, note_cleanup_failure};
use crate::windows_security::kernel_controls::KernelPlan;
use anyhow::{Result, ensure};
use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
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
pub(super) fn controls(plan: &KernelPlan) -> Result<()> {
    let mut data: WsaData = unsafe { zeroed() };
    ensure!(size_of::<WsaData>() == 408, "kernel Winsock ABI differs");
    // SAFETY: exact initialized x64 WSADATA buffer, requesting fixed Winsock2.2.
    ensure!(
        unsafe { WSAStartup(0x0202, &mut data) } == 0,
        "kernel Winsock initialization failed"
    );
    let operation = (|| {
        ensure!(data.version == 0x0202, "kernel Winsock version differs");
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
