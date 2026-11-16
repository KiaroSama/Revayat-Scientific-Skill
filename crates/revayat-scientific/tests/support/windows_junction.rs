//! Test-only real NTFS directory junction; no interpreter or symlink privilege.
#![cfg(windows)]
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *const c_void,
        disposition: u32,
        flags: u32,
        template: *mut c_void,
    ) -> *mut c_void;
    fn DeviceIoControl(
        file: *mut c_void,
        code: u32,
        input: *const c_void,
        input_size: u32,
        output: *mut c_void,
        output_size: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

pub fn create(link: &Path, target: &Path) -> io::Result<()> {
    let target = target.canonicalize()?;
    let print = target.as_os_str().encode_wide().collect::<Vec<_>>();
    let mut substitute = vec![92u16, 63, 63, 92];
    if print.starts_with(&[92, 92, 63, 92]) {
        substitute.extend_from_slice(&print[4..]);
    } else {
        substitute.extend_from_slice(&print);
    }
    if substitute.len() > 4096 || print.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "junction target exceeds bound",
        ));
    }
    let substitute_bytes = (substitute.len() * 2) as u16;
    let print_offset = substitute_bytes + 2;
    let print_bytes = (print.len() * 2) as u16;
    let data_length = 8 + usize::from(print_offset) + usize::from(print_bytes) + 2;
    let mut buffer = Vec::new();
    buffer.extend(0xa0000003u32.to_le_bytes());
    buffer.extend((data_length as u16).to_le_bytes());
    buffer.extend(0u16.to_le_bytes());
    for value in [0u16, substitute_bytes, print_offset, print_bytes] {
        buffer.extend(value.to_le_bytes());
    }
    for value in substitute
        .into_iter()
        .chain(Some(0))
        .chain(print)
        .chain(Some(0))
    {
        buffer.extend(value.to_le_bytes());
    }
    std::fs::create_dir(link)?;
    let path = link
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: open only the newly created directory itself, without traversing
    // reparse points, for the one fixed mount-point control operation.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            0x40000000,
            0,
            null(),
            3,
            0x02200000,
            null_mut(),
        )
    };
    if handle.is_null() || handle as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut returned = 0;
    // SAFETY: buffer contains the bounded mount-point REPARSE_DATA_BUFFER layout.
    let set = unsafe {
        DeviceIoControl(
            handle,
            0x900a4,
            buffer.as_ptr().cast(),
            buffer.len() as u32,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    };
    let error = if set == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    let closed = unsafe { CloseHandle(handle) };
    if let Some(error) = error {
        return Err(error);
    }
    if closed == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
