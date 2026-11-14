//! Handle-bound fixed scratch leaves. No caller-provided leaf or arbitrary deletion is admitted.
use super::ffi::*;
use crate::windows_security::quota_controls::{OwnerInventory, Sid, VOLUME_BYTES};
use anyhow::{Result, ensure};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::{ManuallyDrop, size_of},
    os::windows::io::FromRawHandle,
    ptr::null_mut,
};

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Identity {
    pub(super) volume: u64,
    id: [u8; 16],
}
#[repr(C)]
#[derive(Default)]
struct Attributes {
    flags: u32,
    tag: u32,
}
pub(super) fn identity(handle: Raw, directory: bool) -> Result<Identity> {
    let mut attrs = Attributes::default();
    let mut id = Identity::default();
    // SAFETY: live handle and exact initialized Win32 output layouts.
    ensure!(
        size_of::<Identity>() == 24
            && unsafe { GetFileType(handle) } == 1
            && unsafe {
                GetFileInformationByHandleEx(handle, 9, (&mut attrs as *mut Attributes).cast(), 8)
            } != 0
            && attrs.flags & 0x410 == if directory { 0x10 } else { 0 }
            && attrs.tag == 0,
        "quota object is not a plain disk object"
    );
    ensure!(
        unsafe { GetFileInformationByHandleEx(handle, 18, (&mut id as *mut Identity).cast(), 24) }
            != 0,
        "quota file identity query failed"
    );
    Ok(id)
}
pub(super) fn name(handle: Raw) -> Result<String> {
    let mut output = [0u16; 512];
    // SAFETY: live handle and bounded writable name buffer, VOLUME_NAME_NT.
    let count = unsafe { GetFinalPathNameByHandleW(handle, output.as_mut_ptr(), 512, 2) } as usize;
    ensure!(
        (1..512).contains(&count) && output[count] == 0 && !output[..count].contains(&0),
        "quota native object name exceeds bound"
    );
    String::from_utf16(&output[..count])
        .map_err(|_| anyhow::anyhow!("quota native object name is not Unicode"))
}
pub(super) fn absent(path: &str) -> Result<()> {
    let path = wide(path);
    // SAFETY: fixed bounded NUL-terminated leaf path; inspect error immediately.
    let attrs = unsafe { GetFileAttributesW(path.as_ptr()) };
    let error = unsafe { GetLastError() };
    ensure!(
        attrs == u32::MAX && error == 2,
        "quota fixed leaf is not absent"
    );
    Ok(())
}
pub(super) fn bind(handle: Raw, id: Identity, expected: &str) -> Result<()> {
    ensure!(
        identity(handle, false)? == id && name(handle)? == expected,
        "quota file identity or native path changed"
    );
    Ok(())
}
pub(super) fn disposition(handle: Raw) -> Result<()> {
    let mut flag = 1u8;
    // SAFETY: borrowed DELETE-capable identity-qualified handle and FILE_DISPOSITION_INFO byte.
    ensure!(
        unsafe { SetFileInformationByHandle(handle, 4, (&mut flag as *mut u8).cast(), 1) } != 0,
        "quota bound file deletion failed"
    );
    Ok(())
}
pub(super) fn grant(handle: Raw, expected: u32) -> Result<()> {
    let mut info = [0u32; 14];
    let mut returned = 0;
    // SAFETY: exact 56-byte PUBLIC_OBJECT_BASIC_INFORMATION layout and live file handle.
    let status = unsafe { NtQueryObject(handle, 0, info.as_mut_ptr().cast(), 56, &mut returned) };
    ensure!(
        status == 0 && returned == 56 && info[0] & 2 == 0 && info[1] == expected,
        "quota private creator actual handle grant differs"
    );
    Ok(())
}
pub(super) fn file(handle: Raw) -> ManuallyDrop<File> {
    // SAFETY: synchronous borrowed view; ManuallyDrop never closes or transfers the actual owner.
    ManuallyDrop::new(unsafe { File::from_raw_handle(handle) })
}
pub(super) struct Root {
    pub(super) path: String,
    pub(super) native: String,
    pub(super) id: Identity,
    pub(super) handle: Owned,
}
impl Root {
    pub(super) fn open(path: &str) -> Result<Self> {
        let mut handle = open(path, 0x80, 7, 3, 0x02200000, std::ptr::null())?;
        let result = (|| {
            let id = identity(handle.0, true)?;
            let native = name(handle.0)?;
            ensure!(
                crate::windows_security::scratch::private::native_root(&native),
                "quota scratch native root shape differs"
            );
            let path_w = wide(path);
            let mut bytes = 0;
            let mut filesystem = [0u16; 32];
            let mut flags = 0;
            // SAFETY: actual drive root, writable bounded filesystem name/flag outputs.
            ensure!(
                unsafe {
                    GetVolumeInformationW(
                        path_w.as_ptr(),
                        null_mut(),
                        0,
                        null_mut(),
                        null_mut(),
                        &mut flags,
                        filesystem.as_mut_ptr(),
                        32,
                    )
                } != 0
                    && filesystem[..5] == [78, 84, 70, 83, 0]
                    && flags & 0x68 == 0x68,
                "quota worker requires actual NTFS ACL, quota and sparse capabilities"
            );
            // SAFETY: fixed root and writable capacity scalar; no free-space inference is used.
            ensure!(
                unsafe { GetDiskFreeSpaceExW(path_w.as_ptr(), null_mut(), &mut bytes, null_mut()) }
                    != 0
                    && bytes > 0
                    && bytes <= VOLUME_BYTES,
                "quota scratch capacity exceeds original volume bound"
            );
            Ok(Self {
                path: path.into(),
                native,
                id,
                handle: Owned(std::mem::replace(&mut handle.0, null_mut())),
            })
        })();
        combine(result, handle.close())
    }
    pub(super) fn require(&self) -> Result<()> {
        ensure!(
            identity(self.handle.0, true)? == self.id && name(self.handle.0)? == self.native,
            "quota scratch root binding changed"
        );
        Ok(())
    }
    pub(super) fn create(&self, leaf: &str) -> Result<Leaf> {
        ensure!(
            [
                "positive-primary",
                "positive-token-child",
                "authority-normal",
                "quota-ordinary",
                "quota-sparse",
                "quota-aggregate-0",
                "quota-aggregate-1"
            ]
            .contains(&leaf),
            "quota leaf is outside fixed set"
        );
        self.require()?;
        let path = format!("{}{leaf}", self.path);
        absent(&path)?;
        let mut handle = open(&path, 0xC0030080, 3, 1, 0x00200080, std::ptr::null())?;
        let result = (|| {
            let id = identity(handle.0, false)?;
            let expected = format!("{}{leaf}", self.native);
            ensure!(
                id.volume == self.id.volume && name(handle.0)? == expected,
                "quota newly created leaf is outside pinned root"
            );
            Ok(Leaf {
                path,
                id,
                expected,
                handle: Owned(std::mem::replace(&mut handle.0, null_mut())),
                removed: false,
            })
        })();
        combine(result, handle.close())
    }
    pub(super) fn close(&mut self) -> Result<()> {
        self.handle.close()
    }
}
pub(super) struct Leaf {
    pub(super) path: String,
    id: Identity,
    expected: String,
    pub(super) handle: Owned,
    removed: bool,
}
impl Leaf {
    pub(super) fn require(&self) -> Result<()> {
        bind(self.handle.0, self.id, &self.expected)
    }
    pub(super) fn close(&mut self) -> Result<()> {
        if self.removed {
            return self.handle.close();
        }
        let result = (|| {
            self.require()?;
            disposition(self.handle.0)?;
            Ok(())
        })();
        let result = combine(result, self.handle.close());
        self.removed = true;
        combine(result, absent(&self.path))
    }
}
impl Drop for Leaf {
    fn drop(&mut self) {
        if self.close().is_err() {
            note_cleanup_failure();
        }
    }
}
pub(super) fn owner_matches_user(handle: Raw, inventory: &OwnerInventory) -> Result<()> {
    let (mut owner, mut descriptor) = (null_mut(), null_mut());
    // SAFETY: live READ_CONTROL file handle and writable native allocation/pointer outputs.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            1,
            1,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    let mut descriptor = Descriptor(descriptor);
    let result = (|| {
        ensure!(
            status == 0 && !descriptor.0.is_null() && !owner.is_null(),
            "quota new-file owner query failed"
        );
        let bytes = unsafe { GetSecurityDescriptorLength(descriptor.0) } as usize;
        let base = descriptor.0 as usize;
        let pointer = owner as usize;
        ensure!(
            (20..=65536).contains(&bytes) && pointer >= base && pointer.is_multiple_of(4),
            "quota new-file owner pointer differs"
        );
        let offset = pointer - base;
        ensure!(
            offset <= bytes && bytes - offset >= 8,
            "quota new-file owner header is outside descriptor"
        );
        // SAFETY: bounded SID header inside the live API-allocated descriptor.
        let header = unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), 8) };
        ensure!(
            header[0] == 1 && header[1] <= 15,
            "quota new-file owner SID header differs"
        );
        let length = 8 + usize::from(header[1]) * 4;
        ensure!(
            length <= bytes - offset,
            "quota new-file owner SID exceeds descriptor"
        );
        let sid = Sid::binary(unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), length) })?;
        let matches = sid == inventory.user;
        ensure!(
            matches,
            "quota new file owner differs from actual token user"
        );
        Ok(())
    })();
    combine(result, descriptor.close())
}
pub(super) fn positive(root: &Root, inventory: &OwnerInventory, child: bool) -> Result<()> {
    let mut leaf = root.create(if child {
        "positive-token-child"
    } else {
        "positive-primary"
    })?;
    let result = (|| {
        let mut stream = file(leaf.handle.0);
        stream
            .write_all(b"bounded control")
            .map_err(|_| anyhow::anyhow!("quota positive write failed"))?;
        stream
            .flush()
            .map_err(|_| anyhow::anyhow!("quota positive flush failed"))?;
        stream
            .seek(SeekFrom::Start(0))
            .map_err(|_| anyhow::anyhow!("quota positive seek failed"))?;
        let mut bytes = [0u8; 15];
        stream
            .read_exact(&mut bytes)
            .map_err(|_| anyhow::anyhow!("quota positive read failed"))?;
        ensure!(
            bytes == *b"bounded control",
            "quota positive contents differ"
        );
        leaf.require()?;
        owner_matches_user(leaf.handle.0, inventory)
    })();
    combine(result, leaf.close())
}
