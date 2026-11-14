//! Native scratch handles, exact identities and protected durable records.
use super::{
    Handle,
    authority::{Descriptor, wide},
};
use anyhow::{Context, Result, ensure};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    ffi::c_void,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};

#[repr(C)]
struct Security {
    size: u32,
    descriptor: Handle,
    inherit: i32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[repr(C)]
pub(super) struct Identity {
    pub volume: u64,
    pub high: u64,
    pub low: u64,
}
#[repr(C)]
#[derive(Default)]
struct Attributes {
    attributes: u32,
    tag: u32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *const Security,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetFileType(handle: Handle) -> u32;
    fn GetFileInformationByHandleEx(handle: Handle, class: i32, data: Handle, size: u32) -> i32;
    fn GetFinalPathNameByHandleW(handle: Handle, path: *mut u16, size: u32, flags: u32) -> u32;
    fn DeviceIoControl(
        handle: Handle,
        code: u32,
        input: *const c_void,
        input_size: u32,
        output: Handle,
        output_size: u32,
        returned: *mut u32,
        overlapped: Handle,
    ) -> i32;
    fn SetFileInformationByHandle(
        handle: Handle,
        class: u32,
        data: *const c_void,
        size: u32,
    ) -> i32;
    fn LocalFree(value: Handle) -> Handle;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetSecurityInfo(
        handle: Handle,
        kind: i32,
        fields: u32,
        owner: *mut Handle,
        group: *mut Handle,
        dacl: *mut Handle,
        sacl: *mut Handle,
        descriptor: *mut Handle,
    ) -> u32;
    fn GetSecurityDescriptorLength(descriptor: Handle) -> u32;
    fn SetFileSecurityW(path: *const u16, fields: u32, descriptor: Handle) -> i32;
}

pub(super) fn combine<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(error)) => Err(crate::windows_security::activation::Failures {
            errors: vec![primary, error],
        }
        .into()),
    }
}
pub(super) fn native_error(operation: &'static str) -> anyhow::Error {
    anyhow::anyhow!(
        "{operation} winerror={}",
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    )
}
pub(super) fn object_id(handle: Handle) -> Result<crate::identity::ObjectId> {
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut data: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    ensure!(
        unsafe { GetFileInformationByHandle(handle, &mut data) } != 0,
        "scratch held state identity query failed"
    );
    Ok(crate::identity::ObjectId {
        volume: u64::from(data.dwVolumeSerialNumber),
        index: (u64::from(data.nFileIndexHigh) << 32) | u64::from(data.nFileIndexLow),
    })
}
pub(super) struct Owned(pub Handle);
impl Owned {
    pub fn checked(handle: Handle) -> Result<Self> {
        ensure!(
            !handle.is_null() && handle as isize != -1,
            "invalid scratch handle"
        );
        Ok(Self(handle))
    }
    pub fn open(path: impl AsRef<Path>, access: u32, share: u32, flags: u32) -> Result<Self> {
        let path = wide(path.as_ref());
        let handle =
            unsafe { CreateFileW(path.as_ptr(), access, share, null(), 3, flags, null_mut()) };
        if handle.is_null() || handle as isize == -1 {
            return Err(std::io::Error::last_os_error()).context("open bound scratch object");
        }
        Ok(Self(handle))
    }
    pub fn close(&mut self) -> Result<()> {
        if !self.0.is_null() {
            let handle = std::mem::replace(&mut self.0, null_mut());
            ensure!(
                unsafe { CloseHandle(handle) } != 0,
                "scratch handle close failed"
            );
        }
        Ok(())
    }
    pub fn duplicate(&self) -> Result<Self> {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentProcess() -> Handle;
            fn DuplicateHandle(
                source_process: Handle,
                source: Handle,
                target_process: Handle,
                target: *mut Handle,
                access: u32,
                inherit: i32,
                options: u32,
            ) -> i32;
        }
        ensure!(!self.0.is_null(), "scratch owner is closed");
        let mut target = null_mut();
        ensure!(
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    self.0,
                    GetCurrentProcess(),
                    &mut target,
                    0,
                    0,
                    2,
                )
            } != 0,
            "duplicate scratch owner failed"
        );
        Self::checked(target)
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
pub(super) fn identity(handle: Handle, directory: bool) -> Result<Identity> {
    ensure!(
        unsafe { GetFileType(handle) } == 1,
        "scratch object is not a disk file"
    );
    let mut attributes = Attributes::default();
    let mut value = Identity {
        volume: 0,
        low: 0,
        high: 0,
    };
    ensure!(
        unsafe {
            GetFileInformationByHandleEx(handle, 9, (&mut attributes as *mut Attributes).cast(), 8)
        } != 0,
        "scratch attributes query failed"
    );
    ensure!(
        attributes.attributes & 0x410 == if directory { 0x10 } else { 0 } && attributes.tag == 0,
        "scratch object type or reparse tag differs"
    );
    ensure!(
        unsafe {
            GetFileInformationByHandleEx(handle, 18, (&mut value as *mut Identity).cast(), 24)
        } != 0,
        "scratch file identity query failed"
    );
    Ok(value)
}
pub(super) fn name(handle: Handle) -> Result<String> {
    let mut text = [0u16; 512];
    let length = unsafe { GetFinalPathNameByHandleW(handle, text.as_mut_ptr(), 512, 2) } as usize;
    ensure!(
        length > 0 && length < 512 && text[length] == 0,
        "scratch native name exceeds bound"
    );
    Ok(String::from_utf16(&text[..length])?)
}
pub(super) fn ioctl(handle: Handle, code: u32, input: &[u8], output: &mut [u8]) -> Result<usize> {
    let mut returned = 0;
    let status = unsafe {
        DeviceIoControl(
            handle,
            code,
            if input.is_empty() {
                null()
            } else {
                input.as_ptr().cast()
            },
            input.len().try_into()?,
            if output.is_empty() {
                null_mut()
            } else {
                output.as_mut_ptr().cast()
            },
            output.len().try_into()?,
            &mut returned,
            null_mut(),
        )
    };
    // Capture the API's error before any subsequent native call or formatting.
    let error = (status == 0).then(std::io::Error::last_os_error);
    let result = (|| {
        if let Some(error) = error {
            return Err(error.into());
        }
        ensure!(
            returned as usize <= output.len(),
            "scratch device response exceeds buffer"
        );
        Ok(())
    })();
    result.map_err(|error| {
        use crate::windows_security::activation::diagnostics::{self, Numbers, Stage};
        let native_error = error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
            .map(|code| code as u32);
        diagnostics::annotate(
            error,
            Stage::ScratchDeviceControl,
            Numbers {
                native_error,
                properties: Some(code),
                bytes: Some(returned),
                count: u32::try_from(output.len()).ok(),
                ..Default::default()
            },
        )
    })?;
    Ok(returned as usize)
}
pub(super) fn bytes<T>(value: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((value as *const T).cast(), size_of::<T>()) }
}
pub(super) fn query<T>(handle: Handle, code: u32) -> Result<T> {
    let mut value: T = unsafe { zeroed() };
    let output =
        unsafe { std::slice::from_raw_parts_mut((&mut value as *mut T).cast(), size_of::<T>()) };
    ensure!(
        ioctl(handle, code, &[], output)? == size_of::<T>(),
        "scratch device response size differs"
    );
    Ok(value)
}
pub(super) fn security(handle: Handle, fields: u32) -> Result<Vec<u8>> {
    let (mut owner, mut group, mut dacl, mut sacl, mut descriptor) =
        (null_mut(), null_mut(), null_mut(), null_mut(), null_mut());
    let error = unsafe {
        GetSecurityInfo(
            handle,
            1,
            fields,
            &mut owner,
            &mut group,
            &mut dacl,
            &mut sacl,
            &mut descriptor,
        )
    };
    let result = (|| {
        ensure!(
            error == 0 && !descriptor.is_null(),
            "scratch descriptor query failed winerror={error}"
        );
        let size = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
        ensure!(
            (20..=65536).contains(&size),
            "scratch descriptor exceeds bound"
        );
        Ok(unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), size) }.to_vec())
    })();
    combine(
        result,
        if descriptor.is_null() || unsafe { LocalFree(descriptor) }.is_null() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("scratch descriptor release failed"))
        },
    )
}
pub(super) fn set_security(path: &Path, sddl: &str, fields: u32) -> Result<()> {
    let mut descriptor = Descriptor::new(sddl)?;
    let path = wide(path);
    let result = if unsafe { SetFileSecurityW(path.as_ptr(), fields, descriptor.0) } != 0 {
        Ok(())
    } else {
        Err(native_error("set scratch policy"))
    };
    combine(result, descriptor.close())
}
pub(super) fn private_sddl(host: &str) -> String {
    let system = if host == "S-1-5-18" {
        String::new()
    } else {
        "(A;;FA;;;SY)".into()
    };
    format!("O:{host}G:{host}D:P(D;;0x000C0000;;;OW){system}(A;;FA;;;{host})")
}
pub(super) fn require_private(handle: Handle, host: &str) -> Result<()> {
    use crate::windows_security::policy::{Acl, Descriptor as Relative};
    let actual = security(handle, 7)?;
    let actual = Relative::parse(&actual)?;
    let mut expected = Descriptor::new(&private_sddl(host))?;
    let result = (|| {
        let length = unsafe { GetSecurityDescriptorLength(expected.0) } as usize;
        ensure!(
            (20..=65536).contains(&length),
            "scratch expected policy exceeds bound"
        );
        let data = unsafe { std::slice::from_raw_parts(expected.0.cast::<u8>(), length) };
        let expected = Relative::parse(data)?;
        ensure!(
            actual.owner == expected.owner
                && actual.group == expected.group
                && actual.control & 0x1004 == 0x1004,
            "scratch private owner/protection differs"
        );
        let actual = Acl::parse(actual.dacl.context("scratch private DACL absent")?)?;
        let expected = Acl::parse(expected.dacl.context("scratch expected DACL absent")?)?;
        ensure!(
            actual.aces.len() == expected.aces.len()
                && actual
                    .aces
                    .iter()
                    .zip(expected.aces)
                    .all(|(a, b)| a.bytes == b.bytes),
            "scratch private ACL differs"
        );
        Ok(())
    })();
    combine(result, expected.close())
}
pub(super) fn record_path(state: &Path, record: &str) -> Result<PathBuf> {
    ensure!(
        matches!(
            record,
            "sxs-trace.intent"
                | "sxs-trace.bound"
                | "scratch-disk.intent"
                | "scratch-disk.created"
                | "scratch-disk.attach-intent"
                | "scratch-disk.layout-intent"
                | "scratch-disk.volume"
                | "scratch-disk.mount-intent"
                | "scratch-disk.ready"
                | "scratch-disk.detached"
                | "scratch-volume-supported.receipt"
                | "scratch-volume-diagnostic.receipt"
        ),
        "unsupported scratch durable record"
    );
    Ok(state.join(record))
}
pub(super) fn write_record(state: &Path, host: &str, record: &str, data: &[u8]) -> Result<()> {
    ensure!(
        !data.is_empty() && data.len() <= 196608,
        "scratch durable record exceeds bound"
    );
    crate::windows_security::plain_path(state)?;
    let path = record_path(state, record)?;
    let text = wide(&path);
    let mut descriptor = Descriptor::new(&private_sddl(host))?;
    let attributes = Security {
        size: size_of::<Security>() as u32,
        descriptor: descriptor.0,
        inherit: 0,
    };
    let raw = unsafe {
        CreateFileW(
            text.as_ptr(),
            0xc0000000,
            1,
            &attributes,
            1,
            0x200080,
            null_mut(),
        )
    };
    let result = (|| {
        ensure!(
            !raw.is_null() && raw as isize != -1,
            "create scratch durable record failed"
        );
        let mut file = unsafe { File::from_raw_handle(raw) };
        let result = (|| {
            identity(file.as_raw_handle(), false)?;
            require_private(file.as_raw_handle(), host)?;
            file.write_all(data)?;
            file.flush()?;
            file.sync_all()?;
            file.seek(SeekFrom::Start(0))?;
            let mut actual = Vec::new();
            Read::by_ref(&mut file)
                .take(196609)
                .read_to_end(&mut actual)?;
            ensure!(actual == data, "scratch durable record readback differs");
            Ok(())
        })();
        let mut owner = Owned(file.into_raw_handle());
        combine(result, owner.close())
    })();
    combine(result, descriptor.close())
}
pub(super) fn read_record(state: &Path, host: &str, record: &str) -> Result<Option<Vec<u8>>> {
    let path = record_path(state, record)?;
    if !path.try_exists()? {
        return Ok(None);
    }
    crate::windows_security::plain_path(&path)?;
    let owner = Owned::open(&path, 0x80020080, 1, 0x200000)?;
    let mut file = unsafe { File::from_raw_handle(owner.0) };
    std::mem::forget(owner);
    let result = (|| {
        let before = identity(file.as_raw_handle(), false)?;
        require_private(file.as_raw_handle(), host)?;
        let mut data = Vec::new();
        Read::by_ref(&mut file)
            .take(196609)
            .read_to_end(&mut data)?;
        ensure!(
            !data.is_empty()
                && data.len() <= 196608
                && identity(file.as_raw_handle(), false)? == before,
            "scratch durable record span or identity differs"
        );
        Ok(data)
    })();
    let mut owner = Owned(file.into_raw_handle());
    combine(result, owner.close()).map(Some)
}
pub(super) fn write_json<T: Serialize>(
    state: &Path,
    host: &str,
    record: &str,
    value: &T,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    write_record(state, host, record, &bytes)
}
pub(super) fn read_json<T: DeserializeOwned + Serialize>(
    state: &Path,
    host: &str,
    record: &str,
) -> Result<Option<T>> {
    read_record(state, host, record)?
        .map(|data| {
            let value = serde_json::from_slice(&data)?;
            let mut canonical = serde_json::to_vec(&value)?;
            canonical.push(b'\n');
            ensure!(data == canonical, "scratch durable JSON is not canonical");
            Ok(value)
        })
        .transpose()
}
pub(super) fn remove_record(state: &Path, host: &str, record: &str, expected: &[u8]) -> Result<()> {
    remove_record_identity(state, host, record, expected, None)
}
pub(super) fn remove_record_identity(
    state: &Path,
    host: &str,
    record: &str,
    expected: &[u8],
    expected_id: Option<Identity>,
) -> Result<()> {
    let path = record_path(state, record)?;
    let mut handle = Owned::open(&path, 0x80030080, 3, 0x200000)?;
    let result = (|| {
        require_private(handle.0, host)?;
        let actual_id = identity(handle.0, false)?;
        ensure!(
            expected_id.is_none_or(|id| id == actual_id),
            "scratch receipt object differs before removal"
        );
        ensure!(
            read_handle(handle.0)? == expected && identity(handle.0, false)? == actual_id,
            "scratch receipt replaced before removal"
        );
        let remove = 1u8;
        ensure!(
            unsafe { SetFileInformationByHandle(handle.0, 4, (&remove as *const u8).cast(), 1) }
                != 0,
            "scratch receipt bound removal failed"
        );
        Ok(())
    })();
    combine(result, handle.close())
}
pub(super) fn read_handle(handle: Handle) -> Result<Vec<u8>> {
    let mut file = std::mem::ManuallyDrop::new(unsafe { File::from_raw_handle(handle) });
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut *file)
        .take(196609)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= 196608,
        "scratch receipt read exceeds bound"
    );
    Ok(bytes)
}
pub(super) fn process_sid(process: Handle, class: u32) -> Result<Vec<u8>> {
    ensure!(
        matches!(class, 1 | 31),
        "unsupported scratch token SID query"
    );
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: i32,
            data: Handle,
            size: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let mut token = null_mut();
    ensure!(
        unsafe { OpenProcessToken(process, 8, &mut token) } != 0,
        "scratch process token query failed"
    );
    let mut token = Owned::checked(token)?;
    let result = (|| {
        let mut required = 0;
        let initial =
            unsafe { GetTokenInformation(token.0, class as i32, null_mut(), 0, &mut required) };
        let error = std::io::Error::last_os_error().raw_os_error();
        ensure!(
            initial == 0 && error == Some(122) && (8..=65536).contains(&required),
            "scratch token SID sizing differs"
        );
        let mut data = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
        let mut returned = 0;
        ensure!(
            unsafe {
                GetTokenInformation(
                    token.0,
                    class as i32,
                    data.as_mut_ptr().cast(),
                    required,
                    &mut returned,
                )
            } != 0
                && returned >= 8
                && returned <= required,
            "scratch token SID query extent differs"
        );
        let start = data.as_ptr() as usize;
        let pointer = data[0];
        ensure!(
            pointer >= start
                && pointer - start <= returned as usize
                && 8 <= returned as usize - (pointer - start),
            "scratch token SID pointer escapes buffer"
        );
        let offset = pointer - start;
        let bytes =
            unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), returned as usize) };
        ensure!(
            bytes[offset] == 1 && bytes[offset + 1] <= 15,
            "scratch token SID header differs"
        );
        let length = 8 + usize::from(bytes[offset + 1]) * 4;
        ensure!(
            length <= bytes.len() - offset,
            "scratch token SID span differs"
        );
        Ok(bytes[offset..offset + length].to_vec())
    })();
    combine(result, token.close())
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PrivilegeState {
    count: u32,
    low: u32,
    high: i32,
    attributes: u32,
}
pub(super) struct ManageVolume {
    token: Owned,
    previous: PrivilegeState,
    changed: bool,
}
impl ManageVolume {
    pub fn acquire() -> Result<Self> {
        crate::windows_security::activation::native::require_host()?;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentProcess() -> Handle;
            fn SetLastError(error: u32);
        }
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
            fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut u32) -> i32;
            fn AdjustTokenPrivileges(
                token: Handle,
                disable: i32,
                state: *const c_void,
                bytes: u32,
                previous: *mut c_void,
                returned: *mut u32,
            ) -> i32;
        }
        let mut token = null_mut();
        ensure!(
            unsafe { OpenProcessToken(GetCurrentProcess(), 0x28, &mut token) } != 0,
            "open host volume privilege token failed"
        );
        let mut token = Owned::checked(token)?;
        let result = (|| {
            let name = wide("SeManageVolumePrivilege");
            let mut state = PrivilegeState {
                count: 1,
                attributes: 2,
                ..Default::default()
            };
            ensure!(
                unsafe { LookupPrivilegeValueW(null(), name.as_ptr(), &mut state.low) } != 0,
                "resolve host volume privilege failed"
            );
            let mut previous = PrivilegeState::default();
            let mut returned = 0;
            unsafe { SetLastError(0) };
            let success = unsafe {
                AdjustTokenPrivileges(
                    token.0,
                    0,
                    (&state as *const PrivilegeState).cast(),
                    16,
                    (&mut previous as *mut PrivilegeState).cast(),
                    &mut returned,
                )
            };
            let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            if previous.count > 1 {
                std::process::abort();
            }
            let mut owner = Self {
                token: Owned(std::mem::replace(&mut token.0, null_mut())),
                previous,
                changed: previous.count == 1,
            };
            if success == 0 || error != 0 || returned > 16 {
                return combine(
                    Err(anyhow::anyhow!(
                        "enable host volume privilege failed winerror={error}"
                    )),
                    owner.close(),
                );
            }
            Ok(owner)
        })();
        combine(result, token.close())
    }
    pub fn close(&mut self) -> Result<()> {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn SetLastError(error: u32);
        }
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn AdjustTokenPrivileges(
                token: Handle,
                disable: i32,
                state: *const c_void,
                bytes: u32,
                previous: *mut c_void,
                returned: *mut u32,
            ) -> i32;
        }
        let result = if self.changed {
            self.changed = false;
            unsafe { SetLastError(0) };
            let success = unsafe {
                AdjustTokenPrivileges(
                    self.token.0,
                    0,
                    (&self.previous as *const PrivilegeState).cast(),
                    0,
                    null_mut(),
                    null_mut(),
                )
            };
            let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            if success != 0 && error == 0 {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "restore host volume privilege failed winerror={error}"
                ))
            }
        } else {
            Ok(())
        };
        combine(result, self.token.close())
    }
}
impl Drop for ManageVolume {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
