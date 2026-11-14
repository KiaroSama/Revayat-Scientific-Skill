//! Exact primary/duplicate/effective LPAC identities for the suspended scratch comparison.
use super::{Handle, Identity, ProbeOwners, References, ScratchVolume, access, actual, modeled};
use crate::windows_security::{
    activation::native::require_host,
    policy::{profile_validation::registry_context, within},
    scratch::{self, access::Privileges},
};
use crate::windows_security::{native::authority::wide, scratch::file};
use anyhow::{Result, ensure};
use registry_authority::native::CreateFileW;
use registry_authority::native::{
    GetLastError, GetTokenInformation, NtQuerySecurityAttributesToken, OpenProcessToken, Unicode,
};
use std::{
    cell::{Cell, RefCell},
    ptr::{null, null_mut},
};

#[link(name = "advapi32")]
unsafe extern "system" {
    fn DuplicateTokenEx(
        token: Handle,
        access: u32,
        attributes: Handle,
        level: i32,
        kind: i32,
        output: *mut Handle,
    ) -> i32;
    fn ImpersonateLoggedOnUser(token: Handle) -> i32;
    fn RevertToSelf() -> i32;
    fn OpenThreadToken(thread: Handle, access: u32, as_self: i32, token: *mut Handle) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentThread() -> Handle;
}

struct Query {
    words: Vec<u64>,
    length: usize,
}
impl Query {
    fn read(token: Handle, kind: i32) -> Result<Self> {
        let mut returned = 0;
        let initial = unsafe { GetTokenInformation(token, kind, null_mut(), 0, &mut returned) };
        let code = if initial == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        ensure!(
            initial == 0 && code == 122 && (4..=65536).contains(&returned),
            "scratch diagnostic token size differs kind={kind} winerror={code}"
        );
        let capacity = returned;
        let mut data = Self {
            words: vec![0; (capacity as usize).div_ceil(8)],
            length: capacity as usize,
        };
        let success = unsafe {
            GetTokenInformation(
                token,
                kind,
                data.words.as_mut_ptr().cast(),
                capacity,
                &mut returned,
            )
        };
        let code = if success == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        ensure!(
            success != 0 && (4..=capacity).contains(&returned),
            "scratch diagnostic token query differs kind={kind} winerror={code}"
        );
        data.length = returned as usize;
        Ok(data)
    }
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.length) }
    }
    fn dword(&self, at: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.bytes()
                .get(at..at + 4)
                .ok_or_else(|| anyhow::anyhow!("short scratch diagnostic token scalar"))?
                .try_into()?,
        ))
    }
    fn sid(&self, at: usize, minimum: usize) -> Result<Vec<u8>> {
        let pointer = u64::from_le_bytes(
            self.bytes()
                .get(at..at + 8)
                .ok_or_else(|| anyhow::anyhow!("short scratch diagnostic SID pointer"))?
                .try_into()?,
        );
        let start = self.words.as_ptr() as u64;
        ensure!(
            self.length >= minimum
                && within(start, self.length as u64, pointer, 8, 4)
                && pointer - start >= minimum as u64,
            "scratch diagnostic SID is outside its returned buffer"
        );
        let bytes = &self.bytes()[(pointer - start) as usize..];
        ensure!(
            bytes[0] == 1 && bytes[1] <= 15,
            "scratch diagnostic SID header differs"
        );
        let length = 8 + usize::from(bytes[1]) * 4;
        ensure!(length <= bytes.len(), "scratch diagnostic SID is truncated");
        Ok(bytes[..length].to_vec())
    }
}
impl Drop for Query {
    fn drop(&mut self) {
        self.words.fill(0);
    }
}
fn scalar(token: Handle, kind: i32) -> Result<u32> {
    let data = Query::read(token, kind)?;
    ensure!(data.length == 4, "scratch diagnostic scalar ABI differs");
    data.dword(0)
}
fn groups(token: Handle, kind: i32) -> Result<Vec<(Vec<u8>, u32)>> {
    let data = Query::read(token, kind)?;
    let count = data.dword(0)? as usize;
    ensure!(
        count <= 256 && (count == 0 || 8 + count * 16 <= data.length),
        "scratch diagnostic token group budget exceeded"
    );
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let at = 8 + index * 16;
        result.push((data.sid(at, 8 + count * 16)?, data.dword(at + 8)?));
    }
    result.sort(); // A sorted multiset preserves duplicate SID/attribute entries.
    Ok(result)
}
fn lpac(token: Handle) -> Result<()> {
    let text = registry_context::LPAC_NAME
        .encode_utf16()
        .collect::<Vec<_>>();
    let name = Unicode {
        length: (text.len() * 2) as u16,
        maximum: (text.len() * 2) as u16,
        buffer: text.as_ptr(),
    };
    let mut data = Query {
        words: vec![0; 64],
        length: 512,
    };
    let mut returned = 0;
    let status = unsafe {
        NtQuerySecurityAttributesToken(
            token,
            &name,
            1,
            data.words.as_mut_ptr().cast(),
            512,
            &mut returned,
        )
    };
    if status == scratch::access::PENDING {
        std::process::abort();
    }
    ensure!(
        status == 0 && (16..=512).contains(&returned),
        "scratch diagnostic LPAC attribute query failed ntstatus=0x{:08X}",
        status as u32
    );
    data.length = returned as usize;
    registry_context::require_lpac(data.bytes(), data.words.as_ptr() as u64)
}
struct Snapshot {
    user: Vec<u8>,
    package: Vec<u8>,
    restricted: Vec<(Vec<u8>, u32)>,
    privileges: Privileges,
}
impl Snapshot {
    fn read(token: Handle, duplicate: bool) -> Result<Self> {
        ensure!(
            scalar(token, 8)? == if duplicate { 2 } else { 1 },
            "scratch diagnostic token type differs"
        );
        ensure!(
            !duplicate || scalar(token, 9)? == 2,
            "scratch diagnostic impersonation level differs"
        );
        ensure!(
            scalar(token, 29)? == 1 && groups(token, 30)?.is_empty(),
            "scratch diagnostic requires the zero-capability AppContainer"
        );
        lpac(token)?;
        Ok(Self {
            user: Query::read(token, 1)?.sid(0, 16)?,
            package: Query::read(token, 31)?.sid(0, 8)?,
            restricted: groups(token, 11)?,
            privileges: Privileges::parse(Query::read(token, 3)?.bytes())?,
        })
    }
    fn same(&self, actual: &Self) -> Result<()> {
        registry_context::require_equal(
            registry_context::Identity {
                user: &self.user,
                package: &self.package,
                restricted: &self.restricted,
            },
            registry_context::Identity {
                user: &actual.user,
                package: &actual.package,
                restricted: &actual.restricted,
            },
        )?;
        self.privileges.same(&actual.privileges)
    }
}

pub(super) struct Context {
    primary: access::Owned,
    duplicate: access::Owned,
    expected: Option<Snapshot>,
    effective: RefCell<Option<Privileges>>,
    frames: Vec<String>,
    impersonating: Cell<bool>,
}
impl Context {
    pub(super) fn open(process: Handle, host: &str, package: &str) -> Result<Self> {
        require_host()?;
        let mut value = Self {
            primary: access::Owned(null_mut()),
            duplicate: access::Owned(null_mut()),
            expected: None,
            effective: RefCell::new(None),
            frames: Vec::new(),
            impersonating: Cell::new(false),
        };
        let result = (|| {
            let success = unsafe { OpenProcessToken(process, 0xa, &mut value.primary.0) };
            let code = if success == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            let valid = scratch::valid_handle(value.primary.0 as usize);
            if !valid {
                value.primary.0 = null_mut();
            }
            ensure!(
                success != 0 && valid,
                "scratch diagnostic primary open failed winerror={code}"
            );
            let expected = Snapshot::read(value.primary.0, false)?;
            ensure!(
                expected.user == scratch::sid(host)? && expected.package == scratch::sid(package)?,
                "scratch diagnostic token is not the bound host/package"
            );
            let success = unsafe {
                DuplicateTokenEx(
                    value.primary.0,
                    0xc,
                    null_mut(),
                    2,
                    2,
                    &mut value.duplicate.0,
                )
            };
            let code = if success == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            let valid = scratch::valid_handle(value.duplicate.0 as usize);
            let alias = value.duplicate.0 == value.primary.0;
            if !valid || alias {
                value.duplicate.0 = null_mut();
            }
            ensure!(
                success != 0 && valid && !alias,
                "scratch diagnostic duplicate open failed winerror={code} aliased={alias}"
            );
            let duplicate = Snapshot::read(value.duplicate.0, true)?;
            expected.same(&duplicate)?;
            value.frames.push(expected.privileges.frame("primary")?);
            value.frames.push(duplicate.privileges.frame("duplicate")?);
            value.expected = Some(expected);
            Ok(())
        })();
        if let Err(error) = result {
            return access::combine(Err(error), value.close());
        }
        Ok(value)
    }
    pub(super) fn enter(&self) -> Result<()> {
        require_host()?;
        ensure!(
            !self.impersonating.get() && self.expected.is_some(),
            "scratch diagnostic context is unavailable"
        );
        ensure!(
            unsafe { ImpersonateLoggedOnUser(self.duplicate.0) } != 0,
            "{}",
            access::native_error("enter scratch diagnostic context")
        );
        self.impersonating.set(true);
        Ok(())
    }
    pub(super) fn leave(&self) {
        if self.impersonating.replace(false)
            && (unsafe { RevertToSelf() } == 0 || require_host().is_err())
        {
            std::process::abort();
        }
    }
    pub(super) fn check(&self, owners: &ProbeOwners) -> Result<()> {
        ensure!(
            self.impersonating.get(),
            "scratch diagnostic thread is not impersonating"
        );
        let mut token = null_mut();
        let success = unsafe { OpenThreadToken(GetCurrentThread(), 8, 1, &mut token) };
        let code = if success == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        owners.opened(token as usize);
        let result = (|| {
            ensure!(
                success != 0 && scratch::valid_handle(token as usize),
                "scratch diagnostic effective token open failed winerror={code}"
            );
            let actual = Snapshot::read(token, true)?;
            self.expected
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("scratch diagnostic snapshot absent"))?
                .same(&actual)?;
            self.effective.replace(Some(actual.privileges));
            Ok(())
        })();
        access::combine(result, owners.close(token as usize))
    }
    pub(super) fn scoped<T>(&self, body: impl FnOnce() -> Result<T>) -> Result<T> {
        self.enter()?;
        struct Revert<'a>(&'a Context);
        impl Drop for Revert<'_> {
            fn drop(&mut self) {
                self.0.leave();
            }
        }
        let guard = Revert(self);
        let result = body();
        drop(guard);
        result
    }
    pub(super) fn finish_frames(&self) -> Result<Vec<String>> {
        let mut frames = self.frames.clone();
        frames.push(
            self.effective
                .borrow()
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!("scratch diagnostic effective inventory was not observed")
                })?
                .frame("effective")?,
        );
        Ok(frames)
    }
    pub(super) fn close(&mut self) -> Result<()> {
        self.leave();
        self.expected.take();
        let duplicate = self.duplicate.close();
        access::combine(duplicate, self.primary.close())
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileAttributesW(path: *const u16) -> u32;
    fn SetFileInformationByHandle(
        handle: Handle,
        class: u32,
        data: *const std::ffi::c_void,
        size: u32,
    ) -> i32;
}

fn absent(path: &[u16]) -> Result<()> {
    let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
    let error = if attributes == u32::MAX {
        unsafe { GetLastError() }
    } else {
        0
    };
    file::require_file_absent(attributes, error)
}
pub(super) fn file_creations(
    volume: &ScratchVolume,
    refs: &References,
    context: &Context,
    owners: &ProbeOwners,
    deadline: &dyn Fn() -> Result<()>,
) -> Result<[u32; 2]> {
    let path = wide(std::path::Path::new(&format!(
        "{}scratch-file-control",
        volume.drive_root()
    )));
    let mut errors = [0; 2];
    for (role, error) in errors.iter_mut().enumerate() {
        let host = role == 0;
        *error = actual(file::file_creation(
            host,
            file::FileCalls {
                create: &mut |value| {
                    file::file_create_request(
                        "scratch-file-control",
                        value,
                        |request| {
                            let handle = unsafe {
                                CreateFileW(
                                    path.as_ptr(),
                                    request.access,
                                    request.share,
                                    null(),
                                    request.disposition,
                                    request.flags,
                                    null_mut(),
                                )
                            };
                            owners.opened(handle as usize);
                            handle as usize
                        },
                        || unsafe { GetLastError() },
                    );
                    Ok(())
                },
                enter: &mut || {
                    modeled((|| {
                        deadline()?;
                        require_host()?;
                        if !host {
                            context.enter()?;
                        }
                        Ok(())
                    })())
                },
                check: &mut || {
                    modeled((|| {
                        deadline()?;
                        if !host {
                            context.check(owners)?;
                        }
                        Ok(())
                    })())
                },
                leave: &mut || {
                    if !host {
                        context.leave();
                    }
                },
                bind: &mut |value| {
                    modeled((|| {
                        deadline()?;
                        let handle = unsafe {
                            CreateFileW(path.as_ptr(), 0x80, 7, null(), 3, 0x200000, null_mut())
                        };
                        value.pin = handle as usize;
                        owners.opened(value.pin);
                        ensure!(
                            scratch::valid_handle(value.pin),
                            "{}",
                            access::native_error("pin scratch diagnostic file")
                        );
                        let id = access::identity(handle, false)?;
                        ensure!(
                            id.volume == refs.root_id.volume
                                && access::identity(value.handle as Handle, false)? == id,
                            "scratch diagnostic created-file identity differs"
                        );
                        value.identity = scratch::FileIdentity {
                            volume: id.volume,
                            high: id.high,
                            low: id.low,
                        };
                        Ok(())
                    })())
                },
                close: &mut |handle| modeled(owners.close(handle)),
                remove: &mut |value| {
                    modeled({
                        let raw = unsafe {
                            CreateFileW(path.as_ptr(), 0x10080, 3, null(), 3, 0x200000, null_mut())
                        };
                        owners.opened(raw as usize);
                        let result = (|| {
                            ensure!(
                                scratch::valid_handle(raw as usize),
                                "{}",
                                access::native_error("open scratch diagnostic file cleanup")
                            );
                            let id = access::identity(raw, false)?;
                            let expected = Identity {
                                volume: value.identity.volume,
                                high: value.identity.high,
                                low: value.identity.low,
                            };
                            ensure!(
                                id == expected
                                    && access::identity(value.pin as Handle, false)? == expected,
                                "scratch diagnostic deletion identity differs"
                            );
                            let remove = 1u8;
                            ensure!(
                                unsafe {
                                    SetFileInformationByHandle(
                                        raw,
                                        4,
                                        (&remove as *const u8).cast(),
                                        1,
                                    )
                                } != 0,
                                "{}",
                                access::native_error("mark scratch diagnostic file for deletion")
                            );
                            Ok(())
                        })();
                        access::combine(result, owners.close(raw as usize))
                    })
                },
                absent: &mut || {
                    modeled((|| {
                        deadline()?;
                        absent(&path)
                    })())
                },
                release: &mut |value| modeled(owners.close(std::mem::take(&mut value.pin))),
            },
        ))?;
    }
    deadline()?;
    Ok(errors)
}
