//! Exact actual-token identity and scoped disposable default-owner impersonation.
#[cfg(test)]
use crate::windows_security::activation::Failures;
use crate::windows_security::{activation::native::require_host, policy::within};
use anyhow::{Result, ensure};
use registry_authority::native::{
    GetCurrentProcess, GetTokenInformation, NtQuerySecurityAttributesToken, OpenProcessToken,
    Unicode,
};
use std::{ffi::c_void, ptr::null_mut};
pub(super) type Raw = *mut c_void;
#[link(name = "advapi32")]
unsafe extern "system" {
    fn DuplicateTokenEx(
        token: Raw,
        access: u32,
        attributes: Raw,
        level: i32,
        kind: i32,
        output: *mut Raw,
    ) -> i32;
    fn SetTokenInformation(token: Raw, kind: i32, data: Raw, length: u32) -> i32;
    fn ImpersonateLoggedOnUser(token: Raw) -> i32;
    fn RevertToSelf() -> i32;
    fn OpenThreadToken(thread: Raw, access: u32, as_self: i32, token: *mut Raw) -> i32;
    fn ConvertSidToStringSidW(sid: Raw, text: *mut *mut u16) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentThread() -> Raw;
    fn GetLastError() -> u32;
    fn CloseHandle(handle: Raw) -> i32;
    fn LocalFree(memory: Raw) -> Raw;
}
pub(super) fn finish<T>(result: Result<T>, errors: Vec<anyhow::Error>) -> Result<T> {
    crate::windows_security::policy::token_validation::finish(result, errors)
}
pub(super) struct Handle(pub Raw);
impl Handle {
    fn outcome(success: i32, raw: Raw, code: u32, operation: &'static str) -> Result<Self> {
        let mut owner = Self(if raw as isize == -1 { null_mut() } else { raw });
        let result = (|| {
            ensure!(
                success != 0 && !owner.0.is_null(),
                "SxS token operation failed operation={operation} winerror={code}"
            );
            Ok(())
        })();
        if let Err(primary) = result {
            let errors = owner.close().err().into_iter().collect();
            return finish(Err(primary), errors);
        }
        Ok(owner)
    }
    pub fn close(&mut self) -> Result<()> {
        if self.0.is_null() {
            return Ok(());
        }
        let raw = std::mem::replace(&mut self.0, null_mut());
        let success = unsafe { CloseHandle(raw) };
        let code = if success == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        ensure!(success != 0, "SxS token close failed winerror={code}");
        Ok(())
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
#[derive(Clone)]
struct Query {
    words: Vec<u64>,
    length: usize,
}
impl Query {
    fn read(token: Raw, kind: i32, ceiling: u32) -> Result<Self> {
        let mut returned = 0;
        let initial = unsafe { GetTokenInformation(token, kind, null_mut(), 0, &mut returned) };
        let code = if initial == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        ensure!(
            initial == 0 && code == 122 && (4..=ceiling).contains(&returned),
            "invalid SxS token query size kind={kind} winerror={code}"
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
            "invalid SxS token query result kind={kind} winerror={code}"
        );
        data.length = returned as usize;
        Ok(data)
    }
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.length) }
    }
    #[cfg(test)]
    fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast(), self.length) }
    }
    fn dword(&self, at: usize) -> Result<u32> {
        let bytes = self
            .bytes()
            .get(at..at + 4)
            .ok_or_else(|| anyhow::anyhow!("short SxS token scalar"))?;
        Ok(u32::from_le_bytes(bytes.try_into()?))
    }
    fn sid(&self, at: usize, minimum: usize) -> Result<Vec<u8>> {
        let header = self
            .bytes()
            .get(at..at + 8)
            .ok_or_else(|| anyhow::anyhow!("short SxS token SID pointer"))?;
        let pointer = u64::from_le_bytes(header.try_into()?);
        let base = self.words.as_ptr() as u64;
        ensure!(
            self.length >= minimum
                && within(base, self.length as u64, pointer, 8, 4)
                && pointer - base >= minimum as u64,
            "SxS token SID outside returned allocation"
        );
        let offset = (pointer - base) as usize;
        let bytes = &self.bytes()[offset..];
        ensure!(
            bytes[0] == 1 && bytes[1] <= 15,
            "invalid SxS token SID header"
        );
        let length = 8 + 4 * usize::from(bytes[1]);
        ensure!(length <= bytes.len(), "truncated SxS token SID");
        Ok(bytes[..length].to_vec())
    }
}
impl Drop for Query {
    fn drop(&mut self) {
        self.words.fill(0);
    }
}
fn scalar(token: Raw, kind: i32) -> Result<u32> {
    let data = Query::read(token, kind, 65536)?;
    ensure!(data.length == 4, "SxS token scalar ABI differs");
    data.dword(0)
}
fn sid(token: Raw, kind: i32) -> Result<Vec<u8>> {
    Query::read(token, kind, 256)?.sid(0, if kind == 1 { 16 } else { 8 })
}
fn groups(token: Raw, kind: i32) -> Result<Vec<(Vec<u8>, u32)>> {
    let data = Query::read(token, kind, 65536)?;
    let count = data.dword(0)? as usize;
    ensure!(
        count <= 256 && (count == 0 || 8 + count * 16 <= data.length),
        "SxS token group budget exceeded"
    );
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let at = 8 + index * 16;
        entries.push((data.sid(at, 8 + count * 16)?, data.dword(at + 8)?));
    }
    entries.sort();
    Ok(entries)
}
fn lpac(token: Raw) -> Result<()> {
    let name = "WIN://NOALLAPPPKG".encode_utf16().collect::<Vec<_>>();
    let query = Unicode {
        length: (name.len() * 2) as u16,
        maximum: (name.len() * 2) as u16,
        buffer: name.as_ptr(),
    };
    let mut data = Query {
        words: vec![0; 64],
        length: 512,
    };
    let mut returned = 0;
    let status = unsafe {
        NtQuerySecurityAttributesToken(
            token,
            &query,
            1,
            data.words.as_mut_ptr().cast(),
            512,
            &mut returned,
        )
    };
    ensure!(
        status == 0 && (16..=512).contains(&returned),
        "SxS LPAC named attribute query failed ntstatus={:08X}",
        status as u32
    );
    data.length = returned as usize;
    require_lpac(&data, &name)
}
fn require_lpac(data: &Query, name: &[u16]) -> Result<()> {
    use crate::windows_security::policy::profile_validation::registry_context;
    ensure!(
        name.iter()
            .copied()
            .eq(registry_context::LPAC_NAME.encode_utf16()),
        "SxS LPAC fixed query name differs"
    );
    registry_context::require_lpac(data.bytes(), data.words.as_ptr() as u64)
}
#[derive(Clone)]
struct Snapshot {
    user: Vec<u8>,
    package: Vec<u8>,
    restricted: Vec<(Vec<u8>, u32)>,
}
impl Snapshot {
    fn read(token: Raw, duplicate: bool) -> Result<Self> {
        ensure!(
            scalar(token, 8)? == if duplicate { 2 } else { 1 },
            "SxS authority token type differs"
        );
        ensure!(
            !duplicate || scalar(token, 9)? == 2,
            "SxS authority impersonation level differs"
        );
        ensure!(
            scalar(token, 29)? == 1 && groups(token, 30)?.is_empty(),
            "SxS authority lost zero-capability AppContainer identity"
        );
        lpac(token)?;
        Ok(Self {
            user: sid(token, 1)?,
            package: sid(token, 31)?,
            restricted: groups(token, 11)?,
        })
    }
    fn require_same(&self, actual: &Self) -> Result<()> {
        use crate::windows_security::policy::profile_validation::registry_context::{
            Identity, require_equal,
        };
        require_equal(
            Identity {
                user: &self.user,
                package: &self.package,
                restricted: &self.restricted,
            },
            Identity {
                user: &actual.user,
                package: &actual.package,
                restricted: &actual.restricted,
            },
        )
    }
}
fn open(process: Raw) -> Result<Handle> {
    let mut raw = null_mut();
    let success = unsafe { OpenProcessToken(process, 0xa, &mut raw) };
    let code = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    Handle::outcome(success, raw, code, "open-primary")
}
fn duplicate(token: Raw, owner: bool) -> Result<Handle> {
    let mut raw = null_mut();
    let success = unsafe {
        DuplicateTokenEx(
            token,
            if owner { 0x8c } else { 0xc },
            null_mut(),
            2,
            2,
            &mut raw,
        )
    };
    let code = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let mut value = Handle::outcome(success, raw, code, "duplicate-primary")?;
    if value.0 == token {
        value.0 = null_mut();
        anyhow::bail!("SxS duplicate token aliased primary");
    }
    Ok(value)
}
fn effective() -> Result<Handle> {
    let mut raw = null_mut();
    let success = unsafe { OpenThreadToken(GetCurrentThread(), 8, 1, &mut raw) };
    let code = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    Handle::outcome(success, raw, code, "open-effective")
}
struct Impersonation(bool);
impl Impersonation {
    fn restore(&mut self) {
        if self.0 {
            self.0 = false;
            if unsafe { RevertToSelf() } == 0 || require_host().is_err() {
                std::process::abort();
            }
        }
    }
}
impl Drop for Impersonation {
    fn drop(&mut self) {
        self.restore();
    }
}
fn scoped<T>(token: Raw, body: impl FnOnce() -> Result<T>) -> Result<T> {
    require_host()?;
    let success = unsafe { ImpersonateLoggedOnUser(token) };
    let code = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    ensure!(
        success != 0,
        "SxS token impersonation failed winerror={code}"
    );
    let mut scope = Impersonation(true);
    let result = body();
    scope.restore();
    result
}
fn require_owner_identity(
    expected: &[u8],
    user: &[u8],
    owner: &[u8],
    kind: u32,
    level: u32,
    duplicate: bool,
    strict: bool,
) -> Result<()> {
    super::canary::identity(expected, user, owner, kind, level, duplicate, strict)
}
fn check_owner(token: Raw, expected: &[u8], duplicate: bool, strict: bool) -> Result<()> {
    canary_owner::check_owner(token, expected, duplicate, strict)
}

pub(crate) fn current_user_sid() -> Result<String> {
    require_host()?;
    let mut raw = null_mut();
    let success = unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut raw) };
    let code = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let mut primary = Handle::outcome(success, raw, code, "current-user")?;
    let result = sid(primary.0, 1).and_then(|user| sid_text(&user));
    finish(result, primary.close().err().into_iter().collect())
}
pub(super) fn host_user() -> Result<Vec<u8>> {
    require_host()?;
    let mut primary = open(unsafe { GetCurrentProcess() })?;
    let result = (|| {
        let user = sid(primary.0, 1)?;
        ensure!(
            user != [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            "SxS storage host cannot be SYSTEM"
        );
        check_owner(primary.0, &user, false, false)?;
        Ok(user)
    })();
    finish(result, primary.close().err().into_iter().collect())
}
pub(super) fn owner<T>(body: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
    canary_owner::owner(body)
}

pub(super) fn sid_text(bytes: &[u8]) -> Result<String> {
    let mut words = vec![0u32; bytes.len().div_ceil(4)];
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), words.as_mut_ptr().cast(), bytes.len());
    }
    let mut text = null_mut();
    let success = unsafe { ConvertSidToStringSidW(words.as_mut_ptr().cast(), &mut text) };
    let code = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let result = (|| {
        ensure!(
            success != 0 && !text.is_null(),
            "SxS SID conversion failed winerror={code}"
        );
        let mut length = 0;
        while length < 256 && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        ensure!(length < 256, "SxS SID conversion exceeds bound");
        Ok(String::from_utf16(unsafe {
            std::slice::from_raw_parts(text, length)
        })?)
    })();
    words.fill(0);
    let errors = if !text.is_null() && !unsafe { LocalFree(text.cast()) }.is_null() {
        vec![anyhow::anyhow!("SxS SID conversion close failed")]
    } else {
        vec![]
    };
    finish(result, errors)
}
#[path = "native_context.rs"]
mod context;
pub(super) use context::authority;
#[cfg(test)]
use context::{authority_context, startup_outcome, startup_query};
pub(crate) use context::{observe_startup_token, with_authority};
#[cfg(test)]
#[path = "native_identity_tests.rs"]
mod tests;

#[path = "native_canary.rs"]
mod canary_owner;
