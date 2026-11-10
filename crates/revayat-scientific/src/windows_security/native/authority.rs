//! Fixed authoritative registry probe in an owned, zero-capability LPAC.
use super::*;
use crate::windows_security::{Capture, ERROR_LIMIT, OUTPUT_LIMIT, privilege_inventory};
use std::io::Write;

#[path = "authority_abi.rs"]
mod abi;
#[path = "authority_image.rs"]
mod authority_image;
#[path = "authority_observer.rs"]
mod observer;
pub(crate) use observer::AuthorityObserver;
use observer::NoObserver;
#[path = "authority_creation.rs"]
mod creation;
#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
use abi::*;
use creation::{creation_result, retain_cleanup};

pub(super) fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

pub(super) struct Descriptor(pub(super) Handle);
impl Descriptor {
    pub(super) fn new(sddl: &str) -> Result<Self> {
        let text = wide(sddl);
        let mut descriptor = null_mut();
        let mut bytes = 0;
        // SAFETY: live terminated SDDL and initialized output slots.
        ensure!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut descriptor,
                    &mut bytes,
                )
            } != 0,
            "parse owned process security"
        );
        ensure!(
            !descriptor.is_null() && (20..=65536).contains(&bytes),
            "invalid process descriptor"
        );
        Ok(Self(descriptor))
    }
    pub(super) fn close(&mut self) -> Result<()> {
        if !self.0.is_null() {
            let descriptor = std::mem::replace(&mut self.0, null_mut());
            ensure!(
                unsafe { LocalFree(descriptor) }.is_null(),
                "process descriptor cleanup failed"
            );
        }
        Ok(())
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

struct Owned(Handle);
impl Owned {
    fn creation_output(handle: Handle) -> Self {
        // Defensive only: an invalid creation output must not become a pseudo-process owner.
        Self(if handle as isize == -1 {
            null_mut()
        } else {
            handle
        })
    }
    fn checked(handle: Handle) -> Result<Self> {
        ensure!(
            !handle.is_null() && handle as isize != -1,
            "invalid native owner"
        );
        Ok(Self(handle))
    }
    fn close(&mut self) -> Result<()> {
        if self.0.is_null() {
            return Ok(());
        }
        let handle = std::mem::replace(&mut self.0, null_mut());
        // SAFETY: exclusive handle ownership invalidated before close.
        ensure!(
            unsafe { CloseHandle(handle) } != 0,
            "native handle cleanup failed"
        );
        Ok(())
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
fn restricted_primary() -> Result<Owned> {
    let mut original = null_mut();
    // SAFETY: borrowed pseudo handle; returned primary-token handle immediately owned.
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), 0xb, &mut original) } != 0,
        "open primary for restricted copy"
    );
    let mut original = Owned::checked(original)?;
    // Complete binary SID S-1-5-32-544, with native DWORD alignment.
    let mut administrator = [0x0000_0201u32, 0x0500_0000, 32, 544];
    let disabled = SidAttributes {
        sid: administrator.as_mut_ptr().cast(),
        attributes: 0,
    };
    let mut restricted = null_mut();
    // SAFETY: exact live SID_AND_ATTRIBUTES; create a restricted LUA primary,
    // never SANDBOX_INERT and never an unrestricted fallback.
    let success = unsafe {
        CreateRestrictedToken(
            original.0,
            5,
            1,
            &disabled,
            0,
            null_mut(),
            0,
            null_mut(),
            &mut restricted,
        )
    };
    let creation = creation_result(
        success,
        !restricted.is_null() && restricted as isize != -1,
        "CreateRestrictedToken",
        || unsafe { GetLastError() },
    );
    let mut owner = Owned::creation_output(restricted);
    let mut cleanup = usize::from(original.close().is_err());
    if (creation.is_err() || cleanup != 0) && owner.close().is_err() {
        cleanup += 1;
    }
    retain_cleanup(creation, cleanup)?;
    Ok(owner)
}
struct Profile {
    name: Vec<u16>,
    sid: Handle,
    created: bool,
    outer_recovery: bool,
}
impl Profile {
    fn new() -> Result<Self> {
        let mut storage = profile_storage::Storage::before_create()?;
        let mut profile = Self {
            name: storage.name(),
            sid: null_mut(),
            created: false,
            outer_recovery: false,
        };
        // The exact new package path and expected derived SID were bound before creation.
        let status = unsafe {
            CreateAppContainerProfile(
                profile.name.as_ptr(),
                profile.name.as_ptr(),
                profile.name.as_ptr(),
                null_mut(),
                0,
                &mut profile.sid,
            )
        };
        profile.created = status == 0;
        let result = (|| {
            ensure!(
                status == 0 && !profile.sid.is_null(),
                "create owned AppContainer profile failed hresult={:08X}",
                status as u32
            );
            storage.prepare(profile.sid, |record| NoObserver.token_metadata(record))
        })();
        let storage_cleanup = storage.close();
        let uncertain = storage_cleanup.is_err();
        let result = profile_storage::combine(result, storage_cleanup);
        if let Err(primary) = result {
            // A failed close never authorizes deleting a profile with potentially live objects.
            let cleanup = if uncertain {
                profile.retain()
            } else {
                profile.close()
            };
            return profile_storage::combine(Err(primary), cleanup);
        }
        Ok(profile)
    }
    fn new_owned(view: &super::state::NativeRunView) -> Result<Self> {
        view.require()?;
        let mut storage =
            profile_storage::Storage::for_profile(&view.profile_name(), view.package_sid())?;
        view.begin_profile()?;
        let mut profile = Self {
            name: storage.name(),
            sid: null_mut(),
            created: false,
            outer_recovery: true,
        };
        let status = unsafe {
            CreateAppContainerProfile(
                profile.name.as_ptr(),
                profile.name.as_ptr(),
                profile.name.as_ptr(),
                null_mut(),
                0,
                &mut profile.sid,
            )
        };
        profile.created = status == 0;
        let recorded = view.profile_result(status);
        let result = (|| {
            ensure!(
                status == 0 && !profile.sid.is_null(),
                "create owned AppContainer profile failed hresult={:08X}",
                status as u32
            );
            storage.prepare(profile.sid, |record| NoObserver.token_metadata(record))
        })();
        let result = profile_storage::combine(result, recorded);
        let result = profile_storage::combine(result, storage.close());
        if let Err(primary) = result {
            return profile_storage::combine(Err(primary), profile.close());
        }
        Ok(profile)
    }
    fn sid_text(&self) -> Result<String> {
        profile_storage::sid_text(self.sid)
    }
    fn retain(&mut self) -> Result<()> {
        // Uncertain retained keys/files/processes forbid deleting their owned profile.
        self.created = false;
        let sid = std::mem::replace(&mut self.sid, null_mut());
        if !sid.is_null() {
            ensure!(
                unsafe { FreeSid(sid) }.is_null(),
                "retained profile SID cleanup failed"
            );
        }
        Ok(())
    }
    fn close(&mut self) -> Result<()> {
        self.close_with(
            |sid| {
                ensure!(
                    unsafe { FreeSid(sid) }.is_null(),
                    "owned profile SID cleanup failed"
                );
                Ok(())
            },
            |name| {
                let status = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
                ensure!(
                    status == 0,
                    "owned profile deletion failed hresult={:08X}",
                    status as u32
                );
                Ok(())
            },
        )
    }
    fn close_with(
        &mut self,
        free: impl FnOnce(Handle) -> Result<()>,
        delete: impl FnOnce(&[u16]) -> Result<()>,
    ) -> Result<()> {
        let sid = std::mem::replace(&mut self.sid, null_mut());
        let created = std::mem::replace(&mut self.created, false);
        let released = if sid.is_null() { Ok(()) } else { free(sid) };
        // Successful creation owns profile deletion independently of a malformed NULL SID output.
        let deleted = if created && !self.outer_recovery {
            delete(&self.name)
        } else {
            Ok(())
        };
        profile_storage::combine(released, deleted)
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
struct Attributes {
    data: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn new() -> Result<Self> {
        Self::with_count(3)
    }
    fn with_count(count: u32) -> Result<Self> {
        ensure!(
            matches!(count, 1 | 3),
            "unsupported fixed process attribute count"
        );
        let mut size = 0;
        // SAFETY: size-only call cannot dereference null list.
        unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        ensure!(
            (1..=65536).contains(&size),
            "invalid process attribute size"
        );
        let mut value = Self {
            data: vec![0; size.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        // SAFETY: aligned allocation spans requested size and remains live until deletion.
        ensure!(
            unsafe {
                InitializeProcThreadAttributeList(
                    value.data.as_mut_ptr().cast(),
                    count,
                    0,
                    &mut size,
                )
            } != 0,
            "initialize process attributes"
        );
        value.initialized = true;
        Ok(value)
    }
    fn set(&mut self, key: usize, pointer: Handle, size: usize) -> Result<()> {
        // SAFETY: caller retains pointed attribute values until after CreateProcessW.
        ensure!(
            unsafe {
                UpdateProcThreadAttribute(
                    self.data.as_mut_ptr().cast(),
                    0,
                    key,
                    pointer,
                    size,
                    null_mut(),
                    null_mut(),
                )
            } != 0,
            "set process attribute"
        );
        Ok(())
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe { DeleteProcThreadAttributeList(self.data.as_mut_ptr().cast()) };
        }
    }
}
fn pipe() -> Result<(Owned, Owned)> {
    let mut read = null_mut();
    let mut write = null_mut();
    let security = Security {
        size: size_of::<Security>() as u32,
        descriptor: null_mut(),
        inherit: 1,
    };
    // SAFETY: exact writable handle slots and live attributes.
    let success = unsafe { CreatePipe(&mut read, &mut write, &security, 4096) };
    let reader = Owned(read);
    let writer = Owned(write);
    ensure!(
        success != 0 && !reader.0.is_null() && !writer.0.is_null(),
        "create capture pipe"
    );
    // SAFETY: read endpoint remains exclusively in controller.
    ensure!(
        unsafe { SetHandleInformation(reader.0, 1, 0) } != 0,
        "disable capture reader inheritance"
    );
    Ok((reader, writer))
}
fn remove_privileges(process: Handle) -> Result<()> {
    let mut raw = null_mut();
    // SAFETY: owned suspended process; returned token immediately owned.
    ensure!(
        unsafe { OpenProcessToken(process, 0x28, &mut raw) } != 0,
        "open suspended worker token"
    );
    let mut token = Owned::checked(raw)?;
    let mut size = 0;
    unsafe { GetTokenInformation(token.0, 3, null_mut(), 0, &mut size) };
    ensure!((4..=65536).contains(&size), "invalid privilege query size");
    let mut data = vec![0u32; (size as usize).div_ceil(4)];
    let capacity = size;
    // SAFETY: aligned writable allocation covers advertised capacity.
    ensure!(
        unsafe { GetTokenInformation(token.0, 3, data.as_mut_ptr().cast(), capacity, &mut size) }
            != 0
            && size <= capacity,
        "read worker privilege inventory"
    );
    let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), size as usize) };
    ensure!(bytes.len() >= 4, "short privilege header");
    let count = u32::from_le_bytes(bytes[..4].try_into()?) as usize;
    ensure!(
        count <= 128 && 4 + count * 12 <= bytes.len(),
        "invalid privilege inventory"
    );
    let mut remove = vec![0u32];
    for entry in bytes[4..4 + count * 12].as_chunks::<12>().0 {
        let luid = u64::from_le_bytes(entry[..8].try_into()?);
        if luid != 23 {
            remove[0] += 1;
            remove.extend([luid as u32, (luid >> 32) as u32, 4]);
        }
    }
    if remove[0] > 0 {
        // SAFETY: packed TOKEN_PRIVILEGES with native 4-byte alignment, exact count and entries.
        unsafe { SetLastError(0) };
        let success = unsafe {
            AdjustTokenPrivileges(
                token.0,
                0,
                remove.as_ptr().cast(),
                0,
                null_mut(),
                null_mut(),
            )
        };
        let error = unsafe { GetLastError() };
        ensure!(
            success != 0 && error == 0,
            "worker privileges were not fully removed"
        );
    }
    // SAFETY: reuse owned bounded allocation and validate returned span independently.
    ensure!(
        unsafe { GetTokenInformation(token.0, 3, data.as_mut_ptr().cast(), capacity, &mut size) }
            != 0
            && size <= capacity,
        "read final worker privileges"
    );
    privilege_inventory(
        unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), capacity as usize) },
        size as usize,
    )?;
    data.fill(0);
    remove.fill(0);
    token.close()
}
fn metadata_unknown(stage: &str, code: u32) -> String {
    let code = code as i32; // Match Marshal.GetLastWin32Error's original signed field.
    format!(
        "WINDOWS_DEFAULT_DACL status=unknown stage={stage} native_error={code} effective_access_proved=False"
    )
}
fn read_default_metadata(
    mut query: impl FnMut(i32, &mut [u64]) -> std::result::Result<usize, u32>,
    close: impl FnOnce() -> Result<()>,
) -> Result<String> {
    use crate::windows_security::policy::{
        DefaultAclSummary, default_acl_summary, token_default_acl, token_metadata_sid,
    };
    // Fixed, eight-byte-aligned capacity is shared by all three same-token queries.
    let mut buffer = vec![0u64; 65536 / 8];
    let start = buffer.as_ptr() as u64;
    let mut acl = Vec::new();
    let mut user = Vec::new();
    let mut package = Vec::new();
    let observed = (|| -> std::result::Result<String, (&'static str, u32)> {
        let returned = query(6, &mut buffer).map_err(|code| ("query-default", code))?;
        if !(8..=65536).contains(&returned) {
            return Err(("default-length", 0));
        }
        // SAFETY: fixed allocation is live; only the bounded returned span is decoded.
        let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned) };
        let Some(value) = token_default_acl(bytes, start).map_err(|stage| (stage, 0))? else {
            return Ok(DefaultAclSummary {
                is_null: true,
                ..Default::default()
            }
            .record(0));
        };
        acl.extend_from_slice(value); // Native query reuse must not overwrite the ACL being summarized.
        for (kind, output) in [(1, &mut user), (31, &mut package)] {
            buffer.fill(0);
            let returned = query(kind, &mut buffer).map_err(|_| ("identity-query", 0))?;
            if returned > 65536 {
                return Err(("identity-query", 0));
            }
            let bytes =
                unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned) };
            output.extend_from_slice(
                token_metadata_sid(bytes, start, kind == 1).map_err(|_| ("identity-query", 0))?,
            );
        }
        default_acl_summary(Some(&acl), &user, &package)
            .map(|value| value.record(acl.len()))
            .map_err(|_| ("managed-structure", 0))
    })();
    buffer.fill(0);
    acl.fill(0);
    user.fill(0);
    package.fill(0);
    let record = match observed {
        Ok(record) => record,
        Err((stage, code)) => metadata_unknown(stage, code),
    };
    close().map_err(|_| anyhow::anyhow!("close default-DACL diagnostic token failed"))?;
    Ok(record)
}
fn default_metadata(process: Handle) -> Result<String> {
    if size_of::<usize>() != 8 {
        return Ok(metadata_unknown("unsupported-abi", 0));
    }
    let mut raw = null_mut();
    let success = unsafe { OpenProcessToken(process, 8, &mut raw) };
    let error = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let mut token = Owned::creation_output(raw);
    if success == 0 || token.0.is_null() {
        token
            .close()
            .map_err(|_| anyhow::anyhow!("close default-DACL diagnostic token failed"))?;
        return Ok(metadata_unknown("open-token", error));
    }
    let handle = token.0;
    read_default_metadata(
        |kind, buffer| {
            let mut returned = 0;
            let success = unsafe {
                GetTokenInformation(
                    handle,
                    kind,
                    buffer.as_mut_ptr().cast(),
                    65536,
                    &mut returned,
                )
            };
            let error = if success == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            if success == 0 {
                Err(error)
            } else {
                Ok(returned as usize)
            }
        },
        || token.close(),
    )
}
fn drain(pipe: &Owned, capture: &mut Capture, limit: usize) -> Result<()> {
    for _ in 0..=limit {
        let mut available = 0;
        // SAFETY: read-only pipe query and writable scalar output.
        let success = unsafe {
            PeekNamedPipe(
                pipe.0,
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        };
        if success == 0 {
            ensure!(
                unsafe { GetLastError() } == 109,
                "capture pipe query failed"
            );
            capture.end();
            return Ok(());
        }
        if available == 0 {
            return Ok(());
        }
        let mut buffer = [0u8; 1024];
        let capacity = (available as usize).min(buffer.len());
        let mut read = 0;
        // SAFETY: live owned pipe, writable stack buffer, capacity does not exceed storage.
        ensure!(
            unsafe {
                ReadFile(
                    pipe.0,
                    buffer.as_mut_ptr().cast(),
                    capacity as u32,
                    &mut read,
                    null_mut(),
                )
            } != 0
                && read > 0
                && read as usize <= capacity,
            "capture pipe read failed"
        );
        capture.append(&buffer[..read as usize], limit)?;
    }
    anyhow::bail!("capture read budget exhausted")
}

#[path = "authority_run.rs"]
mod runner;
pub(crate) use runner::run_observed;
pub(super) fn assigned_package(name: &str) -> Result<String> {
    profile_storage::Storage::assigned_sid(name)
}
#[path = "profile_registry.rs"]
mod profile_registry;
#[path = "profile_storage.rs"]
mod profile_storage;
#[path = "startup_access.rs"]
mod startup_access;
#[path = "sxs_tool.rs"]
mod sxs_tool;
pub use runner::{run_owned_registry_authority, run_registry_authority};
pub(crate) use sxs_tool::run as run_sxs_tool;
