//! Actual current LPAC profile-registry positive and all frozen mutation negatives.
use super::super::{ffi::*, token};
use crate::windows_security::kernel_controls::KernelPlan;
use anyhow::{Result, ensure};
use registry_authority::native::{Attributes, NtOpenKeyEx, NtQueryKey, NtQueryObject, Unicode};
use std::ptr::null_mut;
#[link(name = "userenv")]
unsafe extern "system" {
    fn GetAppContainerRegistryLocation(access: u32, key: *mut Raw) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegCloseKey(key: Raw) -> i32;
    fn RegOpenKeyExW(
        key: Raw,
        name: *const u16,
        options: u32,
        access: u32,
        result: *mut Raw,
    ) -> i32;
    fn RegCreateKeyExW(
        key: Raw,
        name: *const u16,
        reserved: u32,
        class: *const u16,
        options: u32,
        access: u32,
        security: Raw,
        result: *mut Raw,
        disposition: *mut u32,
    ) -> i32;
}
fn valid(raw: Raw) -> bool {
    let value = raw as usize;
    value > 0 && value < 0x7fffffffffffffff && !(0x80000000..=0x800000ff).contains(&value)
}
struct Key(Raw);
impl Key {
    fn close(&mut self) -> Result<()> {
        if self.0.is_null() {
            return Ok(());
        }
        let raw = std::mem::replace(&mut self.0, null_mut());
        ensure!(
            unsafe { RegCloseKey(raw) } == 0,
            "kernel profile registry handle close failed"
        );
        Ok(())
    }
}
impl Drop for Key {
    fn drop(&mut self) {
        if self.close().is_err() {
            note_cleanup_failure();
        }
    }
}
fn qualify(key: Raw, requested: u32) -> Result<String> {
    ensure!(
        valid(key),
        "kernel profile API returned pseudo/predefined key"
    );
    let mut basic = [0u32; 14];
    let mut returned = 0;
    ensure!(
        unsafe { NtQueryObject(key, 0, basic.as_mut_ptr().cast(), 56, &mut returned) } == 0
            && returned == 56
            && basic[1] & !0x20019 == 0
            && basic[1] & requested == requested,
        "kernel profile granted-access result differs"
    );
    let mut name = [0u64; 512];
    let mut returned = 0;
    let status = unsafe { NtQueryKey(key, 3, name.as_mut_ptr().cast(), 4096, &mut returned) };
    let result = (|| {
        ensure!(
            status == 0 && (4..=4096).contains(&returned),
            "kernel profile key identity query failed"
        );
        let bytes =
            unsafe { std::slice::from_raw_parts(name.as_ptr().cast::<u8>(), returned as usize) };
        let count = u32::from_le_bytes(bytes[..4].try_into()?) as usize;
        ensure!(
            count > 0 && count.is_multiple_of(2) && count <= bytes.len() - 4,
            "kernel profile key identity length differs"
        );
        let mut units = bytes[4..4 + count]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .collect::<Vec<_>>();
        let text = String::from_utf16(&units)
            .map_err(|_| anyhow::anyhow!("kernel profile key identity encoding differs"));
        units.fill(0);
        let text = text?;
        ensure!(
            !text.contains('\0'),
            "kernel profile key identity contains NUL"
        );
        Ok(text)
    })();
    name.fill(0);
    basic.fill(0);
    result
}
// The userenv location API resolves the profile registry through the
// process's predefined HKCU and the intermediate Classes/Storage keys. The
// LPAC access check denies those opens inside the raw lowbox worker: neither
// the Classes root nor the Storage parent carries a package ACE, while the
// sealed location key itself grants the package read. The worker therefore
// opens the location by its absolute NT path, built from its own token user
// SID and the profile moniker the plan already carries (the parent directory
// of profile_ac), and binds the opened key's NT name to that exact path.
fn location_path(plan: &KernelPlan) -> Result<String> {
    let inventory = token::current(&plan.quota.package)?;
    let moniker = plan
        .quota
        .profile_ac
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("kernel profile moniker unavailable from owned plan"))?;
    Ok(format!(
        "\\Registry\\User\\{}_Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\{}",
        inventory.user.canonical(),
        moniker
    ))
}

fn open_location(path: &str, access: u32) -> (i32, Raw) {
    let units: Vec<u16> = path.encode_utf16().collect();
    let unicode = Unicode {
        length: (units.len() * 2) as u16,
        maximum: (units.len() * 2) as u16,
        buffer: units.as_ptr(),
    };
    let attributes = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root: null_mut(),
        name: &unicode,
        flags: 0x40,
        descriptor: null_mut(),
        qos: null_mut(),
    };
    let mut handle: Raw = null_mut();
    // SAFETY: fixed absolute path built above; handle is caller-owned.
    let status = unsafe { NtOpenKeyEx(&mut handle, access, &attributes, 0) };
    (status, handle)
}

pub(super) fn controls(plan: &KernelPlan) -> Result<()> {
    let path = location_path(plan)?;
    let (status, raw) = open_location(&path, 0x20019);
    let mut locator = Key(if valid(raw) { raw } else { null_mut() });
    let operation = (|| {
        token::current(&plan.quota.package)?;
        ensure!(
            status == 0 && valid(raw),
            "kernel sealed profile registry read positive failed ntstatus={:08X} valid={}",
            status as u32,
            valid(raw)
        );
        let identity = qualify(raw, 0x20019)?;
        ensure!(
            crate::windows_security::sxs::ordinal_path_equal(&identity, &path)?,
            "kernel profile key identity differs from owned location"
        );
        for access in [0x20019, 2, 4, 0x10000, 0x40000, 0x80000, 0x20006] {
            let mut raw = null_mut();
            let status = unsafe { RegOpenKeyExW(locator.0, [0u16].as_ptr(), 0, access, &mut raw) };
            let alias = raw == locator.0;
            let mut fresh = Key(if valid(raw) && !alias {
                raw
            } else {
                null_mut()
            });
            let result = (|| {
                ensure!(!alias, "kernel fresh profile key aliases locator");
                if valid(raw) {
                    ensure!(
                        crate::windows_security::sxs::ordinal_path_equal(
                            &qualify(raw, access)?,
                            &identity
                        )?,
                        "kernel fresh profile key identity changed"
                    );
                }
                if access == 0x20019 {
                    ensure!(
                        status == 0 && valid(raw),
                        "kernel fresh profile read positive failed"
                    );
                } else {
                    ensure!(
                        status == 5 && raw.is_null(),
                        "kernel fresh profile mutation was not explicitly denied"
                    );
                }
                Ok(())
            })();
            combine(result, fresh.close())?;
        }
        for access in [2, 4, 0x10000, 0x40000, 0x80000, 0x20006] {
            token::current(&plan.quota.package)?;
            let mut raw = null_mut();
            let status = unsafe { GetAppContainerRegistryLocation(access, &mut raw) } as u32;
            let alias = raw == locator.0;
            let mut fresh = Key(if valid(raw) && !alias {
                raw
            } else {
                null_mut()
            });
            let result = (|| {
                token::current(&plan.quota.package)?;
                ensure!(!alias, "kernel negative profile API aliases locator");
                if valid(raw) {
                    ensure!(
                        crate::windows_security::sxs::ordinal_path_equal(
                            &qualify(raw, access)?,
                            &identity
                        )?,
                        "kernel negative profile API key identity changed"
                    );
                }
                ensure!(
                    status == 0x80070005 && raw.is_null(),
                    "kernel profile API mutation was not HRESULT access-denied"
                );
                Ok(())
            })();
            combine(result, fresh.close())?;
        }
        Ok(())
    })();
    combine(operation, locator.close())?;
    let name = wide("Software\\ScientificSandboxProbe");
    let mut raw = null_mut();
    let mut disposition = 0;
    // SAFETY: one fixed HKCU creation negative, no arbitrary subkey or host privilege.
    let status = unsafe {
        RegCreateKeyExW(
            (0x80000001u32 as i32 as isize) as Raw,
            name.as_ptr(),
            0,
            std::ptr::null(),
            0,
            0x20006,
            null_mut(),
            &mut raw,
            &mut disposition,
        )
    };
    let mut key = Key(if valid(raw) { raw } else { null_mut() });
    combine(
        (|| {
            ensure!(
                std::io::Error::from_raw_os_error(status).kind()
                    == std::io::ErrorKind::PermissionDenied
                    && raw.is_null(),
                "kernel HKCU creation was not access-denied"
            );
            Ok(())
        })(),
        key.close(),
    )
}
