//! Retained registry tree of this run's actual AppContainer profile. No machine-key policy changes.
use super::*;
use crate::windows_security::{
    activation::Failures,
    sxs::{current_user_sid, ordinal_path_equal, with_authority},
};
#[path = "profile_registry_policy.rs"]
mod policy;
#[link(name = "userenv")]
unsafe extern "system" {
    fn GetAppContainerRegistryLocation(access: u32, key: *mut Handle) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegCloseKey(key: Handle) -> i32;
    fn RegEnumKeyExW(
        key: Handle,
        index: u32,
        name: *mut u16,
        length: *mut u32,
        reserved: Handle,
        class: Handle,
        class_length: Handle,
        modified: Handle,
    ) -> i32;
    fn RegOpenKeyExW(
        key: Handle,
        name: *const u16,
        options: u32,
        access: u32,
        result: *mut Handle,
    ) -> i32;
}
fn combine<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(Failures {
            errors: vec![primary, cleanup],
        }
        .into()),
    }
}
fn valid(key: Handle) -> bool {
    !key.is_null() && (key as isize) > 0 && !((0x80000000..=0x800000ff).contains(&(key as usize)))
}
struct Key(Handle);
impl Key {
    fn close(&mut self) -> Result<()> {
        if !self.0.is_null() {
            let key = std::mem::replace(&mut self.0, null_mut());
            let status = unsafe { RegCloseKey(key) };
            ensure!(
                status == 0,
                "owned profile registry close failed winerror={status}"
            );
        }
        Ok(())
    }
}
impl Drop for Key {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
struct Entry {
    key: Key,
    name: String,
}
#[derive(Default)]
pub(super) struct ProfileRegistry {
    entries: Vec<Entry>,
    prepared: bool,
    closed: bool,
    uncertain: std::cell::Cell<bool>,
}
fn tree_budget(count: usize, depth: usize) -> Result<()> {
    ensure!(
        count < 256 && depth <= 32,
        "owned profile registry exceeds finite tree budget"
    );
    Ok(())
}
fn child_name(units: &[u16]) -> Result<String> {
    let text = String::from_utf16(units)?;
    ensure!(
        !text.is_empty()
            && text.len() <= 1020
            && !matches!(text.as_str(), "." | "..")
            && !text.contains(['\\', '\0']),
        "owned profile registry child name is invalid"
    );
    Ok(text)
}
fn decode_name(bytes: &[u8], returned: usize) -> Result<String> {
    ensure!(
        (4..=4096).contains(&returned) && returned <= bytes.len(),
        "owned profile registry identity query exceeds bound"
    );
    let length = u32::from_le_bytes(bytes[..4].try_into()?) as usize;
    ensure!(
        length > 0 && length.is_multiple_of(2) && length <= returned - 4,
        "owned profile registry identity length differs"
    );
    let text = String::from_utf16(
        &bytes[4..4 + length]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|part| u16::from_le_bytes([part[0], part[1]]))
            .collect::<Vec<_>>(),
    )?;
    ensure!(
        !text.contains('\0') && text.starts_with('\\'),
        "owned profile registry identity encoding differs"
    );
    Ok(text)
}
fn name(key: Handle) -> Result<String> {
    let mut data = [0u64; 512];
    let mut returned = 0;
    let status = unsafe {
        registry_authority::native::NtQueryKey(
            key,
            3,
            data.as_mut_ptr().cast(),
            4096,
            &mut returned,
        )
    };
    let result = (|| {
        ensure!(
            status == 0,
            "owned profile registry identity query failed ntstatus={:08X}",
            status as u32
        );
        decode_name(
            unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), 4096) },
            returned as usize,
        )
    })();
    data.fill(0);
    result
}
fn granted(key: Handle) -> Result<u32> {
    let mut bytes = [0u64; 7];
    let mut returned = 0;
    let status = unsafe {
        registry_authority::native::NtQueryObject(
            key,
            0,
            bytes.as_mut_ptr().cast(),
            56,
            &mut returned,
        )
    };
    ensure!(
        status == 0 && returned == 56,
        "profile granted-access query is unknown"
    );
    Ok((bytes[0] >> 32) as u32)
}
fn validate_open(
    api: bool,
    status: u32,
    raw: Handle,
    same: bool,
    grant: u32,
    requested: u32,
    allowed: bool,
) -> Result<()> {
    let valid = valid(raw);
    if valid {
        ensure!(
            same && grant & !0x20019 == 0 && grant & requested == requested,
            "profile access identity or read-only grant differs"
        );
    }
    ensure!(
        if allowed {
            status == 0 && valid
        } else {
            status == if api { 0x80070005 } else { 5 } && raw.is_null()
        },
        "profile access was not the exact expected read or explicit denial"
    );
    Ok(())
}
impl ProfileRegistry {
    pub fn prepare(
        &mut self,
        process: Handle,
        package: &str,
        mut emit: impl FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            !self.prepared && !self.closed && self.entries.is_empty(),
            "profile registry preparation repeated"
        );
        let user = current_user_sid()?;
        // Validate the exact six distinct identities before touching the owned policy.
        policy::sddl(&user, package, false)?;
        let mut root = Key(null_mut());
        let acquired = with_authority(
            process,
            package,
            || Ok(()),
            |qualify| {
                qualify()?;
                let mut raw = null_mut();
                let status = unsafe { GetAppContainerRegistryLocation(0x60019, &mut raw) };
                if valid(raw) {
                    root.0 = raw;
                }
                qualify()?;
                ensure!(
                    status == 0 && valid(raw),
                    "open actual profile registry for seal failed hresult={:08X}",
                    status as u32
                );
                Ok(())
            },
        );
        if !root.0.is_null() {
            self.entries.push(Entry {
                key: root,
                name: String::new(),
            });
        } // Transfer even a valid partial output before qualification/cleanup can fail.
        acquired?;
        self.collect(0, 0)?;
        self.seal(&user, package, false)?;
        emit(&format!(
            "WINDOWS_PROFILE_REGISTRY sealed=true keys={}",
            self.entries.len()
        ))?;
        self.controls(process, package, false)?;
        self.seal(&user, package, true)?;
        self.controls(process, package, true)?;
        emit(&format!(
            "WINDOWS_PROFILE_REGISTRY_READ_PAIR old_denied=true new_read=true individual_mutations_denied=true keys={}",
            self.entries.len()
        ))?;
        self.prepared = true;
        Ok(())
    }
    /// Recheck effective read/mutation controls after suspended token preparation.
    pub fn require_readonly(&self, process: Handle, package: &str) -> Result<()> {
        ensure!(
            self.prepared && !self.closed,
            "profile registry is not sealed"
        );
        self.controls(process, package, true)
    }
    fn collect(&mut self, index: usize, depth: usize) -> Result<()> {
        ensure!(
            depth <= 32,
            "owned profile registry exceeds finite depth budget"
        );
        self.entries[index].name = name(self.entries[index].key.0)?;
        let mut ordinal = 0u32;
        loop {
            let mut units = [0u16; 256];
            let mut length = units.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    self.entries[index].key.0,
                    ordinal,
                    units.as_mut_ptr(),
                    &mut length,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            if status == 259 {
                break;
            }
            ensure!(
                status == 0 && length > 0 && (length as usize) < units.len(),
                "owned profile registry child enumeration failed winerror={status}"
            );
            tree_budget(self.entries.len(), depth + 1)?;
            let child_text = child_name(&units[..length as usize])?;
            let expected = format!("{}\\{}", self.entries[index].name, child_text);
            units.fill(0);
            let child = wide(child_text);
            let mut raw = null_mut();
            let status = unsafe {
                RegOpenKeyExW(
                    self.entries[index].key.0,
                    child.as_ptr(),
                    0,
                    0x60019,
                    &mut raw,
                )
            };
            let alias = self.entries.iter().any(|entry| entry.key.0 == raw);
            let child = Key(if valid(raw) && !alias {
                raw
            } else {
                null_mut()
            });
            if !child.0.is_null() {
                self.entries.push(Entry {
                    key: child,
                    name: String::new(),
                });
            }
            ensure!(
                status == 0 && valid(raw) && !alias,
                "owned profile registry child open failed winerror={status}"
            );
            let last = self.entries.len() - 1;
            self.entries[last].name = name(self.entries[last].key.0)?;
            ensure!(
                ordinal_path_equal(&self.entries[last].name, &expected)?,
                "owned profile registry child identity differs"
            );
            self.collect(last, depth + 1)?;
            ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("profile child census overflow"))?;
        }
        Ok(())
    }
    fn seal(&self, user: &str, package: &str, read_only: bool) -> Result<()> {
        ensure!(
            !self.entries.is_empty() && self.entries.len() <= 256,
            "owned profile registry handle set exceeds bound"
        );
        for entry in self.entries.iter().rev() {
            ensure!(
                ordinal_path_equal(&name(entry.key.0)?, &entry.name)?,
                "retained profile registry identity changed"
            );
            policy::apply(entry.key.0, user, package, read_only)?;
        }
        Ok(())
    }
    fn controls(&self, process: Handle, package: &str, readable: bool) -> Result<()> {
        with_authority(
            process,
            package,
            || Ok(()),
            |qualify| {
                self.check(0x20019, readable, qualify)?;
                if readable {
                    for mask in [2, 4, 0x10000, 0x40000, 0x80000] {
                        self.check(mask, false, qualify)?;
                    }
                }
                Ok(())
            },
        )
    }
    fn check(&self, mask: u32, allowed: bool, qualify: &dyn Fn() -> Result<()>) -> Result<()> {
        let retained = self
            .entries
            .first()
            .ok_or_else(|| anyhow::anyhow!("profile registry root absent"))?;
        for api in [true, false] {
            qualify()?;
            let mut raw = null_mut();
            let status = if api {
                (unsafe { GetAppContainerRegistryLocation(mask, &mut raw) }) as u32
            } else {
                (unsafe { RegOpenKeyExW(retained.key.0, [0u16].as_ptr(), 0, mask, &mut raw) })
                    as u32
            };
            let alias = self.entries.iter().any(|entry| entry.key.0 == raw);
            let mut owner = Key(if valid(raw) && !alias {
                raw
            } else {
                null_mut()
            });
            let checked = (|| {
                qualify()?;
                ensure!(!alias, "fresh profile access returned retained alias");
                let same = if valid(raw) {
                    ordinal_path_equal(&name(raw)?, &retained.name)?
                } else {
                    false
                };
                let rights = if valid(raw) { granted(raw)? } else { 0 };
                validate_open(api, status, raw, same, rights, mask, allowed)
            })();
            let cleanup = owner.close();
            if cleanup.is_err() {
                self.uncertain.set(true);
            }
            combine(checked, cleanup)?;
        }
        Ok(())
    }
    fn close_with(&mut self, mut close: impl FnMut(Handle) -> Result<()>) -> Result<()> {
        if self.closed {
            ensure!(
                !self.uncertain.get(),
                "owned profile registry close remains uncertain"
            );
            return Ok(());
        }
        self.closed = true;
        let mut errors = Vec::new();
        for entry in self.entries.iter_mut().rev() {
            let raw = std::mem::replace(&mut entry.key.0, null_mut());
            if !raw.is_null()
                && let Err(error) = close(raw)
            {
                errors.push(error);
            }
            entry.name.clear();
        }
        self.entries.clear();
        if !errors.is_empty() {
            self.uncertain.set(true);
        }
        if self.uncertain.get() {
            if errors.is_empty() {
                errors.push(anyhow::anyhow!(
                    "owned profile registry close remains uncertain"
                ));
            }
            Err(Failures { errors }.into())
        } else {
            Ok(())
        }
    }
    pub fn close(&mut self) -> Result<()> {
        self.close_with(|key| {
            let status = unsafe { RegCloseKey(key) };
            ensure!(
                status == 0,
                "owned profile registry close failed winerror={status}"
            );
            Ok(())
        })
    }
}
impl Drop for ProfileRegistry {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
#[cfg(test)]
#[path = "profile_registry_tests.rs"]
mod tests;
