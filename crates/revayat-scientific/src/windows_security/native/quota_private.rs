//! Original private creator authority positives, finite-owner negatives and pinned cleanup.
use super::{
    eof,
    ffi::*,
    files::{self, Identity, Root},
};
use crate::windows_security::quota_controls::{OwnerInventory, Sid, WorkerPlan};
use anyhow::{Result, ensure};
use std::{
    io::Write,
    mem::size_of,
    os::windows::io::{AsRawHandle, BorrowedHandle},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn DuplicateHandle(
        source: Raw,
        handle: Raw,
        target: Raw,
        out: *mut Raw,
        access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        process: Raw,
        class: u32,
        data: Raw,
        bytes: u32,
        returned: *mut u32,
    ) -> i32;
}
#[repr(C)]
struct ProcessHandleEntry {
    handle_value: usize,
    handle_count: usize,
    pointer_count: usize,
    granted_access: u32,
    object_type_index: u32,
    handle_attributes: u32,
    reserved: u32,
}

pub(crate) fn cleanup_provisioned_private_file(path: &Path) -> Result<()> {
    let owned = path.file_name() == Some(std::ffi::OsStr::new("authority-protected"))
        && path.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("private-creator"));
    ensure!(owned, "private creator cleanup path differs");
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => anyhow::bail!("provisioned private creator cleanup failed"),
    }
    files::absent(
        path.to_str()
            .ok_or_else(|| anyhow::anyhow!("private creator cleanup path is not Unicode"))?,
    )
}

pub(crate) fn provision_private_creator_file(
    child_process: BorrowedHandle<'_>,
    scratch: &str,
    inventory: &OwnerInventory,
) -> Result<PathBuf> {
    let path = PathBuf::from(format!("{scratch}private-creator\\authority-protected"));
    let text = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("private creator provision path is not Unicode"))?;
    files::absent(text)?;
    let mut descriptor = Descriptor::new(&format!(
        "D:P(A;;GA;;;{})(A;;GA;;;{})",
        inventory.user.canonical(),
        inventory.package.canonical(),
    ))?;
    let security = Security {
        length: size_of::<Security>() as u32,
        descriptor: descriptor.0,
        inherit: 0,
    };
    let mut original = match open(text, 0xC00C0000, 3, 1, 0x80, &security) {
        Ok(original) => original,
        Err(primary) => return combine(Err(primary), descriptor.close()),
    };
    let mut duplicate = null_mut();
    let operation = (|| {
        files::grant(original.0, 0x1E019F)?;
        // SAFETY: host owns the source; the actual suspended child owns the non-inherited output.
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                original.0,
                child_process.as_raw_handle(),
                &mut duplicate,
                0x001E019F,
                0,
                0,
            )
        };
        ensure!(
            ok != 0 && !duplicate.is_null(),
            "private creator handle provisioning failed"
        );
        Ok(())
    })();
    let operation = combine(operation, all([original.close(), descriptor.close()]));
    if let Err(primary) = operation {
        let mut rollback = Ok(());
        if !duplicate.is_null() {
            let mut recovered = null_mut();
            // SAFETY: revoke only this call's remote output, returning an owned local copy for closure.
            let ok = unsafe {
                DuplicateHandle(
                    child_process.as_raw_handle(),
                    duplicate,
                    GetCurrentProcess(),
                    &mut recovered,
                    0,
                    0,
                    3,
                )
            };
            let mut recovered = Owned(recovered);
            rollback = combine(
                if ok != 0 {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("private creator handle rollback failed"))
                },
                recovered.close(),
            );
        }
        return combine(
            Err(primary),
            all([rollback, cleanup_provisioned_private_file(&path)]),
        );
    }
    Ok(path)
}

fn provisioned_handle(root: &Root, expected: &str) -> Result<Owned> {
    let abi = size_of::<usize>() == 8 && size_of::<ProcessHandleEntry>() == 40;
    ensure!(abi, "private creator handle snapshot ABI differs");
    // usize storage keeps the two-word header and each entry naturally aligned.
    let mut buffer = vec![0usize; 65536 / size_of::<usize>()];
    for _ in 0..8 {
        let bytes = buffer.len() * size_of::<usize>();
        let mut returned = 0u32;
        // SAFETY: current-process pseudo-handle and live aligned writable snapshot buffer.
        let status = unsafe {
            NtQueryInformationProcess(
                -1isize as Raw,
                51,
                buffer.as_mut_ptr().cast(),
                bytes as u32,
                &mut returned,
            )
        };
        if status == 0xC0000004u32 as i32 {
            let next = (returned as usize)
                .checked_add(4096)
                .ok_or_else(|| anyhow::anyhow!("private creator handle snapshot overflow"))?;
            let bounded = next > bytes && next <= 16 * 1024 * 1024;
            ensure!(bounded, "private creator handle snapshot exceeds bound");
            buffer.resize(next.div_ceil(size_of::<usize>()), 0);
            continue;
        }
        let valid = status == 0
            && (16..=bytes).contains(&(returned as usize))
            && buffer[0] <= (returned as usize - 16) / size_of::<ProcessHandleEntry>();
        ensure!(valid, "private creator handle snapshot query failed");
        let mut matches = Vec::new();
        for index in 0..buffer[0] {
            // SAFETY: count and returned byte bound prove this complete entry lies in the snapshot.
            let entry = unsafe {
                std::ptr::read_unaligned(
                    buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(16 + index * size_of::<ProcessHandleEntry>())
                        .cast::<ProcessHandleEntry>(),
                )
            };
            if entry.granted_access != 0x001E019F || entry.handle_attributes != 0 {
                continue;
            }
            let handle = entry.handle_value as Raw;
            // SAFETY: snapshot handle is borrowed in this process; only the unique match is adopted.
            if unsafe { GetFileType(handle) } != 1 {
                continue;
            }
            let Ok(id) = files::identity(handle, false) else {
                continue;
            };
            if id.volume == root.id.volume && files::name(handle)? == expected {
                matches.push(handle);
            }
        }
        ensure!(
            matches.len() == 1,
            "private creator provisioned handle is not unique"
        );
        return Ok(Owned(matches[0]));
    }
    anyhow::bail!("private creator handle snapshot did not stabilize")
}

fn direct_create_denied(path: &str, security: &Security) -> Result<()> {
    files::absent(path)?;
    let name = wide(path);
    // SAFETY: fresh fixed sibling path, live non-inheritable security, CREATE_NEW only.
    let raw = unsafe { CreateFileW(name.as_ptr(), 0xC00C0000, 3, security, 1, 0x80, null_mut()) };
    let error = unsafe { GetLastError() };
    if !raw.is_null() && raw as isize != -1 {
        let mut unexpected = Owned(raw);
        return combine(
            Err(anyhow::anyhow!(
                "private creator direct open unexpectedly succeeded"
            )),
            all([
                unexpected.close(),
                std::fs::remove_file(path).map_err(|_| {
                    anyhow::anyhow!("private creator unexpected direct file cleanup failed")
                }),
            ]),
        );
    }
    let denied = raw as isize == -1 && error == 5;
    ensure!(denied, "private creator direct open was not access-denied");
    files::absent(path)
}

struct PrivateFile {
    path: String,
    expected: String,
    volume: u64,
    directory: Owned,
    original: Owned,
    pin: Owned,
    id: Option<Identity>,
    closed: bool,
}
impl PrivateFile {
    fn create(root: &Root, descriptor: &Descriptor) -> Result<Self> {
        root.require()?;
        let parent = format!("{}private-creator", root.path);
        let path = format!("{parent}\\authority-protected");
        let directory = open(&parent, 0x80, 3, 3, 0x02200000, null())?;
        let mut value = Self {
            path,
            expected: format!("{}private-creator\\authority-protected", root.native),
            volume: root.id.volume,
            directory,
            original: Owned::empty(),
            pin: Owned::empty(),
            id: None,
            closed: false,
        };
        let result = (|| {
            ensure!(
                files::identity(value.directory.0, true)?.volume == root.id.volume
                    && files::name(value.directory.0)? == format!("{}private-creator", root.native),
                "private creator parent binding differs"
            );
            let security = Security {
                length: size_of::<Security>() as u32,
                descriptor: descriptor.0,
                inherit: 0,
            };
            let denied_probe = format!("{parent}\\authority-direct-denied");
            direct_create_denied(&denied_probe, &security)?;
            value.original = provisioned_handle(root, &value.expected)?;
            let id = files::identity(value.original.0, false)?;
            ensure!(
                id.volume == value.volume && files::name(value.original.0)? == value.expected,
                "private creator original identity differs"
            );
            value.id = Some(id);
            files::grant(value.original.0, 0x1E019F)?;
            value.pin = open(&value.path, 0x80, 7, 3, 0x00200000, null())?;
            files::bind(value.pin.0, id, &value.expected)?;
            value.qualify()?;
            Ok(())
        })();
        if let Err(error) = result {
            return combine(Err(error), value.close());
        }
        Ok(value)
    }
    fn qualify(&self) -> Result<Raw> {
        let id = self
            .id
            .ok_or_else(|| anyhow::anyhow!("private creator identity is absent"))?;
        ensure!(
            !self.closed && !self.original.0.is_null() && !self.pin.0.is_null(),
            "private creator live bindings are absent"
        );
        files::bind(self.original.0, id, &self.expected)?;
        files::bind(self.pin.0, id, &self.expected)?;
        files::grant(self.original.0, 0x1E019F)?;
        Ok(self.original.0)
    }
    fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let mut errors = Vec::new();
        let mut bound = false;
        if let Some(id) = self.id
            && !self.pin.0.is_null()
        {
            match files::bind(self.pin.0, id, &self.expected) {
                Ok(()) => bound = true,
                Err(error) => errors.push(error),
            }
        }
        let closed = match self.original.close() {
            Ok(()) => true,
            Err(error) => {
                errors.push(error);
                false
            }
        };
        let mut removed = false;
        if bound && closed {
            match open(&self.path, 0x10080, 3, 3, 0x00200000, null()) {
                Ok(mut deletion) => {
                    let result = (|| {
                        let id = self.id.ok_or_else(|| {
                            anyhow::anyhow!("private creator deletion identity is absent")
                        })?;
                        files::bind(deletion.0, id, &self.expected)?;
                        files::bind(self.pin.0, id, &self.expected)?;
                        files::disposition(deletion.0)?;
                        removed = true;
                        Ok(())
                    })();
                    if let Err(error) = combine(result, deletion.close()) {
                        errors.push(error);
                    }
                }
                Err(error) => errors.push(error),
            }
        }
        // Keep the file pin alive until deletion was bound and requested; close every handle independently.
        for result in [self.pin.close(), self.directory.close()] {
            if let Err(error) = result {
                errors.push(error);
            }
        }
        if removed && let Err(error) = files::absent(&self.path) {
            errors.push(error);
        }
        all(errors.into_iter().map(Err))
    }
}
impl Drop for PrivateFile {
    fn drop(&mut self) {
        if self.close().is_err() {
            note_cleanup_failure();
        }
    }
}

fn named_denied(path: &str, package: &Sid, dacl: Raw) -> Result<()> {
    let mut path = wide(path);
    for (info, owner, acl) in [
        (0x80000004, null_mut(), dacl),
        (1, package.bytes().as_ptr() as Raw, null_mut()),
    ] {
        // SAFETY: fixed prepared path, valid bounded package SID and parsed non-null DACL; direct DWORD status.
        let status = unsafe {
            SetNamedSecurityInfoW(
                path.as_mut_ptr(),
                1,
                info,
                owner,
                null_mut(),
                acl,
                null_mut(),
            )
        };
        ensure!(
            status == 5,
            "ordinary/protected quota fixture DACL or owner mutation was not access-denied"
        );
    }
    Ok(())
}
fn protected(plan: &WorkerPlan, package: &Sid, dacl: Raw) -> Result<()> {
    let image =
        std::env::current_exe().map_err(|_| anyhow::anyhow!("quota worker image lookup failed"))?;
    let image_parent = image
        .parent()
        .ok_or_else(|| anyhow::anyhow!("quota worker image parent is absent"))?;
    let auxiliary_parent = plan
        .auxiliary_image
        .parent()
        .ok_or_else(|| anyhow::anyhow!("quota auxiliary image parent is absent"))?;
    let profile_parent = plan
        .profile_ac
        .parent()
        .ok_or_else(|| anyhow::anyhow!("quota profile AC parent is absent"))?;
    for path in [
        &plan.readonly_root,
        image_parent,
        &image,
        auxiliary_parent,
        &plan.host_canary,
        std::path::Path::new(&plan.scratch),
        &plan.profile_ac,
        profile_parent,
    ] {
        named_denied(
            path.to_str()
                .ok_or_else(|| anyhow::anyhow!("quota protected path is not Unicode"))?,
            package,
            dacl,
        )?;
    }
    Ok(())
}
fn protected_write_denied(plan: &WorkerPlan) -> Result<()> {
    let path = plan.readonly_root.join("protected-creator-escape");
    let path = wide(
        path.to_str()
            .ok_or_else(|| anyhow::anyhow!("quota protected write path is not Unicode"))?,
    );
    // SAFETY: one fixed negative-control child of the prepared read-only root; no arbitrary target.
    let raw = unsafe { CreateFileW(path.as_ptr(), 0x40000000, 3, null(), 2, 0x80, null_mut()) };
    let error = unsafe { GetLastError() };
    if !raw.is_null() && raw as isize != -1 {
        let mut acquired = Owned::new(raw)?;
        return combine(
            Err(anyhow::anyhow!(
                "private creator escaped protected root write denial"
            )),
            acquired.close(),
        );
    }
    ensure!(
        raw as isize == -1 && error == 5,
        "private creator protected-root write failed without access denial"
    );
    Ok(())
}
fn raw_volume_denied(root: &Root) -> Result<()> {
    let path = wide(&format!("\\\\.\\{}", &root.path[..2]));
    for access in [0xC0000000, 0x40000000, 2] {
        // SAFETY: the exact controller-supplied owned drive, OPEN_EXISTING and no fallback target.
        let raw = unsafe { CreateFileW(path.as_ptr(), access, 3, null(), 3, 0, null_mut()) };
        let error = unsafe { GetLastError() };
        if !raw.is_null() && raw as isize != -1 {
            let mut acquired = Owned::new(raw)?;
            return combine(
                Err(anyhow::anyhow!(
                    "quota worker acquired raw volume write/quota authority"
                )),
                acquired.close(),
            );
        }
        ensure!(
            raw as isize == -1 && error == 5,
            "raw quota volume open failed without access denial"
        );
    }
    Ok(())
}
pub(super) fn controls(root: &Root, plan: &WorkerPlan, inventory: &OwnerInventory) -> Result<()> {
    let mut negative = Descriptor::new(&format!("D:P(A;;GA;;;{})", inventory.package.canonical()))?;
    let operation = (|| {
        let dacl = negative.dacl()?;
        let mut ordinary = root.create("authority-normal")?;
        let operation = (|| {
            files::file(ordinary.handle.0)
                .write_all(b"bounded authority probe")
                .map_err(|_| anyhow::anyhow!("ordinary authority positive write failed"))?;
            ordinary.require()?;
            named_denied(&ordinary.path, &inventory.package, dacl)
        })();
        combine(operation, ordinary.close())?;
        protected(plan, &inventory.package, dacl)?;
        let mut policy = Descriptor::new(&format!(
            "D:P(A;;GA;;;{})(A;;GA;;;{})",
            inventory.user.canonical(),
            inventory.package.canonical()
        ))?;
        let operation = (|| {
            let dacl = policy.dacl()?;
            let mut fixture = PrivateFile::create(root, &policy)?;
            let operation = (|| {
                let handle = fixture.qualify()?;
                // SAFETY: qualified original private file carries exact WRITE_DAC/WRITE_OWNER rights.
                ensure!(
                    unsafe {
                        SetSecurityInfo(
                            handle,
                            1,
                            0x80000004,
                            null_mut(),
                            null_mut(),
                            dacl,
                            null_mut(),
                        )
                    } == 0,
                    "private creator own DACL positive failed"
                );
                eof::native(handle, false)?;
                eof::native(handle, true)?;
                for owner in &inventory.owners {
                    let handle = fixture.qualify()?;
                    let status = unsafe {
                        SetSecurityInfo(
                            handle,
                            1,
                            1,
                            owner.bytes().as_ptr() as Raw,
                            null_mut(),
                            null_mut(),
                            null_mut(),
                        )
                    };
                    if status == 0 {
                        eof::native(handle, true)?;
                    } else {
                        ensure!(
                            [5, 1307].contains(&status),
                            "finite quota owner assignment failed unexpectedly"
                        );
                    }
                }
                for text in ["S-1-5-32-544", "S-1-5-21-101-202-303-404"] {
                    let sid = Sid::text(text)?;
                    let handle = fixture.qualify()?;
                    let status = unsafe {
                        SetSecurityInfo(
                            handle,
                            1,
                            1,
                            sid.bytes().as_ptr() as Raw,
                            null_mut(),
                            null_mut(),
                            null_mut(),
                        )
                    };
                    ensure!(
                        [5, 1307].contains(&status),
                        "private creator assigned an unquotaable negative-control owner"
                    );
                }
                protected_write_denied(plan)?;
                Ok(())
            })();
            combine(operation, fixture.close())
        })();
        combine(operation, policy.close())?;
        raw_volume_denied(root)
    })();
    combine(operation, negative.close())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_snapshot_layout_and_cleanup_scope_stay_fixed() {
        assert_eq!(size_of::<[usize; 2]>(), 16);
        assert_eq!(size_of::<ProcessHandleEntry>(), 40);
        assert_eq!(std::mem::offset_of!(ProcessHandleEntry, granted_access), 24);
        assert_eq!(
            std::mem::offset_of!(ProcessHandleEntry, handle_attributes),
            32
        );
        for path in [
            Path::new("private-creator/other-file"),
            Path::new("other-directory/authority-protected"),
        ] {
            assert!(cleanup_provisioned_private_file(path).is_err());
        }
    }
}
