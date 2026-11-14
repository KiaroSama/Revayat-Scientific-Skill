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
    ptr::{null, null_mut},
};

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
        files::absent(&path)?;
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
            value.original = open(&value.path, 0xC00C0000, 3, 1, 0x80, &security)?;
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
