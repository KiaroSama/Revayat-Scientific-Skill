//! Private storage created with its final DACL, actual-user default owner, and exact LPAC denials.
use super::{capture::storage_step, native_identity as tokens, storage::require_policy};
use crate::windows_security::activation::diagnostics::{self, Numbers, Stage};
use crate::{
    identity::{self, ObjectId},
    windows_security::{activation::native::require_host, plain_path},
};
use anyhow::{Result, ensure};
use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{FromRawHandle, IntoRawHandle},
    },
    path::{Path, PathBuf},
    ptr::null_mut,
    time::{Duration, Instant},
};
type Raw = *mut c_void;
#[link(name = "kernel32")]
unsafe extern "system" {
    fn QueryDosDeviceW(device: *const u16, target: *mut u16, capacity: u32) -> u32;
    fn GetWindowsDirectoryW(buffer: *mut u16, capacity: u32) -> u32;
    fn GetLastError() -> u32;
    fn CloseHandle(handle: Raw) -> i32;
    fn LocalFree(memory: Raw) -> Raw;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        output: *mut Raw,
        bytes: *mut u32,
    ) -> i32;
    fn GetNamedSecurityInfoW(
        path: *const u16,
        kind: i32,
        information: u32,
        owner: *mut Raw,
        group: *mut Raw,
        dacl: *mut Raw,
        sacl: *mut Raw,
        descriptor: *mut Raw,
    ) -> u32;
    fn GetSecurityDescriptorLength(descriptor: Raw) -> u32;
    fn IsValidSecurityDescriptor(descriptor: Raw) -> i32;
}
fn wide(path: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    path.as_ref().encode_wide().chain(Some(0)).collect()
}
fn close(file: File) -> Result<()> {
    let raw = file.into_raw_handle();
    let success = unsafe { CloseHandle(raw) };
    let code = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    ensure!(success != 0, "fixed SxS file close failed winerror={code}");
    Ok(())
}
fn free(pointer: Raw) -> Result<()> {
    ensure!(
        pointer.is_null() || unsafe { LocalFree(pointer) }.is_null(),
        "fixed SxS descriptor close failed"
    );
    Ok(())
}
fn descriptor(sddl: &str) -> Result<Vec<u8>> {
    let text = wide(sddl);
    let mut raw = null_mut();
    let mut length = 0;
    let success = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut raw,
            &mut length,
        )
    };
    let code = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let result = (|| {
        ensure!(
            success != 0 && !raw.is_null() && (20..=65536).contains(&length),
            "fixed SxS descriptor conversion failed winerror={code}"
        );
        Ok(unsafe { std::slice::from_raw_parts(raw.cast(), length as usize) }.to_vec())
    })();
    tokens::finish(result, free(raw).err().into_iter().collect())
}
fn policy(path: &Path, directory: bool, owner: &[u8], package: &[u8]) -> Result<()> {
    plain_path(path)?;
    let path = wide(path);
    let mut raw = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            1,
            5,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut raw,
        )
    };
    let result = (|| {
        if status != 0 || raw.is_null() || unsafe { IsValidSecurityDescriptor(raw) } == 0 {
            return Err(diagnostics::native(
                Stage::SxsStoragePolicy,
                Numbers {
                    native_error: Some(status),
                    ..Default::default()
                },
            ));
        }
        let length = unsafe { GetSecurityDescriptorLength(raw) };
        ensure!(
            (20..=65536).contains(&length),
            "fixed SxS storage security readback exceeds bound"
        );
        require_policy(
            unsafe { std::slice::from_raw_parts(raw.cast(), length as usize) },
            directory,
            owner,
            package,
        )
    })();
    tokens::finish(result, free(raw).err().into_iter().collect())
}
fn binary_package(package: &str) -> Result<Vec<u8>> {
    crate::windows_security::package_sid(package)?;
    let mut bytes = vec![1, 8, 0, 0, 0, 0, 0, 15];
    for part in package.split('-').skip(3) {
        bytes.extend(part.parse::<u32>()?.to_le_bytes());
    }
    Ok(bytes)
}
fn drive(root: &Path) -> Result<String> {
    require_host()?;
    let text = root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("fixed SxS drive is not UTF-8"))?;
    let b = text.as_bytes();
    ensure!(
        b.len() == 3 && (b'D'..=b'Z').contains(&b[0]) && &b[1..] == b":\\",
        "fixed SxS storage requires one non-system drive root"
    );
    let mut windows = [0u16; 32768];
    let length = unsafe { GetWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) };
    ensure!(
        (3..32768).contains(&length)
            && windows[1] == b':' as u16
            && (windows[0] & !0x20) != u16::from(b[0]),
        "fixed SxS storage cannot use the Windows volume"
    );
    plain_path(root)?;
    ensure!(root.is_dir(), "fixed SxS storage volume is absent");
    Ok(text.to_owned())
}
pub(super) struct Storage {
    pub run: String,
    pub folder: PathBuf,
    owner: Vec<u8>,
    package: Vec<u8>,
    directory: Option<ObjectId>,
    created: bool,
    files: Vec<(&'static str, ObjectId)>,
    closed: bool,
}
impl Storage {
    pub fn prepare(root: &Path, package: &str) -> Result<Self> {
        Self::prepare_run(root, package, None)
    }
    pub fn prepare_owned(root: &Path, package: &str, run: &str) -> Result<Self> {
        ensure!(
            run.len() == 32
                && run
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "SxS storage run differs"
        );
        Self::prepare_run(root, package, Some(run))
    }
    fn prepare_run(root: &Path, package: &str, bound_run: Option<&str>) -> Result<Self> {
        let root = drive(root).map_err(|error| diagnostics::at(error, Stage::SxsStorageDrive))?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("fixed SxS nonce unavailable"))?;
        let run = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        nonce.fill(0);
        let run = bound_run.map(str::to_owned).unwrap_or(run);
        let mut owner = Self {
            folder: PathBuf::from(format!("{root}sxs-trace-{run}")),
            run,
            owner: tokens::host_user()?,
            package: binary_package(package)?,
            directory: None,
            created: false,
            files: Vec::new(),
            closed: false,
        };
        let result = (|| {
            storage_step(0, || {
                ensure!(
                    std::fs::symlink_metadata(&owner.folder)
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                    "fixed SxS storage already exists or cannot be qualified absent"
                );
                Ok(())
            })?;
            let user = tokens::sid_text(&owner.owner)?;
            let mut sd = descriptor(&format!(
                "O:{user}D:P(D;OICI;FA;;;{package})(D;OICI;0xc0000;;;S-1-3-4)(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)"
            ))?;
            let creation = storage_step(2, || {
                super::storage_policy::create_sealed(&mut sd, &owner.owner, &owner.package, |sd| {
                    storage_step(3, || {
                        creation::create(
                            owner
                                .folder
                                .to_str()
                                .ok_or_else(|| anyhow::anyhow!("invalid SxS folder encoding"))?,
                            sd,
                            &mut owner.created,
                            &mut owner.directory,
                        )
                    })
                })
            });
            sd.fill(0);
            creation?;
            storage_step(5, || {
                policy(&owner.folder, true, &owner.owner, &owner.package)
            })?;
            storage_step(4, || owner.write("canary", super::seed::CANARY))?;
            storage_step(7, || owner.write("capture.etl", b""))?;
            owner.require_seed()?;
            Ok(())
        })();
        if let Err(primary) = result {
            return tokens::finish(Err(primary), owner.close().err().into_iter().collect());
        }
        Ok(owner)
    }
    pub fn path(&self, name: &'static str) -> Result<PathBuf> {
        ensure!(
            matches!(
                name,
                "canary" | "capture.etl" | "capture.txt" | "collector.manifest"
            ),
            "unsupported fixed SxS storage member"
        );
        Ok(self.folder.join(name))
    }
    fn identity(&self) -> Result<()> {
        plain_path(&self.folder)?;
        ensure!(
            Some(identity::path_object_id(&self.folder)?) == self.directory,
            "fixed SxS storage directory changed"
        );
        Ok(())
    }
    pub fn require(&self, name: &'static str) -> Result<PathBuf> {
        self.identity()?;
        policy(&self.folder, true, &self.owner, &self.package)?;
        let path = self.path(name)?;
        policy(&path, false, &self.owner, &self.package)?;
        let expected = self
            .files
            .iter()
            .find(|(entry, _)| *entry == name)
            .ok_or_else(|| anyhow::anyhow!("SxS storage member was not created by this owner"))?
            .1;
        ensure!(
            identity::path_object_id(&path)? == expected,
            "fixed SxS storage member changed"
        );
        Ok(path)
    }
    pub fn write(&mut self, name: &'static str, bytes: &[u8]) -> Result<()> {
        self.identity()?;
        ensure!(
            bytes.len() <= 4096 && !self.files.iter().any(|(entry, _)| *entry == name),
            "SxS storage member retry or size rejected"
        );
        let path = self.path(name)?;
        let result = tokens::owner(|user| {
            ensure!(user == self.owner, "SxS canary user changed");
            let file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .share_mode(0)
                .custom_flags(0x00200000)
                .open(&path)?;
            if bytes.is_empty() {
                super::seed::create(
                    || Ok(file),
                    |file| {
                        self.files.push((name, identity::object_id(file)?));
                        Ok(file.metadata()?.len())
                    },
                    |file| {
                        file.flush()?;
                        file.sync_all()?;
                        Ok(())
                    },
                    close,
                )
            } else {
                crate::windows_security::activation::control::write_fixed(
                    bytes,
                    || Ok(file),
                    |file, bytes| {
                        self.files.push((name, identity::object_id(file)?));
                        ensure!(
                            file.metadata()?.len() == 0,
                            "SxS canary is not empty at creation"
                        );
                        file.write_all(bytes)?;
                        Ok(())
                    },
                    |file| {
                        file.flush()?;
                        file.sync_all()?;
                        Ok(())
                    },
                    close,
                )
            }
        });
        result?;
        self.require(name)?;
        Ok(())
    }
    pub fn read(&self, name: &'static str, maximum: u64) -> Result<Vec<u8>> {
        let path = self.require(name)?;
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(&path)?;
        let result = (|| {
            let expected = self
                .files
                .iter()
                .find(|(entry, _)| *entry == name)
                .unwrap()
                .1;
            ensure!(
                identity::object_id(&file)? == expected && file.metadata()?.len() <= maximum,
                "SxS held member identity/size differs"
            );
            let mut bytes = Vec::new();
            (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= maximum && bytes.len() as u64 == file.metadata()?.len(),
                "SxS held member length changed"
            );
            Ok(bytes)
        })();
        tokens::finish(result, close(file).err().into_iter().collect())
    }
    pub fn require_empty(&self, name: &'static str) -> Result<()> {
        let path = self.path(name)?;
        super::seed::read(
            || self.require(name).map(|_| ()),
            || {
                Ok(OpenOptions::new()
                    .read(true)
                    .share_mode(0)
                    .custom_flags(0x00200000)
                    .open(&path)?)
            },
            |file| {
                let expected = self
                    .files
                    .iter()
                    .find(|(member, _)| *member == name)
                    .ok_or_else(|| anyhow::anyhow!("fixed SxS seed was not created"))?
                    .1;
                ensure!(
                    identity::object_id(file)? == expected,
                    "fixed SxS seed identity differs"
                );
                Ok(file.metadata()?.len())
            },
            close,
        )
    }
    pub fn require_absent(&self, name: &'static str) -> Result<()> {
        self.identity()?;
        ensure!(
            std::fs::symlink_metadata(self.path(name)?)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "fixed SxS output already exists or absence is uncertain"
        );
        Ok(())
    }
    pub fn require_seed(&self) -> Result<()> {
        storage_step(5, || policy(&self.folder, true, &self.owner, &self.package))?;
        storage_step(6, || {
            policy(&self.path("canary")?, false, &self.owner, &self.package)
        })?;
        storage_step(4, || {
            let mut bytes = self.read("canary", 64)?;
            let result = super::seed::require_canary(&bytes);
            bytes.fill(0);
            result
        })?;
        storage_step(7, || self.require_empty("capture.etl"))
    }
    pub fn deny(&self, process: Raw, package: &str) -> Result<()> {
        self.require_seed()?;
        let start = Instant::now();
        tokens::authority(process, package, |effective| {
            for (path, masks) in [
                (
                    &self.folder,
                    &[1, 2, 4, 0x40, 0x10000, 0x20000, 0x40000, 0x80000][..],
                ),
                (
                    &self.path("canary")?,
                    &[1, 2, 0x10000, 0x20000, 0x40000, 0x80000][..],
                ),
                (
                    &self.path("capture.etl")?,
                    &[1, 2, 0x10000, 0x20000, 0x40000, 0x80000][..],
                ),
            ] {
                let name = wide(path);
                for access in masks {
                    effective()?;
                    ensure!(
                        start.elapsed() < Duration::from_secs(10),
                        "SxS storage denial deadline exceeded"
                    );
                    let raw = unsafe {
                        registry_authority::native::CreateFileW(
                            name.as_ptr(),
                            *access,
                            7,
                            std::ptr::null(),
                            3,
                            0x02200000,
                            null_mut(),
                        )
                    };
                    let code = unsafe { GetLastError() };
                    let result = (|| {
                        if raw as usize != usize::MAX || code != 5 {
                            return Err(diagnostics::native(
                                Stage::SxsStorageDeny,
                                Numbers {
                                    native_error: Some(code),
                                    result: Some(u32::from(raw as usize != usize::MAX)),
                                    count: Some(*access),
                                    ..Default::default()
                                },
                            ));
                        }
                        Ok(())
                    })();
                    let errors = if !raw.is_null() && raw as usize != usize::MAX {
                        close(unsafe { File::from_raw_handle(raw) })
                            .err()
                            .into_iter()
                            .collect()
                    } else {
                        vec![]
                    };
                    tokens::finish(result, errors)?;
                }
            }
            effective()
        })
    }
    pub fn retain(&mut self) {
        self.closed = true;
        self.owner.fill(0);
        self.package.fill(0);
    }
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        require_host()?;
        let mut errors = Vec::new();
        if self.created && self.directory.is_none() {
            errors.push(anyhow::anyhow!(
                "SxS created storage retained because its object identity could not be qualified"
            ));
        }
        if self.directory.is_some() {
            self.identity()?;
            for (name, id) in &self.files {
                let path = self.folder.join(name);
                let result = (|| {
                    plain_path(&path)?;
                    ensure!(
                        identity::path_object_id(&path)? == *id,
                        "SxS cleanup member identity changed"
                    );
                    std::fs::remove_file(path)?;
                    Ok(())
                })();
                if let Err(error) = result {
                    errors.push(error);
                }
            }
            if errors.is_empty()
                && let Err(error) = std::fs::remove_dir(&self.folder)
            {
                errors.push(error.into());
            }
        }
        self.owner.fill(0);
        self.package.fill(0);
        tokens::finish(Ok(()), errors)
    }
}
impl Drop for Storage {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[path = "native_storage_create.rs"]
mod creation;
#[path = "native_evidence.rs"]
mod evidence;
