//! This run's actual package AC path, bounded retained filesystem tree, and final six-rule seal.
use super::*;
use crate::identity::{self, ObjectId};
use crate::windows_security::{activation::Failures, sxs::ordinal_path_equal};
use std::{
    fs::File,
    os::windows::{
        fs::MetadataExt,
        io::{AsRawHandle, FromRawHandle, IntoRawHandle},
    },
    path::{Component, PathBuf},
};
#[path = "profile_storage_policy.rs"]
mod policy;
#[repr(C)]
#[derive(Default)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
const LOCAL_APP_DATA: Guid = Guid {
    a: 0xf1b32785,
    b: 0x6fba,
    c: 0x4fcf,
    d: [0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91],
};
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoCreateGuid(guid: *mut Guid) -> i32;
    fn CoTaskMemFree(memory: Handle);
}
#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(
        folder: *const Guid,
        flags: u32,
        token: Handle,
        path: *mut *mut u16,
    ) -> i32;
}
#[link(name = "userenv")]
unsafe extern "system" {
    fn GetAppContainerFolderPath(sid: *const u16, path: *mut *mut u16) -> i32;
    fn DeriveAppContainerSidFromAppContainerName(name: *const u16, sid: *mut Handle) -> i32;
}
pub(super) fn combine<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(Failures {
            errors: vec![primary, cleanup],
        }
        .into()),
    }
}
fn retain_close<T>(result: Result<T>, cleanup: Result<()>, uncertain: &mut bool) -> Result<T> {
    *uncertain |= cleanup.is_err();
    combine(result, cleanup)
}
fn validate_name(name: &str) -> Result<()> {
    let tail = name
        .strip_prefix("Scientific.Security.")
        .ok_or_else(|| anyhow::anyhow!("profile moniker differs"))?;
    ensure!(
        tail.len() == 32
            && tail
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "profile moniker must contain 32 lowercase hexadecimal digits"
    );
    Ok(())
}
fn moniker(guid: &Guid) -> String {
    let mut text = format!(
        "Scientific.Security.{:08x}{:04x}{:04x}",
        guid.a, guid.b, guid.c
    );
    use std::fmt::Write;
    for byte in guid.d {
        write!(&mut text, "{byte:02x}").expect("in-memory moniker formatting");
    }
    text
}
fn checked_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.as_os_str().encode_wide().count() < 32767
            && !path.as_os_str().encode_wide().any(|unit| unit == 0)
            && !path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir)),
        "owned profile path is not a bounded absolute path"
    );
    ensure!(
        path.ancestors().count() <= 64,
        "profile path exceeds ancestor budget"
    );
    plain_path(path)
}
fn profile_paths(local: &Path, name: &str) -> Result<(PathBuf, PathBuf)> {
    validate_name(name)?;
    checked_path(local)?;
    let root = local.join("Packages").join(name);
    let ac = root.join("AC");
    checked_path(&ac)?;
    Ok((root, ac))
}
fn require_folder(expected: &Path, actual: &Path) -> Result<()> {
    checked_path(actual)?;
    ensure!(
        ordinal_path_equal(
            expected
                .to_str()
                .context("owned expected profile path encoding")?,
            actual
                .to_str()
                .context("owned actual profile path encoding")?
        )?,
        "profile API path is outside its unique owned location"
    );
    Ok(())
}
fn require_absent(path: &Path) -> Result<()> {
    checked_path(path)?;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!("refuse an existing unowned profile storage location"),
        Err(_) => anyhow::bail!("profile storage absence cannot be established"),
    }
}
fn task_path(status: i32, raw: *mut u16) -> Result<PathBuf> {
    let result = (|| {
        ensure!(
            status == 0 && !raw.is_null(),
            "owned profile path query failed hresult={:08X}",
            status as u32
        );
        let mut length = 0;
        while length < 32767 && unsafe { *raw.add(length) } != 0 {
            length += 1;
        }
        ensure!(
            length > 0 && length < 32767,
            "owned profile native path exceeds bound"
        );
        let text = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })?;
        let path = PathBuf::from(text);
        checked_path(&path)?;
        Ok(path)
    })();
    // Both APIs allocate with the COM task allocator. Free even an error's partial output.
    if !raw.is_null() {
        unsafe { CoTaskMemFree(raw.cast()) };
    }
    result
}
fn local_app_data() -> Result<PathBuf> {
    let mut raw = null_mut();
    let status = unsafe { SHGetKnownFolderPath(&LOCAL_APP_DATA, 0, null_mut(), &mut raw) };
    task_path(status, raw)
}
pub(super) fn sid_text(sid: Handle) -> Result<String> {
    ensure!(!sid.is_null(), "owned profile SID unavailable");
    let mut raw = null_mut();
    let success = unsafe { ConvertSidToStringSidW(sid, &mut raw) };
    let code = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let result = (|| {
        ensure!(
            success != 0 && !raw.is_null(),
            "convert owned profile SID failed winerror={code}"
        );
        let mut length = 0;
        while length < 256 && unsafe { *raw.add(length) } != 0 {
            length += 1;
        }
        ensure!(
            length > 0 && length < 256,
            "owned profile SID text exceeds bound"
        );
        let text = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })?;
        crate::windows_security::package_sid(&text)?;
        Ok(text)
    })();
    let cleanup = if raw.is_null() || unsafe { LocalFree(raw.cast()) }.is_null() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("owned SID text cleanup failed"))
    };
    combine(result, cleanup)
}
fn derived_sid(name: &str) -> Result<String> {
    validate_name(name)?;
    let name = wide(name);
    let mut raw = null_mut();
    let status = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut raw) };
    let result = (|| {
        ensure!(
            status == 0 && !raw.is_null(),
            "derive owned profile SID failed hresult={:08X}",
            status as u32
        );
        sid_text(raw)
    })();
    let cleanup = if raw.is_null() || unsafe { FreeSid(raw) }.is_null() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("derived profile SID cleanup failed"))
    };
    combine(result, cleanup)
}
fn close_file(file: File) -> Result<()> {
    let handle = file.into_raw_handle();
    let success = unsafe { CloseHandle(handle) };
    let code = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    ensure!(
        success != 0,
        "owned profile filesystem close failed winerror={code}"
    );
    Ok(())
}
struct Entry {
    file: Option<File>,
    path: PathBuf,
    id: ObjectId,
    directory: bool,
}
impl Entry {
    fn open(path: &Path, seal: bool, uncertain: &mut bool) -> Result<Self> {
        checked_path(path)?;
        let text = wide(path);
        // Deny delete sharing so the retained name cannot be renamed or replaced during sealing.
        let raw = unsafe {
            CreateFileW(
                text.as_ptr(),
                if seal { 0x60080 } else { 0x80 },
                3,
                std::ptr::null(),
                3,
                0x02200000,
                null_mut(),
            )
        };
        let code = if raw.is_null() || raw as isize == -1 {
            unsafe { GetLastError() }
        } else {
            0
        };
        ensure!(
            !raw.is_null() && raw as isize != -1,
            "retain owned profile filesystem object failed winerror={code}"
        );
        let file = unsafe { File::from_raw_handle(raw) };
        let result = (|| {
            let metadata = file.metadata()?;
            ensure!(
                metadata.file_attributes() & 0x400 == 0
                    && (metadata.is_dir() || metadata.is_file()),
                "owned profile object is a reparse point or unsupported type"
            );
            let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
                unsafe { std::mem::zeroed() };
            ensure!(
                unsafe {
                    windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
                        file.as_raw_handle(),
                        &mut info,
                    )
                } != 0
                    && (metadata.is_dir() || info.nNumberOfLinks == 1),
                "owned profile file has unknown or aliased link identity"
            );
            let id = identity::object_id(&file)?;
            ensure!(
                identity::path_object_id(path)? == id,
                "profile pathname does not identify retained object"
            );
            Ok((id, metadata.is_dir()))
        })();
        match result {
            Ok((id, directory)) => Ok(Self {
                file: Some(file),
                path: path.to_path_buf(),
                id,
                directory,
            }),
            Err(primary) => retain_close(Err(primary), close_file(file), uncertain),
        }
    }
    fn require(&self) -> Result<()> {
        checked_path(&self.path)?;
        let file = self
            .file
            .as_ref()
            .context("owned profile object is closed")?;
        let metadata = file.metadata()?;
        let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
            unsafe { std::mem::zeroed() };
        ensure!(
            unsafe {
                windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
                    file.as_raw_handle(),
                    &mut info,
                )
            } != 0
                && (self.directory || info.nNumberOfLinks == 1),
            "retained profile link identity changed"
        );
        ensure!(
            metadata.file_attributes() & 0x400 == 0
                && metadata.is_dir() == self.directory
                && identity::object_id(file)? == self.id
                && identity::path_object_id(&self.path)? == self.id,
            "retained profile object/path identity changed"
        );
        Ok(())
    }
}
fn tree_budget(count: usize, depth: usize) -> Result<()> {
    ensure!(
        count < 256 && (1..=32).contains(&depth),
        "new profile storage exceeds finite tree/depth budget"
    );
    Ok(())
}
pub(super) struct Storage {
    name: String,
    expected_sid: String,
    expected_ac: PathBuf,
    root: PathBuf,
    user: String,
    anchors: Vec<Entry>,
    entries: Vec<Entry>,
    closed: bool,
    uncertain: bool,
}
impl Storage {
    fn for_root(root: PathBuf) -> Self {
        Self {
            name: String::new(),
            expected_sid: String::new(),
            expected_ac: root.join("AC"),
            root,
            user: String::new(),
            anchors: Vec::new(),
            entries: Vec::new(),
            closed: false,
            uncertain: false,
        }
    }
    pub(super) fn before_create() -> Result<Self> {
        let mut guid = Guid::default();
        ensure!(
            unsafe { CoCreateGuid(&mut guid) } == 0,
            "create unique owned profile moniker failed"
        );
        let name = moniker(&guid);
        let expected_sid = derived_sid(&name)?;
        Self::for_profile(&name, &expected_sid)
    }
    pub(in super::super) fn assigned_sid(name: &str) -> Result<String> {
        derived_sid(name)
    }
    pub(super) fn for_profile(name: &str, expected_sid: &str) -> Result<Self> {
        validate_name(name)?;
        ensure!(
            derived_sid(name)? == expected_sid,
            "profile name and assigned SID differ"
        );
        let user = crate::windows_security::sxs::current_user_sid()?;
        policy::sddl(&user, expected_sid, true)?;
        let (root, expected_ac) = profile_paths(&local_app_data()?, name)?;
        let mut value = Self::for_root(root);
        value.name = name.to_owned();
        value.expected_sid = expected_sid.to_owned();
        value.expected_ac = expected_ac;
        value.user = user;
        let result = (|| {
            require_absent(&value.root)?;
            let ancestors = value
                .root
                .parent()
                .context("profile package parent absent")?
                .ancestors()
                .collect::<Vec<_>>();
            ensure!(
                ancestors.len() <= 64,
                "profile path exceeds ancestor budget"
            );
            for path in ancestors.into_iter().rev() {
                let entry = Entry::open(path, false, &mut value.uncertain)?;
                value.anchors.push(entry);
                ensure!(
                    value.anchors.last().is_some_and(|entry| entry.directory),
                    "profile ancestor is not a directory"
                );
            }
            require_absent(&value.root)?;
            Ok(())
        })();
        if let Err(primary) = result {
            return combine(Err(primary), value.close());
        }
        Ok(value)
    }
    pub(super) fn name(&self) -> Vec<u16> {
        wide(&self.name)
    }
    fn collect(&mut self) -> Result<()> {
        ensure!(
            !self.closed && self.entries.is_empty(),
            "profile storage collection repeated"
        );
        self.entries
            .push(Entry::open(&self.root, true, &mut self.uncertain)?);
        ensure!(
            self.entries[0].directory,
            "profile package root is not a directory"
        );
        let mut next = 0;
        while next < self.entries.len() {
            self.entries[next].require()?;
            if self.entries[next].directory {
                let parent = self.entries[next].path.clone();
                for child in std::fs::read_dir(&parent)? {
                    let child = child?;
                    let path = child.path();
                    let relative = path
                        .strip_prefix(&self.root)
                        .context("profile descendant escaped root")?;
                    let depth = relative.components().count();
                    tree_budget(self.entries.len() - 1, depth)?;
                    ensure!(
                        path.parent() == Some(parent.as_path())
                            && relative
                                .components()
                                .all(|part| matches!(part, Component::Normal(_))),
                        "profile enumerated child identity differs"
                    );
                    let entry = Entry::open(&path, true, &mut self.uncertain)?;
                    let aliased = self.entries.iter().any(|existing| existing.id == entry.id);
                    self.entries.push(entry); // Transfer before any later validation can fail.
                    ensure!(!aliased, "profile tree contains aliased object identity");
                }
            }
            next += 1;
        }
        Ok(())
    }
    fn seal_order(&self) -> Vec<usize> {
        let mut order = (0..self.entries.len()).collect::<Vec<_>>();
        order.sort_by_key(|index| {
            std::cmp::Reverse(self.entries[*index].path.as_os_str().encode_wide().count())
        });
        order
    }
    fn seal(&self, user: &str, package: &str) -> Result<()> {
        ensure!(
            !self.closed && !self.entries.is_empty() && self.entries.len() <= 257,
            "owned profile retained tree exceeds bound"
        );
        for index in self.seal_order() {
            for anchor in &self.anchors {
                anchor.require()?;
            }
            let entry = &self.entries[index];
            entry.require()?;
            policy::apply(
                entry
                    .file
                    .as_ref()
                    .context("profile seal owner is closed")?
                    .as_raw_handle(),
                user,
                package,
                entry.directory,
            )?;
            entry.require()?;
        }
        Ok(())
    }
    pub(super) fn prepare(
        &mut self,
        actual_sid: Handle,
        mut emit: impl FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            !self.closed && !self.name.is_empty(),
            "profile preparation owner is unavailable"
        );
        let package = sid_text(actual_sid)?;
        ensure!(
            package == self.expected_sid,
            "created profile SID differs from assigned package"
        );
        let text = wide(&package);
        let mut raw = null_mut();
        let status = unsafe { GetAppContainerFolderPath(text.as_ptr(), &mut raw) };
        let folder = task_path(status, raw)?;
        require_folder(&self.expected_ac, &folder)?;
        for anchor in &self.anchors {
            anchor.require()?;
        }
        self.collect()?;
        let mut found = false;
        for entry in &self.entries {
            if entry.directory && require_folder(&folder, &entry.path).is_ok() {
                found = true;
            }
        }
        ensure!(
            found,
            "actual profile AC directory is absent from retained package tree"
        );
        self.seal(&self.user, &package)?;
        emit(&format!(
            "WINDOWS_PROFILE sealed=true capabilities=0 entries={}",
            self.entries.len() - 1
        ))
    }
    fn close_with(&mut self, mut close: impl FnMut(File) -> Result<()>) -> Result<()> {
        if self.closed {
            ensure!(
                !self.uncertain,
                "profile filesystem cleanup remains uncertain"
            );
            return Ok(());
        }
        self.closed = true;
        let mut errors = Vec::new();
        for entry in self
            .entries
            .iter_mut()
            .rev()
            .chain(self.anchors.iter_mut().rev())
        {
            if let Some(file) = entry.file.take()
                && let Err(error) = close(file)
            {
                errors.push(error);
            }
        }
        self.entries.clear();
        self.anchors.clear();
        self.uncertain |= !errors.is_empty();
        if self.uncertain {
            if errors.is_empty() {
                errors.push(anyhow::anyhow!(
                    "profile filesystem cleanup remains uncertain"
                ));
            }
            return Err(Failures { errors }.into());
        }
        Ok(())
    }
    pub(super) fn close(&mut self) -> Result<()> {
        self.close_with(close_file)
    }
}
impl Drop for Storage {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
#[cfg(test)]
#[path = "profile_storage_tests.rs"]
mod tests;
