//! Private native-state creation, held object identity, bounded reads and explicit file cleanup.
use super::*;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::windows::{
        fs::MetadataExt,
        io::{AsRawHandle, FromRawHandle, IntoRawHandle},
    },
};
#[repr(C)]
struct SecurityAttributes {
    size: u32,
    descriptor: Handle,
    inherit: i32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateDirectoryW(path: *const u16, security: *const SecurityAttributes) -> i32;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *const SecurityAttributes,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetSecurityInfo(
        object: Handle,
        kind: i32,
        information: u32,
        owner: *mut Handle,
        group: *mut Handle,
        dacl: *mut Handle,
        sacl: *mut Handle,
        descriptor: *mut Handle,
    ) -> u32;
    fn GetSecurityDescriptorLength(descriptor: Handle) -> u32;
}
pub(super) fn private_sddl(user: &str, directory: bool) -> Result<String> {
    ensure!(
        user.starts_with("S-1-")
            && user.split('-').skip(2).all(|part| !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))),
        "invalid native state owner SID"
    );
    let flags = if directory { "OICI" } else { "" };
    let system = if user == "S-1-5-18" {
        String::new()
    } else {
        format!("(A;{flags};0x001F01FF;;;S-1-5-18)")
    };
    Ok(format!(
        "O:{user}D:P(D;{flags};0x000C0000;;;S-1-3-4){system}(A;{flags};0x001F01FF;;;{user})"
    ))
}
fn read_security(file: &File) -> Result<Vec<u8>> {
    let (mut owner, mut group, mut dacl, mut sacl, mut raw) =
        (null_mut(), null_mut(), null_mut(), null_mut(), null_mut());
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            1,
            7,
            &mut owner,
            &mut group,
            &mut dacl,
            &mut sacl,
            &mut raw,
        )
    };
    let result = (|| {
        ensure!(
            status == 0
                && !raw.is_null()
                && !owner.is_null()
                && !group.is_null()
                && !dacl.is_null(),
            "native state security query failed winerror={status}"
        );
        let size = unsafe { GetSecurityDescriptorLength(raw) };
        ensure!(
            (20..=65536).contains(&size),
            "native state descriptor exceeds bound"
        );
        Ok(unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), size as usize) }.to_vec())
    })();
    let cleanup = if raw.is_null() || unsafe { LocalFree(raw) }.is_null() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("native state descriptor cleanup failed"))
    };
    finish(result, cleanup)
}
pub(super) fn private(file: &File, user: &str, directory: bool) -> Result<()> {
    let mut expected = Descriptor::new(&private_sddl(user, directory)?)?;
    let result = (|| {
        let actual = read_security(file)?;
        let actual = Relative::parse(&actual)?;
        let size = unsafe { GetSecurityDescriptorLength(expected.0) };
        ensure!(
            (20..=65536).contains(&size),
            "native expected state descriptor exceeds bound"
        );
        let expected_bytes =
            unsafe { std::slice::from_raw_parts(expected.0.cast::<u8>(), size as usize) };
        let expected = Relative::parse(expected_bytes)?;
        ensure!(
            actual.control & 0x1004 == 0x1004
                && actual.owner == expected.owner
                && actual.group.is_some(),
            "native state ownership/protection differs"
        );
        let (actual, expected) = (
            Acl::parse(actual.dacl.context("native state DACL absent")?)?,
            Acl::parse(expected.dacl.context("native expected DACL absent")?)?,
        );
        ensure!(
            actual.revision == expected.revision
                && actual.aces.len() == expected.aces.len()
                && actual
                    .aces
                    .iter()
                    .zip(&expected.aces)
                    .all(|(a, b)| a.bytes == b.bytes),
            "native state private DACL differs"
        );
        Ok(())
    })();
    finish(result, expected.close())
}
fn close(file: File) -> Result<()> {
    let raw = file.into_raw_handle();
    let success = unsafe { CloseHandle(raw) };
    let code = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    ensure!(
        success != 0,
        "native state file close failed winerror={code}"
    );
    Ok(())
}
pub(super) struct Pin {
    pub(super) file: Option<File>,
    pub(super) path: PathBuf,
    pub(super) id: ObjectId,
    pub(super) directory: bool,
    uncertain: bool,
}
impl Pin {
    pub(super) fn open(path: &Path, directory: bool) -> Result<Self> {
        plain_path(path)?;
        let text = wide(path);
        let raw = unsafe {
            CreateFileW(
                text.as_ptr(),
                if directory { 0x20080 } else { 0x120081 },
                if directory { 3 } else { 1 },
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
            "retain native state object failed winerror={code}"
        );
        let file = unsafe { File::from_raw_handle(raw) };
        let result = (|| {
            let metadata = file.metadata()?;
            ensure!(
                metadata.file_attributes() & 0x400 == 0
                    && metadata.is_dir() == directory
                    && (directory || metadata.is_file()),
                "native state object type/reparse differs"
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
                    && (directory || info.nNumberOfLinks == 1),
                "native state file link identity differs"
            );
            let id = identity::object_id(&file)?;
            ensure!(
                identity::path_object_id(path)? == id,
                "native state pathname changed"
            );
            Ok(id)
        })();
        match result {
            Ok(id) => Ok(Self {
                file: Some(file),
                path: path.to_owned(),
                id,
                directory,
                uncertain: false,
            }),
            Err(primary) => finish(Err(primary), close(file)),
        }
    }
    pub(super) fn require(&self) -> Result<()> {
        plain_path(&self.path)?;
        let file = self.file.as_ref().context("native state pin closed")?;
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
            "native state link identity changed"
        );
        ensure!(
            !self.uncertain
                && metadata.file_attributes() & 0x400 == 0
                && metadata.is_dir() == self.directory
                && identity::object_id(file)? == self.id
                && identity::path_object_id(&self.path)? == self.id,
            "native state retained identity differs"
        );
        Ok(())
    }
    pub(super) fn read_bytes(&self) -> Result<Vec<u8>> {
        self.require()?;
        let mut file = self.file.as_ref().context("native receipt pin closed")?;
        let size = file.metadata()?.len();
        ensure!(size > 0 && size <= 4096, "native receipt exceeds bound");
        file.seek(SeekFrom::Start(0))?;
        let mut value = vec![0; size as usize];
        file.read_exact(&mut value)?;
        let mut tail = [0];
        ensure!(file.read(&mut tail)? == 0, "native receipt grew");
        Ok(value)
    }
    pub(super) fn bytes(&mut self) -> Result<Vec<u8>> {
        self.read_bytes()
    }
    pub(super) fn close(&mut self) -> Result<()> {
        if let Some(file) = self.file.take()
            && let Err(error) = close(file)
        {
            self.uncertain = true;
            return Err(error);
        }
        ensure!(!self.uncertain, "native state pin close remains uncertain");
        Ok(())
    }
}
impl Drop for Pin {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
pub(super) fn anchors(state: &Path) -> Result<Vec<Pin>> {
    let paths = state
        .parent()
        .context("native state parent absent")?
        .ancestors()
        .collect::<Vec<_>>();
    ensure!(paths.len() <= 64, "native state ancestor budget exceeded");
    let mut pins = Vec::new();
    for path in paths.into_iter().rev() {
        pins.push(Pin::open(path, true)?);
    }
    Ok(pins)
}
pub(super) fn create_private(path: &Path, user: &str) -> Result<()> {
    plain_path(path)?;
    let mut descriptor = Descriptor::new(&private_sddl(user, true)?)?;
    let attributes = SecurityAttributes {
        size: size_of::<SecurityAttributes>() as u32,
        descriptor: descriptor.0,
        inherit: 0,
    };
    let text = wide(path);
    let success = unsafe { CreateDirectoryW(text.as_ptr(), &attributes) };
    let code = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    finish(
        (|| {
            ensure!(
                success != 0,
                "create new private native state failed winerror={code}"
            );
            Ok(())
        })(),
        descriptor.close(),
    )
}
pub(super) fn write_new(path: &Path, user: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 4096,
        "native durable record exceeds bound"
    );
    plain_path(path)?;
    let text = wide(path);
    let mut descriptor = Descriptor::new(&private_sddl(user, false)?)?;
    let attributes = SecurityAttributes {
        size: size_of::<SecurityAttributes>() as u32,
        descriptor: descriptor.0,
        inherit: 0,
    };
    let raw = unsafe {
        CreateFileW(
            text.as_ptr(),
            0xc0000000,
            0,
            &attributes,
            1,
            0x00200080,
            null_mut(),
        )
    };
    let code = if raw.is_null() || raw as isize == -1 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let opened = if raw.is_null() || raw as isize == -1 {
        Err(anyhow::anyhow!(
            "create new native durable record failed winerror={code}"
        ))
    } else {
        Ok(unsafe { File::from_raw_handle(raw) })
    };
    let released = descriptor.close();
    let mut file = match (opened, released) {
        (Ok(file), Ok(())) => file,
        (Ok(file), Err(primary)) => return finish(Err(primary), close(file)),
        (Err(primary), cleanup) => return finish(Err(primary), cleanup),
    };
    let result = (|| {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    finish(result, close(file))
}
