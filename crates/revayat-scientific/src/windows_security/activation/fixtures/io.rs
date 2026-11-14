//! Absolute plain-path, create-only, retained-descriptor fixture byte ownership.
use crate::identity::{self, ObjectId};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn require_identity(bytes: &[u8], length: u64, expected: &str) -> Result<()> {
    ensure!(
        bytes.len() as u64 == length && digest(bytes) == expected,
        "activation prepared identity differs"
    );
    Ok(())
}
pub fn plain(path: &Path, allow_missing: bool) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "native fixture inputs require absolute paths"
    );
    let ancestors = path.ancestors().collect::<Vec<_>>();
    ensure!(
        ancestors.len() <= 64,
        "native fixture path exceeds ancestor bound"
    );
    for ancestor in ancestors.into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => ensure!(
                !identity::is_link(ancestor)?,
                "native fixture selected input/ancestor is a reparse point"
            ),
            Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
pub fn missing(path: &Path) -> Result<()> {
    plain(path, true)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => anyhow::bail!("fixed activation output or override already exists"),
    }
}
pub fn no_overrides(image: &Path) -> Result<()> {
    for extension in ["manifest", "config"] {
        let mut appended = image.as_os_str().to_owned();
        appended.push(format!(".{extension}"));
        missing(Path::new(&appended))?;
        missing(&image.with_extension(extension))?;
    }
    Ok(())
}
fn open(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    if create {
        options.write(true).create_new(true);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options
            .share_mode(if create { 0 } else { 1 })
            .custom_flags(0x00200000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    Ok(options.open(path)?)
}
fn close(file: File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::IntoRawFd;
        let descriptor = file.into_raw_fd();
        // SAFETY: consumes this owned descriptor exactly once, including uncertainty.
        ensure!(
            unsafe { libc::close(descriptor) } == 0,
            "fixture descriptor close failed"
        );
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::IntoRawHandle;
        let handle = file.into_raw_handle();
        // SAFETY: consumes this owned native handle exactly once.
        ensure!(
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) } != 0,
            "fixture handle close failed"
        );
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        drop(file);
        anyhow::bail!("fixture ownership requires supported native platform")
    }
}
pub fn read(stream: &mut File, maximum: usize) -> Result<Vec<u8>> {
    let before = stream.metadata()?;
    ensure!(
        before.is_file() && before.len() > 0 && before.len() <= maximum as u64,
        "activation held input exceeds fixed bound"
    );
    stream.seek(SeekFrom::Start(0))?;
    let mut bytes = vec![0; before.len() as usize];
    let result = (|| {
        stream.read_exact(&mut bytes)?;
        ensure!(
            stream.read(&mut [0])? == 0 && stream.metadata()?.len() == before.len(),
            "activation held input changed length"
        );
        Ok(())
    })();
    if let Err(error) = result {
        bytes.fill(0);
        return Err(error);
    }
    Ok(bytes)
}
pub struct HeldFile {
    file: Option<File>,
    path: PathBuf,
    id: ObjectId,
    maximum: usize,
    length: u64,
    digest: String,
}
impl HeldFile {
    pub fn open(path: &Path, maximum: usize) -> Result<Self> {
        plain(path, false)?;
        let file = open(path, false)?;
        let mut value = Self {
            id: ObjectId {
                volume: 0,
                index: 0,
            },
            file: Some(file),
            path: path.into(),
            maximum,
            length: 0,
            digest: String::new(),
        };
        let result = (|| {
            value.id = identity::object_id(value.file.as_ref().unwrap())?;
            ensure!(
                identity::path_object_id(path)? == value.id,
                "activation opened object differs from path"
            );
            let mut bytes = read(value.file.as_mut().unwrap(), maximum)?;
            value.length = bytes.len() as u64;
            value.digest = digest(&bytes);
            bytes.fill(0);
            value.verify()
        })();
        if let Err(primary) = result {
            return match value.close() {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(super::super::Failures {
                    errors: vec![primary, cleanup],
                }
                .into()),
            };
        }
        Ok(value)
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        self.verify()?;
        let mut bytes = read(self.file.as_mut().unwrap(), self.maximum)?;
        if let Err(error) = require_identity(&bytes, self.length, &self.digest) {
            bytes.fill(0);
            return Err(error);
        }
        Ok(bytes)
    }
    pub fn verify(&mut self) -> Result<()> {
        plain(&self.path, false)?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("activation retained file is closed"))?;
        ensure!(
            identity::object_id(file)? == self.id
                && identity::path_object_id(&self.path)? == self.id,
            "activation retained object identity changed"
        );
        let mut bytes = read(file, self.maximum)?;
        let result = require_identity(&bytes, self.length, &self.digest);
        bytes.fill(0);
        result
    }
    pub fn close(&mut self) -> Result<()> {
        self.file.take().map_or(Ok(()), close)
    }
    pub fn identity(&self) -> ObjectId {
        self.id
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for HeldFile {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
pub fn create(path: &Path, bytes: &[u8], maximum: usize) -> Result<HeldFile> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "activation created input exceeds fixed bound"
    );
    missing(path)?;
    let mut created = open(path, true)?;
    let result = (|| {
        let id = identity::object_id(&created)?;
        created.write_all(bytes)?;
        created.sync_all()?;
        let mut actual = read(&mut created, maximum)?;
        let equal = actual == bytes;
        actual.fill(0);
        ensure!(equal, "activation build input readback differs");
        Ok(id)
    })();
    let cleanup = close(created);
    let id = match (result, cleanup) {
        (Err(primary), Err(cleanup)) => {
            return Err(super::super::Failures {
                errors: vec![primary, cleanup],
            }
            .into());
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
        (Ok(id), Ok(())) => id,
    };
    let mut held = HeldFile::open(path, maximum)?;
    if held.id != id {
        let cleanup = held.close();
        let primary = anyhow::anyhow!("activation reopened build object differs");
        return match cleanup {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(super::super::Failures {
                errors: vec![primary, cleanup],
            }
            .into()),
        };
    }
    Ok(held)
}
