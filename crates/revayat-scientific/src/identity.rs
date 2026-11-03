//! Counted exact-byte identity with independently checked file and path state.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;

pub const CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectId {
    pub volume: u64,
    pub index: u64,
}

pub fn object_id(file: &File) -> Result<ObjectId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok(ObjectId {
            volume: metadata.dev(),
            index: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: file owns a live handle and info points to writable storage of
        // exactly the native API's required size. No handle ownership is taken.
        ensure!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
            "unable to identify opened file: {}",
            std::io::Error::last_os_error()
        );
        Ok(ObjectId {
            volume: u64::from(info.dwVolumeSerialNumber),
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("file identity requires a supported native platform")
}

pub fn path_object_id(path: &Path) -> Result<ObjectId> {
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        // BACKUP_SEMANTICS allows a directory handle; OPEN_REPARSE_POINT means
        // identity queries never silently follow a substituted junction.
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(path)?
    };
    #[cfg(not(windows))]
    let file = File::open(path)?;
    object_id(&file)
}

pub fn is_link(path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Includes junctions and other reparse points, not only symbolic links.
        Ok(metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0)
    }
    #[cfg(not(windows))]
    Ok(metadata.file_type().is_symlink())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fingerprint {
    pub identity: ObjectId,
    pub size: u64,
    pub modified: SystemTime,
    pub sha256: String,
}

impl Fingerprint {
    pub fn same_bytes(&self, other: &Self) -> bool {
        self.size == other.size && self.sha256 == other.sha256
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Observation {
    id: ObjectId,
    size: u64,
    modified: SystemTime,
    change_time: (i128, i128),
}

fn observation(file: &File, metadata: &Metadata) -> Result<Observation> {
    #[cfg(unix)]
    let change_time = {
        use std::os::unix::fs::MetadataExt;
        (
            i128::from(metadata.ctime()),
            i128::from(metadata.ctime_nsec()),
        )
    };
    #[cfg(not(unix))]
    let change_time = (0, 0);
    #[cfg(unix)]
    let id = {
        use std::os::unix::fs::MetadataExt;
        let _ = file;
        ObjectId {
            volume: metadata.dev(),
            index: metadata.ino(),
        }
    };
    #[cfg(not(unix))]
    let id = object_id(file)?;
    Ok(Observation {
        id,
        size: metadata.len(),
        modified: metadata.modified()?,
        change_time,
    })
}

/// A precise test seam at actual I/O boundaries, not a simulated passing result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadBoundary {
    BeforeOpen,
    BeforeRead(usize),
    AfterRead,
    AfterClose,
}

pub fn file_identity(path: &Path, max_bytes: Option<u64>) -> Result<Fingerprint> {
    file_identity_observed(path, max_bytes, |_, _| Ok(()))
}

pub fn file_identity_observed(
    path: &Path,
    max_bytes: Option<u64>,
    mut boundary: impl FnMut(ReadBoundary, &Path) -> Result<()>,
) -> Result<Fingerprint> {
    let before_metadata = fs::metadata(path)?;
    ensure!(
        before_metadata.is_file(),
        "file identity requires a regular file"
    );
    if let Some(limit) = max_bytes {
        ensure!(
            before_metadata.len() <= limit,
            "file exceeds the caller byte limit"
        );
    }
    // Obtain the path object's native identity before giving the read seam an
    // opportunity to substitute it. The read descriptor is checked independently.
    let path_handle = File::open(path)?;
    let expected = observation(&path_handle, &before_metadata)?;
    drop(path_handle);
    boundary(ReadBoundary::BeforeOpen, path)?;
    let mut file = File::open(path)?;
    let opened = observation(&file, &file.metadata()?)?;
    ensure!(
        opened.id == expected.id
            && opened.size == expected.size
            && opened.modified == expected.modified,
        "file changed before fingerprint reading"
    );
    let mut digest = Sha256::new();
    let mut consumed = 0_u64;
    let mut bytes = vec![0; CHUNK_BYTES];
    loop {
        let size = CHUNK_BYTES.min((expected.size - consumed).saturating_add(1) as usize);
        boundary(ReadBoundary::BeforeRead(size), path)?;
        let length = file.read(&mut bytes[..size])?;
        consumed += length as u64;
        ensure!(
            consumed <= expected.size,
            "file grew beyond its fingerprint snapshot byte limit"
        );
        if length == 0 {
            break;
        }
        digest.update(&bytes[..length]);
        boundary(ReadBoundary::AfterRead, path)?;
    }
    ensure!(
        consumed == expected.size && observation(&file, &file.metadata()?)? == opened,
        "file changed during fingerprint reading"
    );
    let current = File::open(path)?;
    ensure!(
        observation(&current, &current.metadata()?)? == expected,
        "file path changed during fingerprint reading"
    );
    drop(current);
    drop(file);
    boundary(ReadBoundary::AfterClose, path)?;
    let final_file = File::open(path).context("file changed after fingerprint reading")?;
    ensure!(
        observation(&final_file, &final_file.metadata()?)? == expected,
        "file changed after fingerprint reading"
    );
    Ok(Fingerprint {
        identity: expected.id,
        size: expected.size,
        modified: expected.modified,
        sha256: format!("{:x}", digest.finalize()),
    })
}
