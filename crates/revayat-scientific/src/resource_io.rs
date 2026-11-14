//! Opened-descriptor resource reads: canonical path approval must survive opening.
use crate::identity::{ObjectId, is_link, object_id, path_object_id};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, Metadata, OpenOptions},
    io::Read,
    path::Path,
    time::SystemTime,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadBoundary {
    BeforeOpen,
    AfterOpen,
    BeforeRead,
    AfterRead,
}
#[derive(PartialEq, Eq)]
struct Stamp {
    identity: ObjectId,
    bytes: u64,
    modified: SystemTime,
    changed: (i128, i128),
}
fn stamp(file: &File, metadata: &Metadata) -> Result<Stamp> {
    #[cfg(unix)]
    let changed = {
        use std::os::unix::fs::MetadataExt;
        (
            i128::from(metadata.ctime()),
            i128::from(metadata.ctime_nsec()),
        )
    };
    #[cfg(not(unix))]
    let changed = (0, 0);
    Ok(Stamp {
        identity: object_id(file)?,
        bytes: metadata.len(),
        modified: metadata.modified()?,
        changed,
    })
}
fn pinned(path: &Path, root: &Path, identity: ObjectId) -> Result<()> {
    ensure!(
        path.starts_with(root)
            && !is_link(path)?
            && path.canonicalize()? == path
            && path_object_id(path)? == identity,
        "resource path ownership changed outside its approved canonical boundary"
    );
    Ok(())
}
pub fn read(
    path: &Path,
    root: &Path,
    limit: usize,
    mut boundary: impl FnMut(ReadBoundary, &Path) -> Result<()>,
) -> Result<Vec<u8>> {
    ensure!(
        path.starts_with(root) && !is_link(path)? && path.canonicalize()? == path,
        "resource is outside the approved canonical asset boundary"
    );
    let expected = path_object_id(path)?;
    boundary(ReadBoundary::BeforeOpen, path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // No write/delete sharing while bytes are read; an existing conflicting
        // writer makes opening fail rather than admitting an unstable revision.
        options.share_mode(1);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit as u64,
        "resource is not a bounded regular file"
    );
    let original = stamp(&file, &metadata)?;
    ensure!(
        original.identity == expected,
        "resource descriptor ownership changed before opening"
    );
    boundary(ReadBoundary::AfterOpen, path)?;
    pinned(path, root, expected)?;
    boundary(ReadBoundary::BeforeRead, path)?;
    pinned(path, root, expected)?;
    let mut bytes = Vec::new();
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    boundary(ReadBoundary::AfterRead, path)?;
    ensure!(
        bytes.len() <= limit
            && bytes.len() as u64 == original.bytes
            && stamp(&file, &file.metadata()?)? == original,
        "resource bytes changed during a bounded read"
    );
    pinned(path, root, expected).context("resource path changed during reading")?;
    Ok(bytes)
}
