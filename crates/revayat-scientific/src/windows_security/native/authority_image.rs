//! Held read-only authority executable. The parser consumes the bytes actually held for launch.
use super::*;
use crate::identity::{self, Fingerprint};
use crate::windows_security::image::{PeImage, sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::{fs::OpenOptionsExt, io::IntoRawHandle};

pub(super) struct AuthorityImage {
    held: Option<File>,
    identity: Fingerprint,
}
impl AuthorityImage {
    pub(super) fn open(path: &Path, expected: &Fingerprint) -> Result<Self> {
        plain_path(path)?;
        let held = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(path)?;
        let mut owner = Self {
            held: Some(held),
            identity: expected.clone(),
        };
        let result = owner.require(path);
        if let Err(primary) = result {
            let cleanup = usize::from(owner.close().is_err());
            return super::creation::retain_cleanup(Err(primary), cleanup);
        }
        Ok(owner)
    }
    pub(super) fn file(&mut self) -> Result<&mut File> {
        self.held
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("authority image owner is closed"))
    }
    pub(super) fn require(&mut self, path: &Path) -> Result<()> {
        plain_path(path)?;
        let identity = self.identity.clone();
        let held = self.file()?;
        let metadata = held.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.len() == identity.size
                && (256..=8 * 1024 * 1024).contains(&metadata.len())
                && metadata.modified()? == identity.modified
                && identity::object_id(held)? == identity.identity,
            "held authority image identity differs"
        );
        held.seek(SeekFrom::Start(0))?;
        let mut bytes = vec![0; metadata.len() as usize];
        let result = (|| {
            held.read_exact(&mut bytes)?;
            let mut tail = [0; 1];
            ensure!(
                held.read(&mut tail)? == 0 && sha256(&bytes) == identity.sha256,
                "held authority image bytes differ"
            );
            PeImage::parse(&bytes, 1)?.qualify_rust_authority()?;
            ensure!(
                identity::file_identity(path, Some(8 * 1024 * 1024))? == identity,
                "authority pathname no longer identifies held image"
            );
            held.seek(SeekFrom::Start(0))?;
            Ok(())
        })();
        bytes.fill(0);
        result
    }
    pub(super) fn close(&mut self) -> Result<()> {
        let Some(held) = self.held.take() else {
            return Ok(());
        };
        let handle = held.into_raw_handle();
        // SAFETY: take+into_raw_handle transfer one live owned handle, never retried after uncertainty.
        let success = unsafe { CloseHandle(handle) };
        let code = if success == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        ensure!(
            success != 0,
            "authority image close failed winerror={code:?}"
        );
        Ok(())
    }
}
impl Drop for AuthorityImage {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image() -> std::path::PathBuf {
        let exe = std::env::current_exe().unwrap();
        crate::executable_paths::binary_directory(&exe)
            .unwrap()
            .join("registry-authority.exe")
    }
    #[test]
    fn held_actual_rust_authority_rejects_substitution_and_closes_once() {
        let image = image();
        let identity = identity::file_identity(&image, Some(8 * 1024 * 1024)).unwrap();
        let mut held = AuthorityImage::open(&image, &identity).unwrap();
        held.require(&image).unwrap();
        let mut wrong = identity.clone();
        wrong.sha256 = "0".repeat(64);
        assert!(AuthorityImage::open(&image, &wrong).is_err());
        let directory = tempfile::tempdir().unwrap();
        let other = directory.path().join("registry-authority.exe");
        std::fs::copy(&image, &other).unwrap();
        assert!(held.require(&other).is_err());
        held.close().unwrap();
        held.close().unwrap();
        assert!(held.file().is_err());
    }
}
