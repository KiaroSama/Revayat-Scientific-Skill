//! Closed full-runtime data copy. Empty package data never relaxes image/manifest gates.
use super::{io, source};
use crate::{
    identity::{self, ObjectId},
    runtime,
    windows_security::activation::Failures,
};
use anyhow::{Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};
const MAXIMUM: usize = 64 * 1024 * 1024;
struct Bytes(Vec<u8>);
impl Drop for Bytes {
    fn drop(&mut self) {
        self.0.fill(0)
    }
}
#[derive(PartialEq, Eq)]
struct Fingerprint {
    id: ObjectId,
    length: u64,
    modified: SystemTime,
    hash: String,
}
struct Member {
    file: Option<File>,
    path: PathBuf,
    id: ObjectId,
}
impl Member {
    fn open(path: &Path, create: bool) -> Result<Self> {
        io::plain(path, create)?;
        let mut options = OpenOptions::new();
        options.read(true);
        if create {
            io::missing(path)?;
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
        let file = options.open(path)?;
        let mut owner = Self {
            file: Some(file),
            path: path.into(),
            id: ObjectId {
                volume: 0,
                index: 0,
            },
        };
        let result = (|| {
            owner.id = identity::object_id(owner.file.as_ref().unwrap())?;
            ensure!(
                identity::path_object_id(path)? == owner.id
                    && owner.file.as_ref().unwrap().metadata()?.is_file(),
                "runtime data opened identity/type differs"
            );
            Ok(())
        })();
        match result {
            Ok(()) => Ok(owner),
            Err(error) => runtime::with_cleanup(Err(error), owner.close()),
        }
    }
    fn read(&mut self) -> Result<(Bytes, Fingerprint)> {
        io::plain(&self.path, false)?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("runtime data handle is closed"))?;
        ensure!(
            identity::path_object_id(&self.path)? == self.id
                && identity::object_id(file)? == self.id,
            "runtime data retained identity changed"
        );
        let before = file.metadata()?;
        ensure!(
            before.is_file() && before.len() <= MAXIMUM as u64,
            "runtime data file exceeds bound"
        );
        file.rewind()?;
        let mut bytes = Bytes(vec![0; before.len() as usize]);
        file.read_exact(&mut bytes.0)?;
        ensure!(
            file.read(&mut [0u8; 1])? == 0,
            "runtime data file grew while reading"
        );
        let after = file.metadata()?;
        ensure!(
            after.len() == before.len()
                && after.modified()? == before.modified()?
                && identity::object_id(file)? == self.id
                && identity::path_object_id(&self.path)? == self.id,
            "runtime data changed while reading"
        );
        let fingerprint = Fingerprint {
            id: self.id,
            length: before.len(),
            modified: before.modified()?,
            hash: io::digest(&bytes.0),
        };
        Ok((bytes, fingerprint))
    }
    fn close(&mut self) -> Result<()> {
        let Some(file) = self.file.take() else {
            return Ok(());
        };
        #[cfg(unix)]
        {
            use std::os::fd::IntoRawFd;
            ensure!(
                unsafe { libc::close(file.into_raw_fd()) } == 0,
                "runtime data descriptor close failed"
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::IntoRawHandle;
            ensure!(
                unsafe { windows_sys::Win32::Foundation::CloseHandle(file.into_raw_handle()) } != 0,
                "runtime data handle close failed"
            );
        }
        #[cfg(not(any(unix, windows)))]
        {
            drop(file);
            anyhow::bail!("runtime data requires supported native ownership");
        }
        Ok(())
    }
}
impl Drop for Member {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
fn finish<T>(result: Result<T>, members: &mut Vec<Member>) -> Result<T> {
    let mut errors = Vec::new();
    for mut member in std::mem::take(members).into_iter().rev() {
        if let Err(error) = member.close() {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        return result;
    }
    match result {
        Ok(_) => Err(Failures { errors }.into()),
        Err(primary) => {
            errors.insert(0, primary);
            Err(Failures { errors }.into())
        }
    }
}
/// Only a regular member of the original Lib/DLLs data trees can reach this path.
/// Root executables, resource payloads and fixture images use the existing nonempty I/O.
pub fn copy_member(
    input: &Path,
    output: &Path,
    relative: &Path,
    reserve: impl FnOnce(u64) -> Result<()>,
) -> Result<()> {
    ensure!(
        input.is_absolute()
            && output.is_absolute()
            && input.file_name() == output.file_name()
            && input
                .file_name()
                .is_some_and(|name| name == "Lib" || name == "DLLs")
            && !relative.as_os_str().is_empty()
            && relative
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "runtime data copy is outside closed member roots"
    );
    io::plain(input, false)?;
    io::plain(output, false)?;
    let source = input.join(relative);
    let target = output.join(relative);
    io::missing(&target)?;
    let mut members = Vec::new();
    let result = (|| {
        members.push(Member::open(&source, false)?);
        let (bytes, expected) = members[0].read()?;
        if bytes.0.is_empty() {
            ensure!(
                !relative
                    .extension()
                    .and_then(|v| v.to_str())
                    .is_some_and(|extension| ["exe", "dll", "pyd", "lib", "res", "manifest"]
                        .iter()
                        .any(|value| extension.eq_ignore_ascii_case(value))),
                "empty executable/manifest is not runtime data"
            );
        }
        reserve(expected.length)?;
        members.push(Member::open(&target, true)?);
        let id = members[1].id;
        let file = members[1].file.as_mut().unwrap();
        file.write_all(&bytes.0)?;
        file.sync_all()?;
        let (actual, created) = members[1].read()?;
        ensure!(
            actual.0 == bytes.0
                && created.length == expected.length
                && created.hash == expected.hash,
            "runtime data durable readback differs"
        );
        members[1].close()?;
        members.push(Member::open(&target, false)?);
        let (reopened, current) = members[2].read()?;
        ensure!(
            current.id == id
                && current.length == expected.length
                && current.hash == expected.hash
                && reopened.0 == bytes.0,
            "runtime data reopened identity/hash differs"
        );
        let (_, after) = members[0].read()?;
        ensure!(
            after == expected,
            "runtime data source changed while copying"
        );
        Ok(())
    })();
    finish(result, &mut members)
}
/// Added to the existing preparation carrier; these are real tiny filesystem copies, never native proof.
pub fn check_validation(work: &Path) -> Result<()> {
    let tree = tempfile::tempdir_in(work)?;
    let result = (|| {
        let input = tree.path().join("source").join("Lib");
        let output = tree.path().join("python").join("Lib");
        fs::create_dir_all(input.join("package"))?;
        fs::create_dir_all(output.join("package"))?;
        let member = Path::new("package").join("__init__.py");
        fs::write(input.join(&member), [])?;
        let count = std::cell::Cell::new(0);
        copy_member(&input, &output, &member, |length| {
            ensure!(length == 0, "empty data length differs");
            count.set(count.get() + 1);
            Ok(())
        })?;
        ensure!(
            count.get() == 1 && fs::read(output.join(&member))?.is_empty(),
            "empty package data was not copied/counted"
        );
        ensure!(
            io::HeldFile::open(&input.join(&member), MAXIMUM).is_err(),
            "empty fixture image gate was relaxed"
        );
        fs::write(input.join("data.bin"), b"runtime-data\0\r\n")?;
        copy_member(&input, &output, Path::new("data.bin"), |_| Ok(()))?;
        ensure!(
            fs::read(output.join("data.bin"))? == b"runtime-data\0\r\n",
            "ordinary runtime data bytes changed"
        );
        ensure!(
            copy_member(&input, &output, Path::new("data.bin"), |_| Ok(())).is_err()
                && fs::read(output.join("data.bin"))? == b"runtime-data\0\r\n",
            "runtime data overwrote a collision"
        );
        fs::write(input.join("empty.pyd"), [])?;
        ensure!(
            copy_member(&input, &output, Path::new("empty.pyd"), |_| Ok(())).is_err()
                && !output.join("empty.pyd").try_exists()?,
            "empty native image admitted as data"
        );
        fs::write(input.join("refused.txt"), [])?;
        ensure!(
            copy_member(
                &input,
                &output,
                Path::new("refused.txt"),
                |_| anyhow::bail!("budget refusal")
            )
            .is_err()
                && !output.join("refused.txt").try_exists()?,
            "budget refusal created output"
        );
        source::directory_link(&input.join("package"), &input.join("alias"))?;
        let refused = copy_member(
            &input,
            &output,
            &Path::new("alias").join("__init__.py"),
            |_| Ok(()),
        )
        .is_err();
        source::remove_directory_link(&input.join("alias"))?;
        ensure!(refused, "runtime data followed a reparse ancestor");
        Ok(())
    })();
    runtime::with_cleanup(result, tree.close().map_err(Into::into))
}
