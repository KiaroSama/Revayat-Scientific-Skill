//! Rust owner for the genuine external Python pass fixture; Python is subject data, never a controller.
use super::{
    csr,
    pass_resources::{self, Resources},
};
use crate::windows_security::image::{PeImage, sha256};
use anyhow::{Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};
#[path = "native_pass_checks.rs"]
mod checks;
pub use checks::check_validation;
pub const IMAGES: [&str; 3] = ["python.exe", "python311.dll", "vcruntime140.dll"];
const IMPORTS: [&str; 3] = ["python-exe", "python311", "vcruntime140"];
#[derive(Clone, PartialEq, Eq)]
pub struct RuntimeIdentity {
    python: PathBuf,
    hashes: [String; 3],
    lengths: [usize; 3],
    language: u16,
    manifest_hash: String,
    manifest_length: usize,
}
struct ZeroBytes(Vec<u8>);
impl Drop for ZeroBytes {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}
pub fn require_bytes(bytes: &[u8], length: usize, digest: &str) -> Result<()> {
    ensure!(
        (1..=16_777_216).contains(&length) && bytes.len() == length && sha256(bytes) == digest,
        "fixed original Python CSR contract failed"
    );
    Ok(())
}
pub fn require_path(python: &Path, expected: &Path) -> Result<()> {
    ensure!(
        python.is_absolute()
            && expected.is_absolute()
            && python == expected
            && python.file_name().is_some_and(|v| v == "python.exe")
            && python
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|v| v == "python")
            && !python
                .components()
                .any(|v| matches!(v, Component::CurDir | Component::ParentDir)),
        "fixed original Python CSR contract failed"
    );
    Ok(())
}
pub fn require_launch(
    executable: &Path,
    arguments: Option<&[&str]>,
    cwd: &Path,
    expected: &Path,
) -> Result<()> {
    require_path(executable, expected)?;
    ensure!(
        Some(cwd) == expected.parent() && arguments == Some(&["-I", "-B", "-c", "pass"][..]),
        "fixed original Python CSR contract failed"
    );
    Ok(())
}
fn plain(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "fixed runtime path is not absolute");
    let mut count = 0;
    for ancestor in path.ancestors() {
        count += 1;
        ensure!(count <= 64, "fixed runtime ancestor budget exceeded");
        let metadata = std::fs::symlink_metadata(ancestor)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "fixed runtime reparse point refused"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "fixed runtime reparse point refused"
            );
        }
    }
    Ok(())
}
fn missing(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => anyhow::bail!("fixed runtime override collision"),
    }
}
fn overrides(runtime: &Path) -> Result<()> {
    plain(runtime)?;
    for image in ["python.exe", "startup-python.exe"] {
        let image = runtime.join(image);
        for extension in ["manifest", "config"] {
            missing(&PathBuf::from(format!(
                "{}.{}",
                image
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("fixed runtime path is not Unicode"))?,
                extension
            )))?;
            missing(&image.with_extension(extension))?;
        }
        for extension in ["_pth", "zip"] {
            missing(&image.with_extension(extension))?;
        }
    }
    for name in ["python311._pth", "pyvenv.cfg", "pybuilddir.txt"] {
        missing(&runtime.join(name))?;
    }
    for name in IMAGES {
        let image = runtime.join(name);
        for extension in ["manifest", "config"] {
            missing(&PathBuf::from(format!(
                "{}.{}",
                image
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("fixed runtime path is not Unicode"))?,
                extension
            )))?;
            missing(&image.with_extension(extension))?;
        }
    }
    Ok(())
}
fn open(path: &Path) -> Result<File> {
    plain(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x00200000);
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "fixed runtime image is not a plain file"
    );
    Ok(file)
}
fn read(file: &mut File) -> Result<ZeroBytes> {
    let length = file.metadata()?.len();
    ensure!(
        (1..=16_777_216).contains(&length),
        "fixed runtime image byte bound differs"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = ZeroBytes(Vec::new());
    file.take(16_777_217).read_to_end(&mut bytes.0)?;
    ensure!(
        bytes.0.len() as u64 == length,
        "fixed runtime held image changed"
    );
    Ok(bytes)
}
fn close(file: File) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::io::IntoRawHandle;
        let handle = file.into_raw_handle();
        let closed = unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        ensure!(closed != 0, "fixed runtime file close failed");
    }
    #[cfg(unix)]
    {
        use std::os::fd::IntoRawFd;
        let fd = file.into_raw_fd();
        ensure!(
            unsafe { libc::close(fd) } == 0,
            "fixed runtime file close failed"
        );
    }
    #[cfg(not(any(windows, unix)))]
    drop(file);
    Ok(())
}
pub struct HeldRuntime {
    files: Resources<File, fn(File) -> Result<()>>,
    identity: RuntimeIdentity,
}
impl HeldRuntime {
    pub fn acquire(python: &Path, expected: Option<&RuntimeIdentity>) -> Result<Self> {
        require_path(
            python,
            expected.map(|v| v.python.as_path()).unwrap_or(python),
        )?;
        let runtime = python.parent().unwrap();
        overrides(runtime)?;
        let (files, identity) = pass_resources::acquire(
            3,
            |index| open(&runtime.join(IMAGES[index])),
            |files| {
                let mut buffers = Vec::new();
                for file in files {
                    buffers.push(read(file)?);
                }
                let mut hashes = std::array::from_fn(|_| String::new());
                let mut lengths = [0; 3];
                for index in 0..3 {
                    let bytes = &buffers[index].0;
                    PeImage::parse(bytes, 1)?.qualify_python_imports(IMPORTS[index])?;
                    hashes[index] = sha256(bytes);
                    lengths[index] = bytes.len();
                    if let Some(expected) = expected {
                        require_bytes(bytes, expected.lengths[index], &expected.hashes[index])?;
                    }
                }
                let exe_image = PeImage::parse(&buffers[0].0, 1)?;
                let exe = exe_image.manifest(1, false)?;
                let dll_image = PeImage::parse(&buffers[1].0, 1)?;
                let dll = dll_image.module_manifest(false)?;
                ensure!(
                    exe.language == dll.language && exe.bytes == dll.bytes,
                    "fixed Python default/module manifest differs"
                );
                let identity = RuntimeIdentity {
                    python: python.to_path_buf(),
                    hashes,
                    lengths,
                    language: exe.language,
                    manifest_hash: sha256(exe.bytes),
                    manifest_length: exe.bytes.len(),
                };
                if let Some(expected) = expected {
                    ensure!(
                        &identity == expected,
                        "fixed original Python CSR identity differs"
                    );
                }
                identity.require_image(&buffers[0].0)?;
                Ok(identity)
            },
            close as fn(File) -> Result<()>,
        )?;
        Ok(Self { files, identity })
    }
    pub fn identity(&self) -> &RuntimeIdentity {
        &self.identity
    }
    pub fn close(mut self) -> Result<()> {
        self.files.close()
    }
}
impl RuntimeIdentity {
    pub fn capture(python: &Path) -> Result<Self> {
        let held = HeldRuntime::acquire(python, None)?;
        let identity = held.identity.clone();
        held.close()?;
        Ok(identity)
    }
    pub fn hold(&self, python: &Path) -> Result<HeldRuntime> {
        HeldRuntime::acquire(python, Some(self))
    }
    pub fn python(&self) -> &Path {
        &self.python
    }
    pub fn language(&self) -> u16 {
        self.language
    }
    pub fn image_digest(&self) -> &str {
        &self.hashes[0]
    }
    pub fn require_image(&self, bytes: &[u8]) -> Result<()> {
        crate::windows_security::image::qualify_python_dispatch_image(
            bytes,
            &self.hashes[0],
            self.lengths[0],
            self.language,
            &self.manifest_hash,
            self.manifest_length,
        )
    }
    pub fn require_event_image(&self, event_path: &Path, bytes: &[u8]) -> Result<()> {
        let (actual, expected) = event_path
            .to_str()
            .zip(self.python.to_str())
            .ok_or_else(|| anyhow::anyhow!("fixed Python event path is not Unicode"))?;
        ensure!(
            crate::windows_security::sxs::ordinal_path_equal(actual, expected)?,
            "fixed Python creation event image differs"
        );
        self.require_image(bytes)
    }
}
pub fn runtime_path(run: &str, state: &Path) -> Result<PathBuf> {
    ensure!(
        run.len() == 32
            && run
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
            && state.is_absolute()
            && state.file_name().and_then(|v| v.to_str())
                == Some(format!("security-windows-{run}").as_str()),
        "fixed Python runtime run binding differs"
    );
    plain(state)?;
    Ok(state.join("python"))
}
pub fn host_transport(exit: u32, text: &str, errors: &str) -> Result<String> {
    let mut value = csr::Observation::new(true, csr::Role::PythonPass);
    value.record(exit, text, errors)?;
    ensure!(
        value.completed(),
        "fixed original Python CSR contract failed"
    );
    Ok(csr::HOST_PASS.into())
}
/// Owns the positive latch; only actual process/held-file completion can call the common host core.
pub struct PreparedRuntime {
    identity: RuntimeIdentity,
    host_positive: bool,
}
impl PreparedRuntime {
    pub fn prepare(run: &str, state: &Path) -> Result<Self> {
        let python = runtime_path(run, state)?.join("python.exe");
        Ok(Self {
            identity: RuntimeIdentity::capture(&python)?,
            host_positive: false,
        })
    }
    pub fn identity(&self) -> &RuntimeIdentity {
        &self.identity
    }
    pub fn require_host_positive(&self, python: &Path) -> Result<()> {
        require_path(python, self.identity.python())?;
        ensure!(self.host_positive, "fixed Python host positive is absent");
        Ok(())
    }
    pub fn run_host(
        &mut self,
        run: impl FnOnce(&mut dyn FnMut(&str) -> Result<()>) -> Result<String>,
        emit: impl FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        ensure!(!self.host_positive, "fixed Python host positive repeats");
        let held = self.identity.hold(self.identity.python())?;
        csr::complete_host(
            csr::Role::PythonPass,
            run,
            || held.close(),
            emit,
            || {
                self.host_positive = true;
                Ok(())
            },
        )
    }
}
