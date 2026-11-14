//! Streaming same-object tool/library pins and explicit all-attempt native close.
use super::*;
use crate::identity::{self, Fingerprint, ObjectId};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek},
    os::windows::{fs::OpenOptionsExt, io::IntoRawHandle},
    time::{Duration, Instant},
};
const MAX_FILES: usize = 192;
const MAX_FILE: u64 = 256 * 1024 * 1024;
const MAX_TOTAL: u64 = 1024 * 1024 * 1024;
struct Pin {
    path: PathBuf,
    file: Option<File>,
    id: ObjectId,
    fingerprint: Option<Fingerprint>,
    directory: bool,
}
pub(super) struct Pins {
    values: Vec<Pin>,
    total: u64,
    started: Instant,
    closed: bool,
}
impl Pins {
    pub fn new() -> Self {
        Self {
            values: Vec::new(),
            total: 0,
            started: Instant::now(),
            closed: false,
        }
    }
    pub fn deadline(&self) -> Result<()> {
        ensure!(
            !self.closed && self.started.elapsed() < Duration::from_secs(120),
            "fixed tool discovery deadline elapsed"
        );
        Ok(())
    }
    pub fn path(&mut self, path: &Path) -> Result<PathBuf> {
        step(Stage::FixturePinPath, || {
            self.deadline()?;
            io::plain(path, false)?;
            let canonical = step(Stage::FixturePinCanonical, || Ok(path.canonicalize()?))?;
            let text = canonical
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("fixed tool path is not Unicode"))?;
            let text = text.strip_prefix(r"\\?\").unwrap_or(text);
            let bytes = text.as_bytes();
            ensure!(
                bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":\\",
                "fixed tool requires a local DOS path"
            );
            let selected = PathBuf::from(text);
            io::plain(&selected, false)?;
            step(Stage::FixturePinIdentity, || {
                ensure!(
                    identity::path_object_id(path)? == identity::path_object_id(&selected)?,
                    "fixed DOS spelling changed object identity"
                );
                Ok(())
            })?;
            let directories = if selected.is_dir() {
                selected.as_path()
            } else {
                selected.parent().unwrap()
            };
            for ancestor in directories
                .ancestors()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                self.pin(ancestor, true)?;
            }
            Ok(selected)
        })
    }
    pub fn file(&mut self, path: &Path) -> Result<PathBuf> {
        let path = self.path(path)?;
        self.pin(&path, false)?;
        Ok(path)
    }
    fn pin(&mut self, path: &Path, directory: bool) -> Result<()> {
        step(Stage::FixturePinOpen, || {
            self.deadline()?;
            if let Some(pin) = self.values.iter().find(|pin| pin.path == path) {
                ensure!(pin.directory == directory, "fixed tool object role differs");
                return Ok(());
            }
            ensure!(
                self.values.len() < MAX_FILES,
                "fixed tool input count exceeds bound"
            );
            let file = OpenOptions::new()
                .read(true)
                .share_mode(if directory { 3 } else { 1 })
                .custom_flags(0x00200000 | if directory { 0x02000000 } else { 0 })
                .open(path)?;
            self.values.push(Pin {
                path: path.into(),
                file: Some(file),
                id: ObjectId {
                    volume: 0,
                    index: 0,
                },
                fingerprint: None,
                directory,
            });
            let pin = self.values.last_mut().unwrap();
            step(Stage::FixturePinIdentity, || {
                pin.id = identity::object_id(pin.file.as_ref().unwrap())?;
                ensure!(
                    identity::path_object_id(path)? == pin.id
                        && pin.file.as_ref().unwrap().metadata()?.is_dir() == directory,
                    "fixed tool object type/identity differs"
                );
                Ok(())
            })?;
            if !directory {
                let fingerprint = fingerprint(pin, self.started)?;
                self.total = self
                    .total
                    .checked_add(fingerprint.size)
                    .ok_or_else(|| anyhow::anyhow!("fixed tool byte count overflow"))?;
                pin.fingerprint = Some(fingerprint);
                ensure!(
                    self.total <= MAX_TOTAL,
                    "fixed tool/library byte budget exceeded"
                );
            }
            Ok(())
        })
        .map_err(|error| {
            diagnostics::annotate(
                error,
                Stage::FixturePinOpen,
                Numbers {
                    count: u32::try_from(self.values.len()).ok(),
                    bytes: u32::try_from(self.total).ok(),
                    properties: Some(u32::from(directory)),
                    ..Default::default()
                },
            )
        })
    }
    pub fn read(&mut self, path: &Path, maximum: usize) -> Result<Vec<u8>> {
        step(Stage::FixturePinRead, || {
            let path = self.file(path)?;
            let pin = self
                .values
                .iter_mut()
                .find(|pin| pin.path == path)
                .ok_or_else(|| anyhow::anyhow!("fixed tool text is not pinned"))?;
            let file = pin.file.as_mut().unwrap();
            ensure!(
                file.metadata()?.len() <= maximum as u64,
                "fixed tool text exceeds bound"
            );
            file.rewind()?;
            let mut output = Vec::new();
            let result = (|| {
                file.take(maximum as u64 + 1).read_to_end(&mut output)?;
                ensure!(output.len() <= maximum, "fixed tool text grew beyond bound");
                Ok::<_, anyhow::Error>(())
            })();
            if let Err(error) = result {
                output.fill(0);
                return Err(error);
            }
            Ok(output)
        })
    }
    pub fn fingerprint(&mut self, path: &Path) -> Result<Fingerprint> {
        let path = self.file(path)?;
        self.values
            .iter()
            .find(|pin| pin.path == path)
            .and_then(|pin| pin.fingerprint.clone())
            .ok_or_else(|| anyhow::anyhow!("fixed source fingerprint is not retained"))
    }
    pub fn verify(&mut self) -> Result<()> {
        step(Stage::FixturePinsVerify, || {
            self.started = Instant::now();
            self.deadline()?;
            for pin in &mut self.values {
                io::plain(&pin.path, false)?;
                ensure!(
                    identity::path_object_id(&pin.path)? == pin.id
                        && identity::object_id(pin.file.as_ref().unwrap())? == pin.id,
                    "fixed retained tool object changed"
                );
                if !pin.directory {
                    ensure!(
                        Some(fingerprint(pin, self.started)?) == pin.fingerprint,
                        "fixed retained tool bytes changed"
                    );
                }
            }
            Ok(())
        })
    }
    pub fn close(&mut self) -> Result<()> {
        self.closed = true;
        let mut failures = Vec::new();
        for mut pin in std::mem::take(&mut self.values).into_iter().rev() {
            if let Some(file) = pin.file.take() {
                let handle = file.into_raw_handle();
                if unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) } == 0 {
                    failures.push(diagnostics::operation(
                        std::io::Error::last_os_error().into(),
                        Stage::FixturePinsClose,
                    ));
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Failures { errors: failures }.into())
        }
    }
}
impl Drop for Pins {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
fn fingerprint(pin: &mut Pin, started: Instant) -> Result<Fingerprint> {
    step(Stage::FixturePinFingerprint, || {
        let file = pin.file.as_mut().unwrap();
        let metadata = file.metadata()?;
        let modified = metadata.modified()?;
        ensure!(
            metadata.is_file() && (1..=MAX_FILE).contains(&metadata.len()),
            "fixed tool/library length exceeds bound"
        );
        file.rewind()?;
        struct Buffer(Vec<u8>);
        impl Drop for Buffer {
            fn drop(&mut self) {
                self.0.fill(0)
            }
        }
        let mut buffer = Buffer(vec![0; 1024 * 1024]);
        let mut hasher = Sha256::new();
        let mut consumed = 0;
        loop {
            ensure!(
                started.elapsed() < Duration::from_secs(120),
                "fixed tool hashing deadline elapsed"
            );
            let length = file.read(&mut buffer.0)?;
            if length == 0 {
                break;
            }
            consumed += length as u64;
            ensure!(
                consumed <= metadata.len(),
                "fixed tool/library grew while hashing"
            );
            hasher.update(&buffer.0[..length]);
        }
        let after = file.metadata()?;
        ensure!(
            consumed == metadata.len()
                && after.len() == metadata.len()
                && after.modified()? == modified
                && identity::object_id(file)? == pin.id
                && identity::path_object_id(&pin.path)? == pin.id,
            "fixed tool/library changed while hashing"
        );
        Ok(Fingerprint {
            identity: pin.id,
            size: consumed,
            modified,
            sha256: format!("{:x}", hasher.finalize()),
        })
    })
}
