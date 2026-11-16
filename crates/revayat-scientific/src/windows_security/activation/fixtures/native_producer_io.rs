//! Owned native compiler inputs: acquire before fallible capture, recheck, close every handle.
use super::*;
pub(super) struct Inputs {
    files: Vec<HeldFile>,
    snapshots: Vec<Snapshot>,
}
impl Inputs {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            snapshots: Vec::new(),
        }
    }
    fn retain(&mut self, file: HeldFile, maximum: usize) -> Result<()> {
        self.files.push(file);
        self.snapshots
            .push(Snapshot::capture(self.files.last_mut().unwrap(), maximum)?);
        Ok(())
    }
    pub fn open(&mut self, path: &Path, maximum: usize) -> Result<()> {
        self.retain(HeldFile::open(path, maximum)?, maximum)
    }
    pub fn create(&mut self, path: &Path, bytes: &[u8], maximum: usize) -> Result<()> {
        self.retain(io::create(path, bytes, maximum)?, maximum)
    }
    pub fn bytes(&mut self, path: &Path) -> Result<Vec<u8>> {
        self.files
            .iter_mut()
            .find(|file| file.path() == path)
            .ok_or_else(|| anyhow::anyhow!("native producer input is not retained"))?
            .bytes()
    }
    pub fn snapshots(&self) -> Vec<Snapshot> {
        self.snapshots.clone()
    }
    pub fn verify(&mut self) -> Result<()> {
        for file in &mut self.files {
            file.verify()?;
        }
        Ok(())
    }
    pub fn finish<T>(&mut self, operation: Result<T>) -> Result<T> {
        let mut failures = Vec::new();
        for mut file in std::mem::take(&mut self.files).into_iter().rev() {
            if let Err(error) = file.close() {
                failures.push(error);
            }
        }
        if failures.is_empty() {
            return operation;
        }
        match operation {
            Ok(_) => Err(Failures { errors: failures }.into()),
            Err(primary) => {
                failures.insert(0, primary);
                Err(Failures { errors: failures }.into())
            }
        }
    }
}
impl Drop for Inputs {
    fn drop(&mut self) {
        let _ = self.finish(Ok(()));
    }
}
pub(super) struct Bytes(pub Vec<u8>);
impl Drop for Bytes {
    fn drop(&mut self) {
        self.0.fill(0)
    }
}
pub(super) fn directory(path: &Path) -> Result<()> {
    io::missing(path)?;
    std::fs::create_dir(path)?;
    io::plain(path, false)
}
