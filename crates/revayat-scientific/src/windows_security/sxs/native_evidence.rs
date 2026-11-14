//! Validated held-file adapter for the shared original evidence read/clear/close operation.
use super::*;
use crate::windows_security::sxs::{EvidenceRead, LengthPhase, read_owned, require_length};
struct EvidenceFile {
    file: Option<File>,
    expected: ObjectId,
}
impl EvidenceFile {
    fn open(path: &Path, expected: ObjectId) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(path)?;
        let mut held = Self {
            file: Some(file),
            expected,
        };
        let operation = held.bind();
        if let Err(primary) = operation {
            return tokens::finish(Err(primary), held.close().err().into_iter().collect());
        }
        Ok(held)
    }
    fn bind(&self) -> Result<()> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("fixed SxS evidence handle was retired"))?;
        ensure!(
            identity::object_id(file)? == self.expected && file.metadata()?.is_file(),
            "fixed SxS evidence held identity differs"
        );
        Ok(())
    }
}
impl EvidenceRead for EvidenceFile {
    fn length(&mut self) -> Result<i64> {
        self.bind()?;
        Ok(i64::try_from(
            self.file.as_ref().unwrap().metadata()?.len(),
        )?)
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize> {
        self.bind()?;
        Ok(self.file.as_mut().unwrap().read(bytes)?)
    }
    fn close(&mut self) -> Result<()> {
        match self.file.take() {
            Some(file) => close(file),
            None => Ok(()),
        }
    }
}
impl Storage {
    fn evidence_identity(&self, name: &'static str) -> Result<(PathBuf, ObjectId)> {
        let path = self.require(name)?;
        let expected = self
            .files
            .iter()
            .find(|(member, _)| *member == name)
            .ok_or_else(|| anyhow::anyhow!("fixed SxS evidence member was not created"))?
            .1;
        Ok((path, expected))
    }
    pub fn require_evidence_length(&self, name: &'static str, maximum: i64) -> Result<()> {
        let (path, expected) = self.evidence_identity(name)?;
        let mut held = EvidenceFile::open(&path, expected)?;
        let operation = require_length(|| held.length(), maximum, LengthPhase::FileBound);
        let cleanup = held.close().err().into_iter().collect();
        tokens::finish(operation, cleanup)
    }
    pub fn read_evidence(
        &self,
        name: &'static str,
        parse: impl FnOnce(&[u8]) -> Result<String>,
    ) -> Result<String> {
        self.require_evidence_length(name, 1_048_576)?;
        let (path, expected) = self.evidence_identity(name)?;
        read_owned(|| EvidenceFile::open(&path, expected), parse)
    }
}
