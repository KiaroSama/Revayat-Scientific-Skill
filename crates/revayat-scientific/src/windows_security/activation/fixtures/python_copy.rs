//! Create-only full-base copy. Completion counters follow durable, identity-checked copies.
use super::*;
use crate::windows_security::preparation;
use std::time::{Duration, Instant};
pub(super) struct Budget {
    files: usize,
    bytes: u64,
    entries: usize,
    started: Instant,
}
impl Budget {
    pub fn new() -> Self {
        Self {
            files: 0,
            bytes: 0,
            entries: 0,
            started: Instant::now(),
        }
    }
    fn reserve(&mut self, bytes: u64) -> Result<()> {
        ensure!(
            self.started.elapsed() < Duration::from_secs(300),
            "full Python copy deadline elapsed"
        );
        self.files += 1;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("Python copy byte count overflow"))?;
        ensure!(
            self.files <= 100000 && self.bytes <= 1024 * 1024 * 1024,
            "full Python base copy exceeds finite file/byte bounds"
        );
        Ok(())
    }
    pub fn copy_file(&mut self, input: &Path, output: &Path) -> Result<()> {
        let mut source = io::HeldFile::open(input, 64 * 1024 * 1024)?;
        let result = (|| {
            let mut bytes = source.bytes()?;
            let reservation = self.reserve(bytes.len() as u64);
            if let Err(error) = reservation {
                bytes.fill(0);
                return Err(error);
            }
            let created = io::create(output, &bytes, 64 * 1024 * 1024);
            bytes.fill(0);
            created?.close()?;
            source.verify()
        })();
        runtime::with_cleanup(result, source.close())
    }
    pub fn tree(&mut self, input: &Path, output: &Path) -> Result<()> {
        io::plain(input, false)?;
        io::missing(output)?;
        fs::create_dir(output)?;
        walk(input, |path, is_directory| {
            self.entries += 1;
            ensure!(
                self.entries <= 100000,
                "full Python source entry count exceeds bound"
            );
            let relative = path.strip_prefix(input)?;
            ensure!(
                relative.components().count() <= 64,
                "full Python source depth exceeds bound"
            );
            let destination = output.join(relative);
            if is_directory {
                io::missing(&destination)?;
                fs::create_dir(&destination)?;
            } else {
                self.copy_file(path, &destination)?;
                if self.files.is_multiple_of(256) {
                    preparation::runtime_progress(
                        "copy-python-trees",
                        "copied",
                        self.files as i64,
                    )?;
                }
            }
            Ok(())
        })
    }
    pub fn count(&self) -> i64 {
        self.files as i64
    }
}
pub(super) fn validate(input: &Path, phase: &str) -> Result<()> {
    preparation::runtime_progress(phase, "before", 0)?;
    preparation::assert_source_path(input).map_err(preparation::controller_error)?;
    let mut count = 0;
    walk(input, |path, _| {
        count += 1;
        ensure!(
            count <= 100000 && path.strip_prefix(input)?.components().count() <= 64,
            "full Python source traversal exceeds bounds or contains a reparse point"
        );
        if count % 256 == 0 {
            preparation::runtime_progress(phase, "validated", count)?;
        }
        Ok(())
    })?;
    preparation::runtime_progress(phase, "after", count)
}
/// Validate/yield one entry before requesting any descendant. A refusal stops
/// traversal immediately; no rejected junction is followed by another producer read.
fn walk(input: &Path, mut visit: impl FnMut(&Path, bool) -> Result<()>) -> Result<()> {
    let started = Instant::now();
    let mut stack = vec![fs::read_dir(input)?];
    let mut count = 0;
    while let Some(directory) = stack.last_mut() {
        ensure!(
            started.elapsed() < Duration::from_secs(120),
            "full Python traversal deadline elapsed"
        );
        let Some(entry) = directory.next() else {
            stack.pop();
            continue;
        };
        let path = entry?.path();
        count += 1;
        ensure!(
            count <= 100000 && path.strip_prefix(input)?.components().count() <= 64,
            "full Python traversal exceeds entry/depth bounds"
        );
        io::plain(&path, false)?;
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() || metadata.is_dir(),
            "full Python source object is not a file/directory"
        );
        visit(&path, metadata.is_dir())?;
        if metadata.is_dir() {
            io::plain(&path, false)?;
            stack.push(fs::read_dir(&path)?);
        }
    }
    Ok(())
}
