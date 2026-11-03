//! Windows containment policy and bounded, private security receipts.
//!
//! Policy parsing is portable so CI can exercise hostile frames on every host.
//! Kernel enforcement is implemented separately and is never inferred from a
//! successful model check.
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

#[cfg(windows)]
#[path = "windows_security/native.rs"]
pub mod native;

pub const OUTPUT_LIMIT: usize = 2048;
pub const ERROR_LIMIT: usize = 512;
pub const MAX_TOKEN_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobLimits {
    pub processes: u32,
    pub process_memory: usize,
    pub job_memory: usize,
    pub cpu_seconds: u32,
}

impl Default for JobLimits {
    fn default() -> Self {
        Self {
            processes: 8,
            process_memory: 384 * 1024 * 1024,
            job_memory: 512 * 1024 * 1024,
            cpu_seconds: 30,
        }
    }
}

impl JobLimits {
    /// Process lifetime ownership for normal tools; no sandbox claim is made.
    pub const fn ownership() -> Self {
        Self {
            processes: 0,
            process_memory: 0,
            job_memory: 0,
            cpu_seconds: 0,
        }
    }
    /// Chromium's multiprocess renderer needs a distinct bounded profile.
    pub const fn browser() -> Self {
        Self {
            processes: 64,
            process_memory: 1024 * 1024 * 1024,
            job_memory: 2 * 1024 * 1024 * 1024,
            cpu_seconds: 30,
        }
    }
    pub fn validate(self) -> Result<Self> {
        if self == Self::browser() || self == Self::ownership() {
            return Ok(self);
        }
        ensure!((1..=8).contains(&self.processes), "invalid process limit");
        ensure!(
            (1024 * 1024..=384 * 1024 * 1024).contains(&self.process_memory),
            "invalid process memory limit"
        );
        ensure!(
            (self.process_memory..=512 * 1024 * 1024).contains(&self.job_memory),
            "invalid job memory limit"
        );
        ensure!((1..=30).contains(&self.cpu_seconds), "invalid CPU limit");
        Ok(self)
    }
}

/// A query must use the successfully returned span, never the buffer capacity.
pub fn token_span(data: &[u8], returned: usize) -> Result<&[u8]> {
    ensure!(
        (4..=MAX_TOKEN_BYTES).contains(&returned) && returned <= data.len(),
        "invalid token span"
    );
    Ok(&data[..returned])
}

pub fn restricted_value(data: &[u8]) -> Result<bool> {
    let value = match data.len() {
        1 => u32::from(data[0]),
        4 => u32::from_le_bytes(data.try_into()?),
        _ => bail!("invalid restriction width"),
    };
    ensure!(value <= 1, "noncanonical restriction value");
    Ok(value == 1)
}

/// Only SeChangeNotifyPrivilege (the full 64-bit LUID 23) is retained.
pub fn privilege_inventory(data: &[u8], returned: usize) -> Result<()> {
    let data = token_span(data, returned)?;
    let count = u32::from_le_bytes(data[..4].try_into()?) as usize;
    ensure!(
        count <= 128 && 4 + count * 12 <= data.len(),
        "invalid privilege count"
    );
    for entry in data[4..4 + count * 12].as_chunks::<12>().0 {
        let luid = u64::from_le_bytes(entry[..8].try_into()?);
        let flags = u32::from_le_bytes(entry[8..].try_into()?);
        ensure!(
            luid == 23 && flags & !3 == 0,
            "dangerous privilege retained"
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Prerequisite,
    Prepare,
    Create,
    Attach,
    Token,
    Resume,
    Capture,
    Wait,
    Reap,
    Restore,
    Close,
    Report,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fault {
    Control,
    Native,
    Timeout,
    Decode,
    Overflow,
    Exit,
    Cleanup,
}

/// No path, command, environment, panic payload, or child stderr enters a frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub failures: Vec<(Phase, Fault)>,
    pub child_exit: Option<u32>,
}

impl Receipt {
    pub fn new(phase: Phase, fault: Fault) -> Self {
        Self {
            failures: vec![(phase, fault)],
            child_exit: None,
        }
    }
    pub fn retain(&mut self, phase: Phase, fault: Fault) {
        if self.failures.len() < 8 {
            self.failures.push((phase, fault));
        }
    }
    pub fn observe_exit(&mut self, exit: u32) {
        if self.child_exit.is_none() {
            self.child_exit = Some(exit);
        }
    }
    pub fn wire(&self) -> Result<String> {
        ensure!(
            !self.failures.is_empty() && self.failures.len() <= 8,
            "invalid failure inventory"
        );
        let mut output = serde_json::to_string(self)?;
        output.push('\n');
        ensure!(
            output.is_ascii() && output.len() <= ERROR_LIMIT,
            "receipt exceeds bound"
        );
        Ok(output)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= ERROR_LIMIT && bytes.is_ascii(),
            "invalid receipt transport"
        );
        ensure!(
            bytes.last() == Some(&b'\n') && !bytes[..bytes.len() - 1].contains(&b'\n'),
            "invalid receipt terminator"
        );
        let receipt: Self = serde_json::from_slice(&bytes[..bytes.len() - 1])?;
        ensure!(receipt.wire()?.as_bytes() == bytes, "noncanonical receipt");
        Ok(receipt)
    }
}

#[derive(Default, Debug)]
pub struct Capture {
    bytes: Vec<u8>,
    eof: bool,
}

impl Capture {
    pub fn append(&mut self, bytes: &[u8], limit: usize) -> Result<()> {
        ensure!(
            !self.eof
                && limit <= OUTPUT_LIMIT
                && bytes.len() <= limit.saturating_sub(self.bytes.len()),
            "capture overflow or data after EOF"
        );
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub fn end(&mut self) {
        self.eof = true;
    }
    pub fn finish(&self, limit: usize) -> Result<&str> {
        ensure!(
            self.eof && limit <= OUTPUT_LIMIT && self.bytes.len() <= limit,
            "capture incomplete"
        );
        ensure!(self.bytes.is_ascii(), "capture is not ASCII");
        Ok(std::str::from_utf8(&self.bytes)?)
    }
    pub fn clear(&mut self) {
        self.bytes.fill(0);
        self.bytes.clear();
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Lexical relative paths are checked before any filesystem operation.
pub fn relative_leaf(value: &Path) -> Result<()> {
    ensure!(!value.as_os_str().is_empty(), "empty child path");
    for component in value.components() {
        let Component::Normal(name) = component else {
            bail!("child path is not relative");
        };
        let text = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("child name is not Unicode"))?;
        ensure!(
            !text.contains(['\\', ':', '\0']) && !text.ends_with(['.', ' ']),
            "unsafe Windows child name"
        );
        let stem = text.split('.').next().unwrap_or("").to_ascii_uppercase();
        ensure!(
            ![
                "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
                "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
                "LPT9"
            ]
            .contains(&stem.as_str()),
            "reserved Windows device name"
        );
    }
    Ok(())
}

pub fn package_sid(value: &str) -> Result<()> {
    let tail = value
        .strip_prefix("S-1-15-2-")
        .ok_or_else(|| anyhow::anyhow!("invalid package SID"))?;
    let parts = tail.split('-').collect::<Vec<_>>();
    ensure!(
        parts.len() == 7,
        "package SID must identify one concrete AppContainer"
    );
    for part in parts {
        let number = part.parse::<u32>()?;
        ensure!(
            part == number.to_string(),
            "noncanonical package SID component"
        );
    }
    Ok(())
}

/// Verify every existing ancestor without following junctions or symlinks.
pub fn plain_path(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        ensure!(
            !crate::identity::is_link(ancestor)?,
            "reparse point in protected path"
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    Prepared,
    Suspended,
    Attached,
    Qualified,
    Running,
    Reaped,
    Restored,
    Closed,
}

impl Lifecycle {
    /// Enforce containment before execution and reaping before restoring host policy.
    pub fn advance(&mut self, next: Self) -> Result<()> {
        let valid = matches!(
            (*self, next),
            (Self::Prepared, Self::Suspended)
                | (Self::Suspended, Self::Attached)
                | (Self::Attached, Self::Qualified)
                | (Self::Qualified, Self::Running)
                | (Self::Running, Self::Reaped)
                | (Self::Reaped, Self::Restored)
                | (Self::Restored, Self::Closed)
        );
        ensure!(valid, "unsafe containment lifecycle transition");
        *self = next;
        Ok(())
    }
}
