//! Exact private positive-control policy, poisoned lifecycle, and identity-bound removal.
use super::{OperationResult, attempt, finish, need, valid_handle};
use crate::windows_security::policy::{Acl, Descriptor};
use anyhow::{Result, ensure};
use std::{collections::BTreeSet, error::Error, fmt};

#[derive(Debug)]
pub struct PolicyFailure {
    pub line: i32,
    pub field: u32,
    pub first: u32,
    pub second: u32,
    pub third: u32,
}
impl fmt::Display for PolicyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let line = if (1..=9999).contains(&self.line) {
            self.line
        } else {
            0
        };
        write!(
            f,
            "fixed private creator fixture rejected line={line} field={} first=0x{:08X} second=0x{:08X} third=0x{:08X}",
            self.field, self.first, self.second, self.third
        )
    }
}
impl Error for PolicyFailure {}
pub fn policy_need(
    value: bool,
    line: i32,
    field: u32,
    first: u32,
    second: u32,
    third: u32,
) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(PolicyFailure {
            line,
            field,
            first,
            second,
            third,
        }
        .into())
    }
}
pub fn folder(root: &str) -> Result<String> {
    let b = root.as_bytes();
    ensure!(
        b.len() == 3 && (b'D'..=b'Z').contains(&b[0]) && &b[1..] == b":\\",
        "invalid private creator root"
    );
    Ok(format!("{root}private-creator"))
}
pub fn native_root(value: &str) -> bool {
    value
        .strip_prefix("\\Device\\HarddiskVolume")
        .and_then(|v| v.strip_suffix('\\'))
        .is_some_and(|v| !v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit()))
}
pub fn policy(user: &[u8], package: &[u8]) -> Vec<u8> {
    let dacl = super::acl(&[
        super::ace(0, 0, 0x1f01ff, user),
        super::ace(0, 0, 0x1f01ff, package),
    ]);
    let low = [1, 1, 0, 0, 0, 0, 0, 16, 0, 16, 0, 0];
    let sacl = super::acl(&[super::ace(17, 3, 1, &low)]);
    super::descriptor(0x1014, user, user, &dacl, Some(&sacl))
}
pub fn require_policy(bytes: &[u8], user: &[u8], package: &[u8]) -> Result<()> {
    let sd = Descriptor::parse(bytes)?;
    policy_need(
        sd.owner == Some(user) && sd.group == Some(user),
        0,
        0,
        0,
        0,
        0,
    )?;
    policy_need(
        sd.control & 0x1004 == 0x1004 && sd.control & 8 == 0,
        0,
        1,
        sd.control.into(),
        0,
        0,
    )?;
    let dacl = sd.dacl.map(Acl::parse).transpose()?;
    let sacl = sd.sacl.map(Acl::parse).transpose()?;
    policy_need(
        dacl.as_ref().is_some_and(|v| v.aces.len() == 2)
            && sacl.as_ref().is_some_and(|v| v.aces.len() == 1),
        0,
        2,
        dacl.as_ref().map_or(u32::MAX, |v| v.aces.len() as u32),
        sacl.as_ref().map_or(u32::MAX, |v| v.aces.len() as u32),
        0,
    )?;
    let mut principals = BTreeSet::new();
    for ace in dacl.unwrap().aces {
        policy_need(
            ace.kind == 0
                && ace.flags == 0
                && ace.mask()? == 0x1f01ff
                && (ace.sid()? == user || ace.sid()? == package)
                && principals.insert(ace.sid()?.to_vec()),
            0,
            3,
            ace.kind.into(),
            ace.flags.into(),
            ace.mask()?,
        )?;
    }
    let sacl = sacl.unwrap();
    let label = &sacl.aces[0];
    policy_need(
        label.kind == 17 && label.bytes.len() == 20 && label.flags == 3,
        0,
        4,
        label.kind.into(),
        label.flags.into(),
        label.bytes.len() as u32,
    )?;
    policy_need(
        label.mask()? == 1 && label.sid()? == [1, 1, 0, 0, 0, 0, 0, 16, 0, 16, 0, 0],
        0,
        5,
        label.mask()?,
        0,
        0,
    )
}

#[derive(Debug, Default)]
pub struct Lifecycle {
    attempted: bool,
    prepared: bool,
    seal_attempted: bool,
    sealed: bool,
    running: bool,
    used: bool,
    uncertain: bool,
    removing: bool,
    pub removed: bool,
}
impl Lifecycle {
    pub fn prepare(
        &mut self,
        operation: impl FnOnce() -> OperationResult<()>,
    ) -> OperationResult<()> {
        need(!self.attempted)?;
        self.attempted = true;
        operation()?;
        self.prepared = true;
        Ok(())
    }
    pub fn seal(&mut self, operation: impl FnOnce() -> OperationResult<()>) -> OperationResult<()> {
        need(self.prepared && !self.seal_attempted)?;
        self.seal_attempted = true;
        operation()?;
        self.sealed = true;
        Ok(())
    }
    pub fn use_control(
        &mut self,
        operation: impl FnOnce() -> OperationResult<()>,
    ) -> OperationResult<()> {
        need(self.sealed && !self.running && !self.uncertain && !self.removing)?;
        self.running = true;
        match operation() {
            Ok(()) => {
                self.used = true;
                Ok(())
            }
            Err(error) => {
                self.uncertain = true;
                Err(error)
            }
        }
    }
    pub fn end(&mut self, clean: bool) {
        self.uncertain |= !clean;
        self.running = false;
    }
    pub fn remove(
        &mut self,
        operation: impl FnOnce() -> OperationResult<()>,
    ) -> OperationResult<()> {
        need(self.sealed && self.used && !self.running && !self.uncertain && !self.removing)?;
        self.removing = true;
        operation()?;
        self.removed = true;
        Ok(())
    }
    pub fn release(
        &mut self,
        operation: impl FnOnce() -> OperationResult<()>,
    ) -> OperationResult<()> {
        need(!self.running && !self.uncertain)?;
        operation()
    }
}
pub struct Removal<'a> {
    pub check: &'a mut dyn FnMut() -> OperationResult<()>,
    pub close_pin: &'a mut dyn FnMut() -> OperationResult<()>,
    pub open: &'a mut dyn FnMut() -> OperationResult<usize>,
    pub bind: &'a mut dyn FnMut(usize) -> OperationResult<()>,
    pub dispose: &'a mut dyn FnMut(usize) -> OperationResult<()>,
    pub close: &'a mut dyn FnMut(usize) -> OperationResult<()>,
    pub absent: &'a mut dyn FnMut() -> OperationResult<()>,
}
pub fn remove_bound(calls: Removal<'_>) -> OperationResult<()> {
    let (mut deletion, mut marked, mut closed) = (0, false, false);
    let result = (|| {
        (calls.check)()?;
        (calls.close_pin)()?;
        deletion = (calls.open)()?;
        (calls.bind)(deletion)?;
        (calls.dispose)(deletion)?;
        marked = true;
        Ok(())
    })();
    let mut errors = Vec::new();
    if valid_handle(deletion) {
        attempt(&mut errors, || {
            (calls.close)(deletion)?;
            closed = true;
            Ok(())
        });
    }
    if marked && closed {
        attempt(&mut errors, calls.absent);
    }
    finish(result, errors)
}
