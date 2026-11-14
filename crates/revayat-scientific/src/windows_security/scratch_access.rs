//! Exact scratch native-open requests, synchronous ownership and read-only model metadata.
use super::{OperationResult, attempt, failure, finish, need, valid_handle};
use crate::windows_security::policy::{Acl, Descriptor};
use anyhow::{Result, ensure};
use std::collections::BTreeSet;

pub const DESIRED: u32 = 0x100020;
pub const PENDING: i32 = 0x103;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AttributeInformation {
    pub attributes: u32,
    pub tag: u32,
}
pub fn require_plain(value: AttributeInformation, directory: bool) -> Result<()> {
    ensure!(
        value.attributes & 0x410 == if directory { 0x10 } else { 0 } && value.tag == 0,
        "fixed scratch object type/reparse differs"
    );
    Ok(())
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum: u16,
    pub buffer: usize,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root: usize,
    pub name: usize,
    pub attributes: u32,
    pub descriptor: usize,
    pub qos: usize,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoStatus {
    pub status: i32,
    pub information: usize,
}
#[repr(C)]
#[derive(Debug)]
pub struct OpenOutput {
    pub handle: usize,
    pub io: IoStatus,
}
impl Default for OpenOutput {
    fn default() -> Self {
        Self {
            handle: 0,
            io: IoStatus {
                status: -1,
                information: 0,
            },
        }
    }
}
#[derive(Debug)]
pub struct OpenCall<'a> {
    pub path: &'a str,
    pub root: usize,
    pub access: u32,
    pub share: u32,
    pub options: u32,
    pub object: &'a ObjectAttributes,
    pub unicode: &'a UnicodeString,
    pub text: &'a [u16],
}
#[derive(Debug)]
struct OpenName {
    unicode: UnicodeString,
    text: Box<[u16]>,
}
#[derive(Debug)]
pub struct NativeRequest {
    pub path: String,
    pub role: String,
    pub name: String,
    pub target: String,
    pub root: usize,
    pub requested: u32,
    pub options: u32,
    pub returned: i32,
    pub io_status: i32,
    pub information: u64,
    pub opened: bool,
    pub pending: bool,
    pub output: Option<Box<OpenOutput>>,
    backing: Option<Box<OpenName>>,
}
impl NativeRequest {
    pub fn new(path: impl Into<String>, role: &str, name: &str) -> Self {
        Self {
            path: path.into(),
            role: role.into(),
            name: name.into(),
            target: "root".into(),
            root: 0,
            requested: DESIRED,
            options: 0x200021,
            returned: 0,
            io_status: 0,
            information: 0,
            opened: false,
            pending: false,
            output: None,
            backing: None,
        }
    }
    pub fn open(
        &mut self,
        mut call: impl FnMut(OpenCall<'_>, &mut OpenOutput) -> OperationResult<i32>,
        mut fatal: impl FnMut() -> OperationResult<()>,
    ) -> OperationResult<()> {
        need(
            self.output.is_none()
                && self.backing.is_none()
                && self.path.encode_utf16().count() <= 128,
        )?;
        need(self.root == 0 || valid_handle(self.root) && self.path == "temp")?;
        let text = self
            .path
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let unicode = UnicodeString {
            length: ((text.len() - 1) * 2) as u16,
            maximum: (text.len() * 2) as u16,
            buffer: text.as_ptr() as usize,
        };
        self.backing = Some(Box::new(OpenName { unicode, text }));
        self.output = Some(Box::default());
        let backing = self.backing.as_ref().unwrap();
        let object = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root: self.root,
            name: &backing.unicode as *const _ as usize,
            attributes: 0x40,
            descriptor: 0,
            qos: 0,
        };
        let result = call(
            OpenCall {
                path: &self.path,
                root: self.root,
                access: self.requested,
                share: 7,
                options: self.options,
                object: &object,
                unicode: &backing.unicode,
                text: &backing.text,
            },
            self.output.as_mut().unwrap(),
        );
        let output = self.output.as_ref().unwrap();
        self.pending = matches!(result, Ok(PENDING)) || output.io.status == PENDING;
        if self.pending {
            fatal()?;
            return Err(result.err().unwrap_or_else(|| {
                failure("fixed scratch pending termination unexpectedly returned")
            }));
        }
        self.returned = result?;
        self.io_status = output.io.status;
        self.information = output.io.information as u64;
        self.opened = self.returned == 0;
        if self.opened {
            let device = self.target == "volume"
                && self.root == 0
                && self.options == 0x200000
                && self.path.starts_with("\\Device\\HarddiskVolume")
                && !self.path.ends_with('\\');
            need(
                valid_handle(output.handle)
                    && (device || self.io_status == 0 && self.information == 1),
            )?;
        }
        Ok(())
    }
    pub fn release(
        &mut self,
        mut bind: impl FnMut(usize) -> OperationResult<()>,
        mut close: impl FnMut(usize) -> OperationResult<()>,
    ) -> OperationResult<()> {
        if self.pending {
            return Ok(());
        }
        let Some(output) = self.output.take() else {
            self.backing.take();
            return Ok(());
        };
        let mut errors = Vec::new();
        if valid_handle(output.handle) {
            attempt(&mut errors, || bind(output.handle));
            attempt(&mut errors, || close(output.handle));
        }
        self.backing.take();
        finish(Ok(()), errors)
    }
    pub fn has_storage(&self) -> bool {
        self.output.is_some() || self.backing.is_some()
    }
    pub fn frame(&self) -> Result<String> {
        ensure!(
            matches!(self.role.as_str(), "host" | "lpac")
                && matches!(
                    self.name.as_str(),
                    "dos" | "device" | "temp-absolute" | "temp-relative"
                )
                && matches!(self.target.as_str(), "root" | "temp")
                && !self.pending,
            "invalid scratch native frame metadata"
        );
        Ok(format!(
            "WINDOWS_SCRATCH_NATIVE role={} name={} desired=0x00100020 share=7 options=0x00200021 ntstatus=0x{:08X} opened={} identity_qualified=True context_verified=True cleanup_qualified=True cause_claimed=False child_equivalence_claimed=False",
            self.role,
            self.name,
            self.returned as u32,
            super::truth(self.opened)
        ))
    }
}
impl Drop for NativeRequest {
    fn drop(&mut self) {
        if self.pending {
            if let Some(output) = self.output.take() {
                std::mem::forget(output);
            }
            if let Some(backing) = self.backing.take() {
                std::mem::forget(backing);
            }
        }
    }
}
pub fn native_names(
    root: &str,
    mut query: impl FnMut(&str, &mut [u16; 512]) -> Result<u32>,
) -> Result<[String; 2]> {
    let b = root.as_bytes();
    ensure!(
        b.len() == 3 && (b'D'..=b'Z').contains(&b[0]) && &b[1..] == b":\\",
        "invalid fixed scratch drive root"
    );
    let mut output = [0u16; 512];
    let length = query(&root[..2], &mut output)? as usize;
    ensure!(
        (3..=512).contains(&length)
            && output[length - 1] == 0
            && output[length - 2] == 0
            && output[..length].iter().position(|v| *v == 0) == Some(length - 2),
        "invalid fixed scratch device mapping span"
    );
    let device = String::from_utf16(&output[..length - 2])?;
    let suffix = device
        .strip_prefix("\\Device\\HarddiskVolume")
        .ok_or_else(|| anyhow::anyhow!("invalid fixed scratch device family"))?;
    ensure!(
        !suffix.is_empty() && suffix.len() <= 20 && suffix.bytes().all(|v| v.is_ascii_digit()),
        "invalid fixed scratch volume suffix"
    );
    Ok([format!("\\??\\{root}"), format!("{device}\\")])
}
pub fn require_synchronous(
    returned: i32,
    io: IoStatus,
    mut fatal: impl FnMut() -> Result<()>,
) -> Result<()> {
    if returned == PENDING || io.status == PENDING {
        fatal()?;
        anyhow::bail!("fixed scratch pending termination unexpectedly returned");
    }
    Ok(())
}
pub fn require_volume(returned: i32, io: IoStatus) -> Result<()> {
    ensure!(
        returned == 0 && io.status == 0 && io.information == 8,
        "fixed scratch volume information differs"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Privileges {
    pub inventory: Vec<(u64, u32)>,
    pub present: bool,
    pub attributes: u32,
}
impl Privileges {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            (4..=65536).contains(&bytes.len()),
            "scratch privilege buffer exceeds bounds"
        );
        let count = u32::from_le_bytes(bytes[..4].try_into()?) as usize;
        ensure!(
            count <= 128 && 4 + count * 12 <= bytes.len(),
            "invalid scratch privilege count"
        );
        let mut identities = BTreeSet::new();
        let mut inventory = Vec::new();
        let (mut present, mut attributes) = (false, 0);
        for entry in bytes[4..4 + count * 12].as_chunks::<12>().0 {
            let luid = u64::from_le_bytes(entry[..8].try_into()?);
            let flags = u32::from_le_bytes(entry[8..].try_into()?);
            ensure!(
                identities.insert(luid),
                "duplicate scratch privilege identity"
            );
            inventory.push((luid, flags));
            if luid == 23 {
                present = true;
                attributes = flags;
            }
        }
        inventory.sort_unstable();
        Ok(Self {
            inventory,
            present,
            attributes,
        })
    }
    pub fn same(&self, other: &Self) -> Result<()> {
        ensure!(
            self.inventory == other.inventory,
            "scratch privilege inventory changed"
        );
        Ok(())
    }
    pub fn supported(&self) -> Result<()> {
        crate::windows_security::policy::supported_privileges(&self.inventory)
    }
    pub fn frame(&self, role: &str) -> Result<String> {
        ensure!(
            matches!(role, "primary" | "duplicate" | "effective"),
            "invalid scratch privilege frame role"
        );
        Ok(format!(
            "WINDOWS_SCRATCH_PRIVILEGE role={role} count={} traversal_present={} traversal_enabled={} attributes=0x{:08X} cause_claimed=False",
            self.inventory.len(),
            super::truth(self.present),
            super::truth(self.present && self.attributes & 2 != 0),
            self.attributes
        ))
    }
}
#[derive(Debug)]
pub struct AccessResult {
    pub query: u32,
    pub check_error: u32,
    pub granted: u32,
    pub open_error: u32,
    pub checked: bool,
    pub allowed: bool,
    pub opened: bool,
    pub(super) policy: String,
}
impl Default for AccessResult {
    fn default() -> Self {
        Self {
            query: 0,
            check_error: 0,
            granted: 0,
            open_error: 0,
            checked: false,
            allowed: false,
            opened: false,
            policy: "unknown".into(),
        }
    }
}
impl AccessResult {
    pub fn frame(&self, label: &str) -> Result<String> {
        ensure!(
            matches!(label, "root" | "temp")
                && (!self.allowed || self.checked)
                && (self.checked || self.granted == 0)
                && (!self.opened || self.open_error == 0),
            "invalid scratch access observation"
        );
        let frame = format!(
            "WINDOWS_SCRATCH_ACCESS object={label} desired=0x00100020 descriptor_error=0x{:08X} check_completed={} allowed={} granted=0x{:08X} check_error=0x{:08X} opened={} open_error=0x{:08X} {} identity_qualified=True context_verified=True cleanup_qualified=True cause_claimed=False child_equivalence_claimed=False",
            self.query,
            super::truth(self.checked),
            super::truth(self.allowed),
            self.granted,
            self.check_error,
            super::truth(self.opened),
            self.open_error,
            self.policy
        );
        ensure!(
            frame.len() <= 1024 && !frame.contains("S-1-"),
            "scratch access frame exceeds fixed metadata bound"
        );
        Ok(frame)
    }
}
pub fn policy_summary(bytes: &[u8], user: &[u8], package: &[u8]) -> Result<String> {
    let sd = Descriptor::parse(bytes)?;
    ensure!(
        sd.owner.is_some() && sd.group.is_some(),
        "scratch descriptor identity absent"
    );
    let (mut allow, mut deny, mut owner_deny) = (0, 0, 0);
    if let Some(bytes) = sd.dacl {
        let acl = Acl::parse(bytes)?;
        ensure!(acl.aces.len() <= 256, "scratch policy ACE budget exceeded");
        let owner = super::sid("S-1-3-4")?;
        for ace in acl.aces {
            ensure!(
                matches!(ace.kind, 0..=3) && ace.bytes.len() >= 16,
                "unsupported scratch policy ACE"
            );
            let subject = &ace.bytes[8..];
            ensure!(
                subject[0] == 1
                    && subject[1] <= 15
                    && subject.len() == 8 + usize::from(subject[1]) * 4,
                "invalid scratch policy principal"
            );
            if ace.flags & 8 != 0 {
                continue;
            }
            if subject == package {
                if ace.kind == 0 {
                    allow |= ace.mask()?;
                } else if ace.kind == 1 {
                    deny |= ace.mask()?;
                }
            }
            if subject == owner && ace.kind == 1 {
                owner_deny |= ace.mask()?;
            }
        }
    }
    let (mut rid, mut mandatory, mut labels) = (0, 0, 0);
    if let Some(bytes) = sd.sacl {
        let acl = Acl::parse(bytes)?;
        ensure!(acl.aces.len() <= 16, "scratch label budget exceeded");
        for ace in acl.aces {
            ensure!(
                ace.kind == 17 && ace.bytes.len() == 20,
                "unsupported scratch policy label"
            );
            if ace.flags & 8 != 0 {
                continue;
            }
            let sid = ace.sid()?;
            labels += 1;
            ensure!(
                sid[..8] == [1, 1, 0, 0, 0, 0, 0, 16] && labels == 1,
                "scratch integrity label differs"
            );
            rid = u32::from_le_bytes(sid[8..12].try_into()?);
            mandatory = ace.mask()?;
        }
    }
    Ok(format!(
        "owner_user={} dacl_present={} dacl_null={} package_allow=0x{allow:08X} package_deny=0x{deny:08X} owner_deny=0x{owner_deny:08X} label_present={} label_rid=0x{rid:08X} label_policy=0x{mandatory:08X}",
        super::truth(sd.owner == Some(user)),
        super::truth(sd.control & 4 != 0),
        super::truth(sd.dacl.is_none()),
        super::truth(labels == 1)
    ))
}
