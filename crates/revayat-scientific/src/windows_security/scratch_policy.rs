//! Owned attachment correlation, exact volume policy receipts and rollback operations.
use super::{FileIdentity, OperationResult, SharedError, attempt, failure, finish};
use crate::windows_security::policy::{self, Acl, Descriptor};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

pub const DENIED: i32 = 0xc0000022u32 as i32;
pub const LEGACY_RECEIPT: &str = "scratch-volume-policy.receipt";
pub fn receipt_name(supported: bool) -> &'static str {
    if supported {
        "scratch-volume-supported.receipt"
    } else {
        "scratch-volume-diagnostic.receipt"
    }
}
pub fn receipt_mode(legacy: bool, diagnostic: bool, supported: bool) -> Result<i32> {
    ensure!(
        !legacy && !(diagnostic && supported),
        "conflicting scratch policy receipts"
    );
    Ok(if supported {
        1
    } else if diagnostic {
        0
    } else {
        -1
    })
}
pub fn supports(phase: &str, observe: bool, registry: Option<i32>, qualified: bool) -> bool {
    matches!(phase, "preflight" | "wall" | "regressions")
        && registry == Some(0)
        && (qualified || observe && phase == "preflight")
}
pub fn attachment_number(bytes: &[u8], disk: u32, partition: u32) -> Result<()> {
    ensure!(
        bytes.len() == 12
            && u32::from_le_bytes(bytes[..4].try_into()?) == 7
            && u32::from_le_bytes(bytes[4..8].try_into()?) == disk
            && u32::from_le_bytes(bytes[8..12].try_into()?) == partition
            && partition != 0,
        "fixed scratch attachment observation is invalid"
    );
    Ok(())
}
pub fn attachment_descriptor(bytes: &[u8]) -> Result<Descriptor<'_>> {
    let sd = Descriptor::parse(bytes)?;
    ensure!(
        sd.owner.is_some() && sd.group.is_some(),
        "scratch attachment descriptor identity absent"
    );
    if let Some(bytes) = sd.dacl {
        ensure!(
            Acl::parse(bytes)?.aces.len() <= 256,
            "scratch attachment DACL exceeds bound"
        );
    }
    if let Some(bytes) = sd.sacl {
        ensure!(
            Acl::parse(bytes)?.aces.len() <= 16,
            "scratch attachment SACL exceeds bound"
        );
    }
    Ok(sd)
}
pub fn same_attachment_policy(a: &[u8], b: &[u8]) -> Result<bool> {
    let (a, b) = (attachment_descriptor(a)?, attachment_descriptor(b)?);
    Ok(a.owner == b.owner
        && a.group == b.group
        && a.control == b.control
        && a.rm_control == b.rm_control
        && a.dacl == b.dacl
        && a.sacl == b.sacl)
}
pub fn attachment_pair(name: &str, a: Option<&[u8]>, b: Option<&[u8]>) -> Result<String> {
    ensure!(
        matches!(name, "image-stable" | "image-volume"),
        "invalid scratch attachment pair"
    );
    let known = a.is_some() && b.is_some();
    let equal = if let (Some(a), Some(b)) = (a, b) {
        same_attachment_policy(a, b)?
    } else {
        false
    };
    Ok(format!(
        "WINDOWS_SCRATCH_ATTACHMENT_PAIR pair={name} known={} equal={} attachment_input_verified=False checked_device_verified=False cause_claimed=False",
        super::truth(known),
        super::truth(equal)
    ))
}
pub fn release_attachment(
    primary: Option<SharedError>,
    recheck: impl FnOnce() -> OperationResult<()>,
    close: impl FnOnce() -> OperationResult<()>,
) -> OperationResult<()> {
    let mut errors = Vec::new();
    attempt(&mut errors, recheck);
    attempt(&mut errors, close);
    finish(primary.map_or(Ok(()), Err), errors)
}
pub fn complete_supported(
    clean: bool,
    restore: impl FnOnce() -> OperationResult<()>,
    defer: impl FnOnce() -> OperationResult<()>,
) -> OperationResult<()> {
    if clean {
        return restore();
    }
    let mut cleanup = Vec::new();
    attempt(&mut cleanup, defer);
    finish(
        Err(failure(
            "supported scratch process cleanup remains uncertain",
        )),
        cleanup,
    )
}

/// Restores only an exact original or our exact installed descriptor; foreign edits stop cleanup.
pub fn restore_policy(
    before: &[u8],
    after: &[u8],
    mut read: impl FnMut() -> OperationResult<Vec<u8>>,
    mut write: impl FnMut(&[u8]) -> OperationResult<()>,
) -> OperationResult<()> {
    let current = read()?;
    let same = |a: &[u8], b: &[u8]| {
        policy::descriptor_equal(a, b).map_err(|_| failure("scratch descriptor is unqualified"))
    };
    if same(&current, before)? {
        return Ok(());
    }
    super::need(same(&current, after)?)?;
    write(before)?;
    super::need(same(&read()?, before)?)
}
pub fn differential(
    mut probe: impl FnMut() -> OperationResult<Vec<i32>>,
    mut qualify: impl FnMut() -> OperationResult<()>,
    mut install: impl FnMut() -> OperationResult<()>,
    mut restore: impl FnMut() -> OperationResult<()>,
) -> OperationResult<Vec<Vec<i32>>> {
    let mut values = Vec::new();
    let result = (|| {
        qualify()?;
        values.push(probe()?);
        super::need(values[0].len() >= 2 && values[0][..2] == [DENIED, DENIED])?;
        qualify()?;
        install()?;
        values.push(probe()?);
        qualify()?;
        super::need(
            values[1].len() == values[0].len()
                && values[1][..2]
                    .iter()
                    .all(|value| matches!(*value, 0 | DENIED)),
        )
    })();
    let mut cleanup = Vec::new();
    attempt(&mut cleanup, &mut restore);
    finish(result, cleanup)?;
    qualify()?;
    values.push(probe()?);
    super::need(values[2] == values[0])?;
    Ok(values)
}
pub fn volume_trial(before: &[u8], package: &str) -> Result<Vec<u8>> {
    crate::windows_security::package_sid(package)?;
    policy::descriptor_trial(before, &super::sid(package)?, 0x1301bf)
}
fn hash(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}
fn identifier(run: &str) -> bool {
    run.len() == 32
        && run
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Debug)]
pub struct VolumeReceipt {
    pub run: String,
    pub package: String,
    pub supported: bool,
    pub root: String,
    pub disk: u32,
    pub partition: u32,
    pub image: FileIdentity,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}
impl VolumeReceipt {
    pub fn encode(&self) -> Result<String> {
        ensure!(identifier(&self.run), "invalid scratch run identity");
        crate::windows_security::package_sid(&self.package)?;
        ensure!(
            policy::descriptor_equal(&volume_trial(&self.before, &self.package)?, &self.after)?,
            "scratch trial policy differs"
        );
        let body = format!(
            "scratch-volume-v5\n{}\n{}\n{}\n{}\n{}\n{}\n{:016X}:{:016X}:{:016X}\n{}\n{}\n",
            self.run,
            self.package,
            if self.supported {
                "supported"
            } else {
                "diagnostic"
            },
            self.root,
            self.disk,
            self.partition,
            self.image.volume,
            self.image.high,
            self.image.low,
            STANDARD.encode(&self.before),
            STANDARD.encode(&self.after)
        );
        let text = format!("{body}{}\n", hash(&body));
        ensure!(text.len() <= 196608, "scratch receipt exceeds bound");
        Ok(text)
    }
    pub fn decode(bytes: &[u8], run: &str, package: &str, supported: bool) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= 196608 && identifier(run),
            "invalid scratch receipt span or run"
        );
        let text = std::str::from_utf8(bytes)?;
        let values = text.split('\n').collect::<Vec<_>>();
        ensure!(
            values.len() == 12
                && values[0] == "scratch-volume-v5"
                && values[1] == run
                && values[2] == package
                && values[3] == if supported { "supported" } else { "diagnostic" }
                && values[11].is_empty()
                && values[10] == hash(&format!("{}\n", values[..10].join("\n"))),
            "scratch receipt binding differs"
        );
        crate::windows_security::package_sid(package)?;
        let decimal = |value: &str| -> Result<u32> {
            ensure!(
                !value.is_empty() && value.len() <= 10 && value.bytes().all(|b| b.is_ascii_digit()),
                "invalid scratch attachment number"
            );
            Ok(value.parse()?)
        };
        let identity = values[7].split(':').collect::<Vec<_>>();
        ensure!(
            identity.len() == 3
                && identity.iter().all(|value| value.len() == 16
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))),
            "invalid scratch image identity"
        );
        let before = STANDARD.decode(values[8])?;
        let after = STANDARD.decode(values[9])?;
        ensure!(
            policy::descriptor_equal(&volume_trial(&before, package)?, &after)?,
            "scratch receipt trial differs"
        );
        Ok(Self {
            run: run.into(),
            package: package.into(),
            supported,
            root: values[4].into(),
            disk: decimal(values[5])?,
            partition: decimal(values[6])?,
            image: FileIdentity {
                volume: u64::from_str_radix(identity[0], 16)?,
                high: u64::from_str_radix(identity[1], 16)?,
                low: u64::from_str_radix(identity[2], 16)?,
            },
            before,
            after,
        })
    }
}

/// The receipt is durable before possible mutation is recorded and before any policy write.
#[derive(Default, Debug)]
pub struct LeaseState {
    pub possible: bool,
}
impl LeaseState {
    pub fn install(
        &mut self,
        receipt: &VolumeReceipt,
        mut bind: impl FnMut() -> OperationResult<()>,
        persist: impl FnOnce(&[u8]) -> OperationResult<()>,
        mut read: impl FnMut() -> OperationResult<Vec<u8>>,
        mut write: impl FnMut(&[u8]) -> OperationResult<()>,
    ) -> OperationResult<()> {
        super::need(!self.possible)?;
        bind()?;
        let bytes = receipt
            .encode()
            .map_err(|_| failure("scratch lease receipt is unqualified"))?;
        persist(bytes.as_bytes())?;
        super::need(
            policy::descriptor_equal(&read()?, &receipt.before)
                .map_err(|_| failure("scratch policy read is unqualified"))?,
        )?;
        self.possible = true;
        write(&receipt.after)?;
        super::need(
            policy::descriptor_equal(&read()?, &receipt.after)
                .map_err(|_| failure("scratch policy readback is unqualified"))?,
        )
    }
}
