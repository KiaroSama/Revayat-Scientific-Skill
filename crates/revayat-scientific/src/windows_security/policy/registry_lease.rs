//! Durable fixed-key registry intervention. Compare/read/write is deliberately not called CAS.
use super::{
    REGISTRY_READ, decode_registry_receipt, descriptor_equal, descriptor_trial,
    encode_registry_receipt,
};
use crate::windows_security::activation::Failures;
use anyhow::{Result, ensure};

pub fn require_plain_attributes(attributes: u32) -> Result<()> {
    ensure!(
        attributes & 0x400 == 0,
        "registry lease receipt or ancestor is a reparse point"
    );
    Ok(())
}
pub fn require_absent(attributes: impl FnOnce() -> std::io::Result<u32>) -> Result<()> {
    match attributes() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => anyhow::bail!("fixed registry-policy receipt collision"),
    }
}

fn combined<T>(primary: Result<T>, failures: Vec<anyhow::Error>) -> Result<T> {
    if failures.is_empty() {
        return primary;
    }
    let mut errors = failures;
    if let Err(error) = primary {
        errors.insert(0, error);
    }
    Err(Failures { errors }.into())
}

/// An implementation owns one retained, identity-checked key, exclusive lease and bound receipt.
pub trait RegistryIo {
    fn persist(&mut self, receipt: &[u8]) -> Result<()>;
    fn read(&mut self) -> Result<Vec<u8>>;
    fn write_dacl(&mut self, descriptor: &[u8]) -> Result<()>;
    fn bind_supported(&mut self) -> Result<()>;
    fn close(&mut self) -> Result<()>;
    fn remove_receipt(&mut self, expected: &[u8]) -> Result<()>;
}

pub fn acquire(
    open: impl FnOnce(&mut usize) -> Result<()>,
    finalize: impl FnOnce() -> Result<()>,
    close: impl FnOnce(usize) -> Result<()>,
) -> Result<usize> {
    let mut handle = 0;
    let opened = open(&mut handle);
    let finalization = finalize();
    let mut errors = Vec::new();
    if let Err(error) = opened {
        errors.push(error);
    }
    if let Err(error) = finalization {
        errors.push(error);
    }
    if errors.is_empty() {
        return Ok(handle);
    }
    if handle != 0
        && handle != usize::MAX
        && let Err(error) = close(handle)
    {
        errors.push(error);
    }
    if errors.len() == 1 {
        Err(errors.remove(0))
    } else {
        Err(Failures { errors }.into())
    }
}

pub fn install(
    io: &mut impl RegistryIo,
    before: &[u8],
    after: &[u8],
    receipt: &[u8],
    intent: &mut bool,
) -> Result<()> {
    io.persist(receipt)?;
    *intent = true;
    ensure!(
        descriptor_equal(&io.read()?, before)?,
        "fixed registry lease changed before write"
    );
    io.write_dacl(after)?;
    ensure!(
        descriptor_equal(&io.read()?, after)?,
        "fixed registry lease trial readback differs"
    );
    Ok(())
}

pub fn restore(
    io: &mut impl RegistryIo,
    before: &[u8],
    after: &[u8],
    cleanup_qualified: bool,
) -> Result<()> {
    let current = io.read()?;
    if descriptor_equal(&current, before)? {
        return Ok(());
    }
    ensure!(
        cleanup_qualified && descriptor_equal(&current, after)?,
        "foreign registry policy or unqualified cleanup forbids restoration"
    );
    io.write_dacl(before)?;
    ensure!(
        descriptor_equal(&io.read()?, before)?,
        "fixed registry lease restoration readback differs"
    );
    Ok(())
}

pub fn finish(
    primary: Option<anyhow::Error>,
    actions: &mut [&mut dyn FnMut() -> Result<()>],
) -> Result<Option<anyhow::Error>> {
    let errors = actions
        .iter_mut()
        .filter_map(|action| action().err())
        .collect::<Vec<_>>();
    if errors.is_empty() {
        return Ok(primary);
    }
    combined(primary.map_or(Ok(None), Err), errors)
}

/// The failure path restores only after durable intent, then attempts independent close.
pub fn establish<T>(
    state: &mut T,
    install: impl FnOnce(&mut T) -> Result<()>,
    persisted: impl FnOnce(&T) -> bool,
    recover: impl FnOnce(&mut T) -> Result<()>,
    close: impl FnOnce(&mut T) -> Result<()>,
) -> Result<()> {
    if let Err(primary) = install(state) {
        let mut errors = Vec::new();
        if persisted(state)
            && let Err(error) = recover(state)
        {
            errors.push(error);
        }
        if let Err(error) = close(state) {
            errors.push(error);
        }
        return combined(Err(primary), errors);
    }
    Ok(())
}

pub fn complete_lease<T>(
    state: &mut T,
    intent: bool,
    restore: impl FnOnce(&mut T) -> Result<()>,
    close: impl FnOnce(&mut T) -> Result<()>,
    remove: impl FnOnce(&mut T) -> Result<()>,
) -> Result<()> {
    let mut errors = Vec::new();
    if intent && let Err(error) = restore(state) {
        errors.push(error);
    }
    if let Err(error) = close(state) {
        errors.push(error);
    }
    if intent
        && errors.is_empty()
        && let Err(error) = remove(state)
    {
        errors.push(error);
    }
    combined(Ok(()), errors)
}

/// Recovery and disk finalization are independent; profile deletion needs restored policy,
/// and disposable-state deletion needs every earlier cleanup to have succeeded.
pub fn cleanup_owned(
    recovery: impl FnOnce() -> Result<()>,
    snaps: impl FnOnce() -> Result<()>,
    profile: impl FnOnce() -> Result<()>,
    disk: impl FnOnce() -> Result<()>,
    remove: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut errors = Vec::new();
    let restored = match recovery() {
        Ok(()) => true,
        Err(error) => {
            errors.push(error);
            false
        }
    };
    if let Err(error) = snaps() {
        errors.push(error);
    }
    if restored && let Err(error) = profile() {
        errors.push(error);
    }
    if let Err(error) = disk() {
        errors.push(error);
    }
    if errors.is_empty()
        && let Err(error) = remove()
    {
        errors.push(error);
    }
    combined(Ok(()), errors)
}

pub struct RegistryLease<I: RegistryIo> {
    io: I,
    original: Vec<u8>,
    expected: Vec<u8>,
    receipt: Vec<u8>,
    intent: bool,
    closed: bool,
    deferred: bool,
    supported: bool,
}
impl<I: RegistryIo> RegistryLease<I> {
    pub fn begin(mut io: I, run: &str, package: &[u8], nonce: &str) -> Result<Self> {
        let preparation = (|| {
            let original = io.read()?;
            let expected = descriptor_trial(&original, package, REGISTRY_READ)?;
            let receipt =
                encode_registry_receipt(run, package, nonce, &original, &expected)?.into_bytes();
            Ok((original, expected, receipt))
        })();
        let (original, expected, receipt) = match preparation {
            Ok(value) => value,
            Err(primary) => return combined(Err(primary), io.close().err().into_iter().collect()),
        };
        let mut lease = Self {
            io,
            original,
            expected,
            receipt,
            intent: false,
            closed: false,
            deferred: false,
            supported: false,
        };
        establish(
            &mut lease,
            |lease| {
                install(
                    &mut lease.io,
                    &lease.original,
                    &lease.expected,
                    &lease.receipt,
                    &mut lease.intent,
                )
            },
            |lease| lease.intent,
            |lease| restore(&mut lease.io, &lease.original, &lease.expected, true),
            |lease| lease.close(),
        )?;
        Ok(lease)
    }
    pub fn recover(
        io: I,
        run: &str,
        package: &[u8],
        receipt: &[u8],
        cleanup_qualified: bool,
    ) -> Result<()> {
        let decoded = std::str::from_utf8(receipt)
            .map_err(Into::into)
            .and_then(|text| decode_registry_receipt(text, run, package));
        let (original, expected) = match decoded {
            Ok(value) => value,
            Err(primary) => {
                let mut io = io;
                return combined(Err(primary), io.close().err().into_iter().collect());
            }
        };
        let mut lease = Self {
            io,
            original,
            expected,
            receipt: receipt.into(),
            intent: true,
            closed: false,
            deferred: false,
            supported: false,
        };
        lease.finish(cleanup_qualified)
    }
    fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.io.close()
    }
    pub fn defer(&mut self) -> Result<()> {
        self.deferred = true;
        self.close()
    }
    pub fn bind_supported(&mut self) -> Result<()> {
        ensure!(
            self.intent && !self.closed && !self.deferred && !self.supported,
            "registry lease cannot bind supported policy"
        );
        self.io.bind_supported()?;
        self.supported = true;
        Ok(())
    }
    pub fn finish(&mut self, cleanup_qualified: bool) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        ensure!(!self.deferred, "registry lease recovery was deferred");
        let intent = self.intent;
        complete_lease(
            self,
            intent,
            |lease| {
                restore(
                    &mut lease.io,
                    &lease.original,
                    &lease.expected,
                    cleanup_qualified,
                )?;
                ensure!(
                    cleanup_qualified,
                    "registry lease receipt retirement requires qualified cleanup"
                );
                Ok(())
            },
            |lease| lease.close(),
            |lease| lease.io.remove_receipt(&lease.receipt),
        )
    }
}
impl<I: RegistryIo> Drop for RegistryLease<I> {
    fn drop(&mut self) {
        // A destructor can release ownership, never authorize restoration or receipt retirement.
        let _ = self.close();
        self.original.fill(0);
        self.expected.fill(0);
        self.receipt.fill(0);
    }
}

#[path = "registry_lease_checks.rs"]
mod checks;
pub use checks::check_validation;
