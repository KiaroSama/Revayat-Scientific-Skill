//! Portable assertion-only I/O. Any attempted native operation fails; this never supplies native evidence.
use super::*;
use crate::windows_security::scratch::{self, SharedError};
use std::{cell::Cell, error::Error, fmt, sync::Arc};

#[derive(Default)]
pub(crate) struct CheckIo {
    pub reads: Cell<usize>,
}
impl ContextIo for CheckIo {
    fn read(&mut self, _: usize) -> Result<Vec<u8>> {
        self.reads.set(self.reads.get() + 1);
        anyhow::bail!("portable boundary validator attempted context access")
    }
    fn write(&mut self, _: usize, _: &[u8]) -> Result<()> {
        anyhow::bail!("portable boundary validator attempted context write")
    }
    fn close(&mut self, _: usize) -> Result<()> {
        anyhow::bail!("portable boundary validator attempted native close")
    }
    fn deadline(&mut self) -> Result<()> {
        Ok(())
    }
}
impl BoundaryIo for CheckIo {
    fn region(&mut self, _: usize, _: u64) -> Result<MemoryRegion> {
        anyhow::bail!("portable boundary validator attempted memory query")
    }
}
pub(crate) fn observer<'a>(
    mode: BoundaryMode,
    emit: impl FnMut(&str) -> Result<()> + 'a,
) -> Result<Boundary<'a, CheckIo>> {
    Boundary::new(
        BoundaryOwner {
            process: 1,
            thread: 2,
            pid: 7,
            tid: 11,
        },
        FixtureBinding {
            path: PathBuf::from("fixed"),
            digest: "digest".into(),
        },
        mode,
        CheckIo::default(),
        emit,
    )
}
pub(crate) fn baseline() -> Result<Vec<u8>> {
    let mut bytes = vec![0; super::super::CONTEXT_SIZE];
    software::put(&mut bytes, 112, 0x400)?;
    Ok(bytes)
}
pub(crate) fn initial(observer: &mut Boundary<'_, CheckIo>) -> Result<()> {
    let original = observer.original.as_deref().unwrap();
    let mut bytes = software::desired(
        original,
        original,
        &observer.addresses,
        &observer.enabled,
        false,
    )?;
    software::put(&mut bytes, 104, 0xffff0ff0)?;
    observer.accept_software_context(&bytes)
}
pub(in crate::windows_security::activation) fn kernel() -> Kernel {
    // Only presence is consulted by stage predicates below. No qualifier is bypassed by production APIs.
    Kernel {
        bytes: image::static_validation_fixture(),
        base: 1,
        sites: BoundarySites {
            worker: 0,
            registry: 0,
            funnel: 0,
        },
    }
}
#[derive(Debug)]
pub(crate) struct Identity(pub SharedError);
impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("retained boundary validation failure")
    }
}
impl Error for Identity {}
pub(crate) fn error(error: &SharedError) -> anyhow::Error {
    Identity(error.clone()).into()
}
pub(crate) fn same(error: &anyhow::Error, expected: &SharedError) -> bool {
    error
        .downcast_ref::<Identity>()
        .is_some_and(|v| Arc::ptr_eq(&v.0, expected))
}
pub(crate) fn failure(text: &'static str) -> SharedError {
    scratch::failure(text)
}
pub(crate) fn shared(error: anyhow::Error) -> SharedError {
    if let Some(identity) = error.downcast_ref::<Identity>() {
        identity.0.clone()
    } else {
        Arc::from(error.into_boxed_dyn_error())
    }
}
