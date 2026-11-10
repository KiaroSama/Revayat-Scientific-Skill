//! One fixed CSR call-pair contract and trace/undebugged failure precedence.
use super::{CONTEXT_SIZE, Failures};
use anyhow::{Result, ensure};
use std::fmt;
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
/// Exact readable MEM_IMAGE region for the one held-image CSR IAT pointer read.
#[derive(Clone, Copy)]
pub struct DispatchRegion {
    pub address: u64,
    pub allocation: u64,
    pub size: u64,
    pub state: u32,
    pub kind: u32,
    pub protect: u32,
}
impl DispatchRegion {
    pub fn readable(self, address: u64, allocation: u64) -> bool {
        address >= self.address
            && address - self.address <= self.size
            && 8 <= self.size - (address - self.address)
            && self.state == 0x1000
            && self.kind == 0x1000000
            && self.allocation == allocation
            && self.protect & 0x100 == 0
            && matches!(self.protect & 0xff, 2 | 4 | 8 | 0x20 | 0x40 | 0x80)
    }
}
#[derive(Default)]
pub struct DispatchTarget {
    consumed: bool,
}
impl DispatchTarget {
    pub fn read(
        &mut self,
        address: u64,
        allocation: u64,
        expected: u64,
        region: impl FnOnce() -> Result<DispatchRegion>,
        read: impl FnOnce(&mut [u8; 8]) -> Result<usize>,
    ) -> Result<()> {
        ensure!(
            !self.consumed && expected != 0,
            "CSR target read attempt already consumed or target absent"
        );
        self.consumed = true;
        let mut bytes = [0u8; 8];
        let result = (|| {
            ensure!(
                region()?.readable(address, allocation),
                "CSR target IAT region differs"
            );
            ensure!(
                read(&mut bytes)? == 8 && u64::from_le_bytes(bytes) == expected,
                "CSR target IAT pointer differs"
            );
            Ok(())
        })();
        bytes.fill(0);
        result
    }
}
pub struct CsrPair {
    call: u64,
    post: u64,
    started: bool,
    paired: bool,
    failed: bool,
    generation: u32,
    stack: u64,
    result: u32,
}
impl CsrPair {
    pub fn new(call: u64, post: u64) -> Result<Self> {
        ensure!(
            call != 0 && call <= 0x7ffffffffffffff0 && post == call + 7,
            "fixed CSR pair addresses differ"
        );
        Ok(Self {
            call,
            post,
            started: false,
            paired: false,
            failed: false,
            generation: 0,
            stack: 0,
            result: 0,
        })
    }
    pub fn started(&self) -> bool {
        self.started
    }
    pub fn paired(&self) -> bool {
        self.paired
    }
    pub fn result(&self) -> Result<u32> {
        ensure!(self.paired, "CSR pair has no return observation");
        Ok(self.result)
    }
    pub fn sites(&self, generation: u32) -> [u64; 2] {
        if !self.started {
            [self.call, self.post]
        } else {
            [
                0,
                if !self.paired && generation == self.generation {
                    self.post
                } else {
                    0
                },
            ]
        }
    }
    pub fn begin(&mut self, generation: u32, context: &[u8]) -> Result<()> {
        if self.started || self.paired || self.failed {
            self.failed = true;
            anyhow::bail!("CSR call attempt already consumed");
        }
        self.started = true;
        self.failed = true;
        ensure!(
            context.len() == CONTEXT_SIZE,
            "fixed CSR call context size differs"
        );
        let stack = u64_at(context, 152);
        ensure!(
            stack != 0
                && stack <= 0x7fffffffffff
                && stack & 15 == 0
                && u64_at(context, 184) as u32 == 0x1001001e
                && u64_at(context, 192) as u32 == 0x1f8,
            "fixed CSR call arguments or stack differ"
        );
        self.generation = generation;
        self.stack = stack;
        self.failed = false;
        Ok(())
    }
    pub fn end(&mut self, generation: u32, context: &[u8]) -> Result<()> {
        if !(self.started
            && !self.paired
            && !self.failed
            && generation == self.generation
            && context.len() == CONTEXT_SIZE
            && u64_at(context, 152) == self.stack)
        {
            self.failed = true;
            anyhow::bail!("fixed CSR return generation or stack differs");
        }
        self.result = u64_at(context, 120) as u32;
        self.paired = true;
        Ok(())
    }
    pub fn destroy(&mut self) {
        self.stack = 0;
    }
}
/// Only the owner with demonstrated observed/destructed/clean state may construct this carrier.
pub struct QualifiedFailure {
    original: anyhow::Error,
}
impl QualifiedFailure {
    pub fn original(&self) -> &anyhow::Error {
        &self.original
    }
}
impl fmt::Display for QualifiedFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fixed entry diagnostic failed after qualified cleanup")
    }
}
impl fmt::Debug for QualifiedFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}
impl std::error::Error for QualifiedFailure {}
fn append(first: Option<anyhow::Error>, later: anyhow::Error) -> anyhow::Error {
    match first {
        Some(first) => Failures {
            errors: vec![first, later],
        }
        .into(),
        None => later,
    }
}
pub fn finish_trace(
    primary: Option<anyhow::Error>,
    cleanup: Vec<anyhow::Error>,
    observed: bool,
    destroyed: bool,
    metadata: impl FnOnce() -> Result<String>,
    emit: impl FnOnce(&str) -> Result<()>,
) -> Result<()> {
    if !cleanup.is_empty() {
        let mut errors: Vec<_> = primary.into_iter().collect();
        errors.extend(cleanup);
        return Err(Failures { errors }.into());
    }
    if !observed || !destroyed {
        return Err(
            primary.unwrap_or_else(|| anyhow::anyhow!("fixed entry lifetime is unqualified"))
        );
    }
    let primary = match metadata().and_then(|text| emit(&text)) {
        Ok(()) => primary,
        Err(reporting) => Some(append(primary, reporting)),
    };
    match primary {
        Some(original) => Err(QualifiedFailure { original }.into()),
        None => Ok(()),
    }
}
pub fn execute_trace(
    trace: impl FnOnce() -> Result<()>,
    undebugged: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let retained = match trace() {
        Ok(()) => None,
        Err(error) => match error.downcast::<QualifiedFailure>() {
            Ok(failure) => Some(failure.original),
            Err(error) => return Err(error),
        },
    };
    if let Err(later) = undebugged() {
        return Err(append(retained, later));
    }
    match retained {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
