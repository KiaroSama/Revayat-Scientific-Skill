//! Disposable host default-owner token mechanics. A failed revert cannot release trusted resources.
use crate::windows_security::activation::Failures;
use anyhow::{Result, ensure};
#[path = "canary_checks.rs"]
mod checks;
pub use checks::check_validation;
pub const CAPACITY: usize = 256;
pub fn absent(opened: bool, error: u32, token: usize) -> Result<()> {
    crate::windows_security::activation::require_absent_thread_token(opened, error, token)
}
pub fn within(start: u64, size: u64, address: u64, bytes: u64) -> bool {
    address >= start && address - start <= size && bytes <= size - (address - start)
}
pub fn identity(
    expected: &[u8],
    user: &[u8],
    owner: &[u8],
    kind: u32,
    level: u32,
    duplicate: bool,
    require_owner: bool,
) -> Result<()> {
    ensure!(
        user == expected
            && kind == if duplicate { 2 } else { 1 }
            && (!duplicate || level == 2)
            && (!require_owner || owner == expected),
        "fixed canary token identity differs"
    );
    Ok(())
}
pub fn owner_input(buffer: &mut [u8; CAPACITY], base: u64, user: &[u8]) -> Result<()> {
    buffer.fill(0);
    ensure!(
        user.len() >= 8
            && user[0] == 1
            && user[1] <= 15
            && user.len() == 8 + 4 * usize::from(user[1])
            && user.len() <= CAPACITY - 8,
        "fixed canary owner input SID differs"
    );
    buffer[8..8 + user.len()].copy_from_slice(user);
    buffer[..8].copy_from_slice(
        &base
            .checked_add(8)
            .ok_or_else(|| anyhow::anyhow!("fixed canary owner address overflow"))?
            .to_le_bytes(),
    );
    Ok(())
}
pub fn sid(buffer: &[u8; CAPACITY], base: u64, returned: usize, kind: i32) -> Result<Vec<u8>> {
    let header = if kind == 1 { 16 } else { 8 };
    ensure!(
        matches!(kind, 1 | 4) && (header..=CAPACITY).contains(&returned),
        "fixed canary SID query shape differs"
    );
    let pointer = u64::from_le_bytes(buffer[..8].try_into()?);
    ensure!(
        pointer & 3 == 0
            && within(base, returned as u64, pointer, 8)
            && pointer - base >= header as u64,
        "fixed canary SID lies outside query"
    );
    let at = (pointer - base) as usize;
    let count = usize::from(buffer[at + 1]);
    let size = 8 + 4 * count;
    ensure!(
        buffer[at] == 1 && count <= 15 && within(base, returned as u64, pointer, size as u64),
        "fixed canary SID header/span differs"
    );
    Ok(buffer[at..at + size].to_vec())
}
pub fn scalar(buffer: &[u8; CAPACITY], returned: usize) -> Result<u32> {
    ensure!(returned == 4, "fixed canary scalar width differs");
    Ok(u32::from_le_bytes(buffer[..4].try_into()?))
}
pub fn query(
    token: usize,
    kind: i32,
    buffer: &mut [u8; CAPACITY],
    call: impl FnOnce(usize, i32, &mut [u8; CAPACITY]) -> Result<usize>,
) -> Result<usize> {
    ensure!(
        matches!(kind, 1 | 4 | 8 | 9),
        "unsupported fixed canary token query"
    );
    buffer.fill(0);
    let returned = call(token, kind, buffer)?;
    ensure!(
        (4..=CAPACITY).contains(&returned),
        "fixed canary query length differs"
    );
    Ok(returned)
}
pub trait ScopeIo {
    type Output;
    fn enter(&mut self) -> Result<bool>;
    fn effective(&mut self) -> Result<()>;
    fn body(&mut self) -> Result<Self::Output>;
    fn revert(&mut self) -> Result<bool>;
    fn absent(&mut self) -> Result<()>;
    fn fatal(&mut self) -> Result<()>;
}
pub fn scope<I: ScopeIo>(io: &mut I, trusted: &mut bool) -> Result<I::Output> {
    let mut entered = false;
    let operation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ensure!(io.enter()?, "fixed canary enter failed");
        entered = true;
        *trusted = false;
        io.effective()?;
        io.body()
    }));
    if entered {
        let restored = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> bool {
            matches!(io.revert(), Ok(true)) && io.absent().is_ok()
        }))
        .unwrap_or(false);
        if !restored {
            io.fatal()?;
            anyhow::bail!("fixed canary fatal restoration unexpectedly returned");
        }
        *trusted = true;
    }
    match operation {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
pub fn release<'a>(
    primary: Option<anyhow::Error>,
    trusted: bool,
    actions: Vec<Box<dyn FnMut() -> Result<()> + 'a>>,
) -> Result<Option<anyhow::Error>> {
    if !trusted {
        return Ok(primary);
    }
    let mut errors = Vec::new();
    for mut action in actions {
        if let Err(error) = action() {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(primary)
    } else {
        let mut all = primary.into_iter().collect::<Vec<_>>();
        all.extend(errors);
        Err(Failures { errors: all }.into())
    }
}
pub fn finish<'a, T>(
    operation: Result<T>,
    trusted: bool,
    actions: Vec<Box<dyn FnMut() -> Result<()> + 'a>>,
) -> Result<T> {
    match operation {
        Ok(value) => {
            release(None, trusted, actions)?;
            Ok(value)
        }
        Err(primary) => {
            let original = release(Some(primary), trusted, actions)?;
            Err(original.expect("canary release retains its original error"))
        }
    }
}
